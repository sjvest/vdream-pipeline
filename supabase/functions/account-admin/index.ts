// V:Scout 계정 관리 서버 함수
// - 호출한 사람이 "계정 관리자"(auth app_metadata.account_admin === true)인지 서버에서 직접 확인한다.
// - app_metadata는 본인이 바꿀 수 없고 service role로만 바뀐다. 화면의 메뉴 숨김은 편의일 뿐 보안 장치가 아니다.
// - 비밀번호는 생성/초기화 응답에서 한 번만 돌려주고, 로그·변경 이력에는 남기지 않는다.
// - verify_jwt는 끄고(기존 함수와 동일) 이 함수 안에서 토큰을 직접 검증한다.
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = ["https://sjvest.github.io", "http://localhost:8000", "http://127.0.0.1:8000"];
const EMAIL_DOMAIN = "@vdream.co.kr";

function corsHeaders(req: Request) {
  const origin = req.headers.get("origin") || "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function json(req: Request, status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

// 헷갈리는 글자(0 O 1 l I)를 뺀 임시 비밀번호. 대문자·소문자·숫자를 모두 포함한다.
function makeTempPassword(): string {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", lower = "abcdefghijkmnopqrstuvwxyz", digit = "23456789";
  const all = upper + lower + digit;
  const pick = (set: string) => set[crypto.getRandomValues(new Uint32Array(1))[0] % set.length];
  const chars = [pick(upper), pick(lower), pick(digit)];
  while (chars.length < 12) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(req) });
  if (req.method !== "POST") return json(req, 405, { error: "허용되지 않은 요청입니다." });

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // 1) 로그인 확인 + 계정 관리자 확인 (서버에서)
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return json(req, 401, { error: "로그인이 필요합니다." });
  const { data: who, error: whoErr } = await admin.auth.getUser(token);
  if (whoErr || !who?.user) return json(req, 401, { error: "로그인이 필요합니다." });
  const me = who.user;
  if (me.app_metadata?.account_admin !== true) return json(req, 403, { error: "계정 관리 권한이 없습니다." });

  let body: any;
  try { body = await req.json(); } catch { return json(req, 400, { error: "요청 형식이 올바르지 않습니다." }); }
  const action = String(body?.action || "");

  const { data: myProf } = await admin.from("profiles").select("name").eq("id", me.id).maybeSingle();
  const myName = myProf?.name || me.email || "알 수 없음";

  // 변경 이력(비밀번호는 절대 넣지 않는다). 실패해도 본 작업은 되돌리지 않고 결과에 표시한다.
  async function audit(act: string, targetName: string, changes: string) {
    const { error } = await admin.from("audit_logs").insert({
      action: act, target_type: "계정", target_name: targetName,
      detail: { changes }, created_by: me.id, created_by_name: myName,
    });
    if (error) { console.error("audit_logs 기록 실패:", error.message); return false; }
    return true;
  }

  // 대상 계정 조회 + 계정 관리자 보호(다른 관리자 계정은 이 화면에서 건드릴 수 없다)
  async function loadTarget() {
    const id = String(body?.user_id || "");
    if (!/^[0-9a-f-]{36}$/i.test(id)) return { err: json(req, 400, { error: "대상 계정이 올바르지 않습니다." }) };
    const { data, error } = await admin.auth.admin.getUserById(id);
    if (error || !data?.user) return { err: json(req, 404, { error: "대상 계정을 찾을 수 없습니다." }) };
    if (data.user.app_metadata?.account_admin === true)
      return { err: json(req, 403, { error: "계정 관리자 계정은 이 화면에서 변경할 수 없습니다." }) };
    return { user: data.user };
  }
  async function nameOf(id: string, fallback: string) {
    const { data } = await admin.from("profiles").select("name").eq("id", id).maybeSingle();
    return data?.name || fallback;
  }

  try {
    if (action === "list") {
      const users: any[] = [];
      for (let page = 1; page <= 10; page++) {
        const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
        if (error) return json(req, 500, { error: "계정 목록을 불러오지 못했습니다." });
        users.push(...data.users);
        if (data.users.length < 200) break;
      }
      const { data: profs, error: pErr } = await admin.from("profiles").select("id,name");
      if (pErr) return json(req, 500, { error: "프로필을 불러오지 못했습니다." });
      const nameById = new Map((profs || []).map((p: any) => [p.id, p.name]));
      const now = Date.now();
      const rows = users.map((u) => ({
        id: u.id,
        email: u.email,
        name: nameById.get(u.id) || null,
        last_sign_in_at: u.last_sign_in_at || null,
        created_at: u.created_at,
        active: !(u.banned_until && new Date(u.banned_until).getTime() > now),
        is_account_admin: u.app_metadata?.account_admin === true,
      })).sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
      return json(req, 200, { users: rows });
    }

    if (action === "create") {
      const name = String(body?.name || "").trim();
      const email = String(body?.email || "").trim().toLowerCase();
      if (!name || name.length > 20) return json(req, 400, { error: "이름을 1~20자로 입력하세요." });
      if (!/^[a-z0-9._+-]+@vdream\.co\.kr$/.test(email) || !email.endsWith(EMAIL_DOMAIN))
        return json(req, 400, { error: "회사 메일(@vdream.co.kr)만 아이디로 만들 수 있습니다." });
      const password = makeTempPassword();
      const { data: created, error: cErr } = await admin.auth.admin.createUser({
        email, password, email_confirm: true, user_metadata: { name },
      });
      if (cErr || !created?.user) {
        const dup = /already|registered|exists/i.test(cErr?.message || "");
        return json(req, dup ? 409 : 500, { error: dup ? "이미 만들어진 아이디입니다." : "계정을 만들지 못했습니다." });
      }
      const { error: pErr } = await admin.from("profiles").insert({ id: created.user.id, name });
      if (pErr) {
        await admin.auth.admin.deleteUser(created.user.id); // 반쪽짜리 계정이 남지 않게 되돌린다
        return json(req, 500, { error: "프로필 저장에 실패해 계정 생성을 취소했습니다." });
      }
      const auditOk = await audit("등록", name, `계정 생성: ${email}`);
      return json(req, 200, { id: created.user.id, email, name, password, audit_ok: auditOk });
    }

    if (action === "reset_password") {
      const t = await loadTarget();
      if (t.err) return t.err;
      const password = makeTempPassword();
      const { error } = await admin.auth.admin.updateUserById(t.user!.id, { password });
      if (error) return json(req, 500, { error: "비밀번호를 초기화하지 못했습니다." });
      const nm = await nameOf(t.user!.id, t.user!.email || "");
      const auditOk = await audit("수정", nm, `비밀번호 초기화: ${t.user!.email}`);
      return json(req, 200, { email: t.user!.email, password, audit_ok: auditOk });
    }

    if (action === "set_active") {
      const t = await loadTarget();
      if (t.err) return t.err;
      const active = body?.active === true;
      const { error } = await admin.auth.admin.updateUserById(t.user!.id, { ban_duration: active ? "none" : "876000h" });
      if (error) return json(req, 500, { error: "상태를 바꾸지 못했습니다." });
      const nm = await nameOf(t.user!.id, t.user!.email || "");
      const auditOk = await audit("수정", nm, `${active ? "활성화" : "비활성화"}: ${t.user!.email}`);
      return json(req, 200, { email: t.user!.email, active, audit_ok: auditOk });
    }

    return json(req, 400, { error: "알 수 없는 요청입니다." });
  } catch (e) {
    console.error("account-admin 오류:", (e as Error)?.message);
    return json(req, 500, { error: "처리 중 오류가 발생했습니다." });
  }
});
