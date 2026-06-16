#!/bin/bash
python3 -c "
import re
with open('index.html','r') as f: c=f.read()
scripts=re.findall(r'<script[^>]*>(.*?)</script>',c,re.DOTALL)
js='\n'.join(scripts)
with open('/tmp/check.js','w') as f: f.write(js)
"
node --check /tmp/check.js && echo "✅ 문법 이상 없음 - 푸시 가능" || echo "❌ 문법 오류 있음 - 푸시 하지 마세요"
