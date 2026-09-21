import json
d=json.load(open('/workspace/recon/recon.json'))
for k,v in sorted(d['endpoints'].items()): print(k.ljust(50),str(v))
print('---FORMS---')
for f in d['forms']: print(f)
print('---JS---',d['js'])
print('---PARAMS---',d['params'])
print('---COOKIES---',d['cookies_seen'])
