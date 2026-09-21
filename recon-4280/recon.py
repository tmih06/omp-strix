import urllib.request, urllib.parse, ssl, re, json, sys
from html.parser import HTMLParser
from collections import deque

BASE = 'https://pentest-ground.com:4280/'
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links=[]; self.forms=[]; self.scripts=[]; self._f=None; self.title=''; self._t=False
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='a' and a.get('href'): self.links.append(a['href'])
        if tag=='script' and a.get('src'): self.scripts.append(a['src'])
        if tag=='form': self._f={'action':a.get('action',''),'method':a.get('method','GET').upper(),'inputs':[]}
        if tag in('input','select','textarea') and self._f is not None:
            self._f['inputs'].append({'name':a.get('name',''),'type':a.get('type',''),'value':a.get('value','')})
        if tag=='title': self._t=True
    def handle_endtag(self,tag):
        if tag=='form' and self._f is not None: self.forms.append(self._f); self._f=None
        if tag=='title': self._t=False
    def handle_data(self,d):
        if self._t: self.title+=d

jar={}
def fetch(url, method='GET', data=None):
    req=urllib.request.Request(url, data=data, method=method)
    req.add_header('User-Agent','Mozilla/5.0 (X11; Linux x86_64) recon')
    if jar: req.add_header('Cookie','; '.join(f'{k}={v}' for k,v in jar.items()))
    try:
        r=urllib.request.urlopen(req, context=ctx, timeout=15)
        for h in r.headers.get_all('Set-Cookie') or []:
            m=re.match(r'([^=;]+)=([^;]*)',h)
            if m: jar[m.group(1)]=m.group(2)
        body=r.read()
        return r.status, dict(r.headers), body, r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read() if e.fp else b'', url
    except Exception as e:
        return 0, {}, str(e).encode(), url

results={}
def probe(path):
    url=urllib.parse.urljoin(BASE,path)
    st,h,b,fin=fetch(url)
    p=P()
    try: p.feed(b.decode('utf-8','replace'))
    except Exception: pass
    results[path]={'status':st,'final':fin,'size':len(b),'title':p.title.strip(),'server':h.get('Server',''),'ctype':h.get('Content-Type',''),'forms':p.forms,'links':p.links,'scripts':p.scripts,'location':h.get('Location','')}
    return st,len(b)

# 1. common files + DVWA paths
paths=['robots.txt','sitemap.xml','.git/HEAD','.git/config','.env','.htaccess','composer.json','package.json','README.md','CHANGELOG.md','COPYING.txt','login.php','setup.php','security.php','phpinfo.php','instructions.php','about.php','logout.php','docs/','config/','config/config.inc.php','config/config.inc.php.dist','.DS_Store','server-status','api/','swagger.json','openapi.json','wp-login.php','admin/','test.php','info.php','phpmyadmin/','external/','dvwa/','vulnerabilities/','ids_log.php','.well-known/security.txt','crossdomain.xml','favicon.ico']
for p in paths: probe(p)

# 2. crawl from root, depth 2, same-host only
seen=set(['/']); q=deque([('/',0)])
while q and len(seen)<120:
    path,depth=q.popleft()
    if path not in results: probe(path)
    if depth>=2: continue
    for l in results.get(path,{}).get('links',[]):
        u=urllib.parse.urljoin(BASE,l)
        pu=urllib.parse.urlparse(u)
        if pu.netloc!='pentest-ground.com:4280': continue
        rel=pu.path+(('?'+pu.query) if pu.query else '')
        if rel not in seen and not re.search(r'\.(png|jpg|jpeg|gif|ico|css|woff|ttf)$',pu.path):
            seen.add(rel); q.append((rel,depth+1))

# 3. fetch JS files found
js_urls=set()
for r in results.values():
    for s in r.get('scripts',[]): js_urls.add(urllib.parse.urljoin(BASE,s))
js_data={}
for u in js_urls:
    st,h,b,fin=fetch(u)
    js_data[u]={'status':st,'size':len(b),'body':b.decode('utf-8','replace')[:20000]}

out={'results':results,'js':{u:{k:v for k,v in d.items() if k!='body'} for u,d in js_data.items()},'cookies':jar}
json.dump(out,open('inventory.json','w'),indent=1)
for u,d in js_data.items():
    open('js_'+re.sub(r'[^A-Za-z0-9]','_',u.split('/')[-1])+'.txt','w').write(d['body'])

print('== PATHS ==')
for p,r in sorted(results.items(),key=lambda x:x[0]):
    print(f"{r['status']} {r['size']:>7} {p}  title={r['title'][:60]!r} loc={r['location']}")
print('== FORMS ==')
for p,r in results.items():
    for f in r['forms']: print(p,'->',json.dumps(f))
print('== JS ==')
for u,d in js_data.items(): print(u,d['status'],d['size'])
print('== COOKIES ==',jar)
