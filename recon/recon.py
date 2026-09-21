import re, ssl, json, time, urllib.parse, http.client, collections

HOST="pentest-ground.com"; PORT=4280
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
DEADLINE=time.time()+240
MAXP=400

def req(path, method="GET", body=None, cookies=None):
    h={"User-Agent":"Mozilla/5.0","Accept":"*/*"}
    if cookies: h["Cookie"]="; ".join(f"{k}={v}" for k,v in cookies.items())
    if body is not None: h["Content-Type"]="application/x-www-form-urlencoded"
    try:
        c=http.client.HTTPSConnection(HOST,PORT,context=ctx,timeout=12)
        c.request(method,path,body=body,headers=h)
        r=c.getresponse(); data=r.read(); hdrs=dict(r.getheaders()); c.close()
        return r.status,hdrs,data
    except Exception as e:
        return None,{},str(e).encode()

out={"fingerprint":{},"common_files":{},"endpoints":{},"forms":[],"js":[],"cookies_seen":{},"params":collections.defaultdict(set)}

st,h,b=req("/")
m=re.search(rb"<title>(.*?)</title>",b,re.S)
out["fingerprint"]={"status":st,"server":h.get("Server"),"x-powered-by":h.get("X-Powered-By"),
  "cookies":h.get("Set-Cookie"),"title":m.group(1).decode(errors="replace").strip() if m else ""}

COMMON=["/robots.txt","/sitemap.xml","/.git/HEAD","/.env","/.htaccess","/config.php","/phpinfo.php",
 "/info.php","/index.php~","/index.php.bak","/backup.zip","/backup.tar.gz","/db.sql","/dump.sql",
 "/swagger.json","/openapi.json","/api-docs","/actuator","/actuator/health","/server-status",
 "/.well-known/security.txt","/crossdomain.xml","/composer.json","/package.json","/.DS_Store",
 "/wp-login.php","/xmlrpc.php","/README.md","/CHANGELOG.txt","/docs/","/setup.php","/install.php",
 "/external/","/phpmyadmin/","/security.txt","/CHANGELOG.md","/ids_log.php"]
for p in COMMON:
    if time.time()>DEADLINE: break
    s,hh,bb=req(p)
    if s and s not in (404,):
        out["common_files"][p]={"status":s,"len":len(bb),"ctype":hh.get("Content-Type",""),
            "preview":bb[:120].decode(errors="replace")}

sess={}
s,hh,bb=req("/login.php")
mt=re.search(rb"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]",bb)
tok=mt.group(1).decode() if mt else None
ph=re.search(r"PHPSESSID=([0-9a-f]+)",hh.get("Set-Cookie","") or "")
if ph: sess["PHPSESSID"]=ph.group(1)
sess["security"]="low"
if tok:
    s2,h2,b2=req("/login.php","POST",f"username=admin&password=password&Login=Login&user_token={tok}",sess)
    out["login_attempt"]={"status":s2,"location":h2.get("Location","")}
    ph2=re.search(r"PHPSESSID=([0-9a-f]+)",h2.get("Set-Cookie","") or "")
    if ph2: sess["PHPSESSID"]=ph2.group(1)

seen=set(); q=collections.deque([("/",0),("/index.php",0)])
LINK=re.compile(rb'''(?:href|src|action)=['"]([^'"]+)['"]''',re.I)
FORM=re.compile(rb"<form[^>]*>(.*?)</form>",re.S|re.I)
while q and len(seen)<MAXP and time.time()<DEADLINE:
    path,depth=q.popleft()
    path=urllib.parse.urldefrag(path)[0]
    if path in seen: continue
    seen.add(path)
    s,hh,bb=req(path,cookies=sess)
    if s is None: continue
    ctype=hh.get("Content-Type","")
    sc=hh.get("Set-Cookie","")
    if sc:
        for nm in re.findall(r"(?:^|,\s*)([A-Za-z0-9_]+)=",sc):
            out["cookies_seen"][nm]=sc[:200]
    pr=urllib.parse.urlparse(path)
    if pr.query:
        for k in urllib.parse.parse_qsl(pr.query): out["params"][pr.path].add(k)
    out["endpoints"][path]={"status":s,"len":len(bb),"ctype":ctype.split(";")[0],"depth":depth}
    if "html" not in ctype or depth>=3: continue
    for f in FORM.findall(bb):
        am=re.search(rb"action=['\"]([^'\"]*)",f); mm=re.search(rb"method=['\"]([^'\"]*)",f)
        inputs=re.findall(rb"<(?:input|select|textarea)[^>]*name=['\"]([^'\"]+)",f)
        out["forms"].append({"page":path,"action":(am.group(1).decode() if am else path),
            "method":(mm.group(1).decode().upper() if mm else "GET"),
            "inputs":[i.decode() for i in inputs]})
    for l in LINK.findall(bb):
        l=l.decode(errors="replace").strip()
        if l.startswith(("javascript:","mailto:","data:")): continue
        u=urllib.parse.urljoin(path,l); pu=urllib.parse.urlparse(u)
        if pu.netloc and pu.netloc!=f"{HOST}:{PORT}": continue
        np_=pu.path+("?"+pu.query if pu.query else "")
        if pu.path.endswith((".js",)): out["js"].append(np_)
        if np_ not in seen and not re.search(r"\.(png|jpg|jpeg|gif|ico|css|svg|woff2?|ttf)$",pu.path,re.I):
            q.append((np_,depth+1))

out["params"]={k:sorted(v) for k,v in out["params"].items()}
out["js"]=sorted(set(out["js"]))
out["stats"]={"pages":len(seen),"elapsed":round(time.time()-(DEADLINE-240),1)}
json.dump(out,open("/workspace/recon/recon.json","w"),indent=1)
print(json.dumps(out["fingerprint"],indent=1))
print("LOGIN:",out.get("login_attempt"))
print("PAGES:",len(seen),"FORMS:",len(out["forms"]),"JS:",len(out["js"]))
print("COMMON HITS:",json.dumps(out["common_files"],indent=1)[:3000])
