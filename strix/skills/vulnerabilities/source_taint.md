---
name: source-taint
description: Two-pass white-box taint methodology — permissive candidate generation over network entrypoints, then skeptical per-class verification with demand-driven symbol expansion
---

# Source Taint (Two-Pass White-Box)

White-box taint analysis finds what black-box probing cannot reach: sinks behind auth, internal handlers, and paths that need a specific input shape to fire. The method is two passes with opposite temperaments — Pass 1 is permissive and generates candidates, Pass 2 is skeptical and kills them. Never merge the passes: a single pass either over-reports (permissive) or misses (skeptical).

Use this skill when repository source is available. It complements `source_aware_whitebox` (coordination) and `source_aware_discovery` (mapping); this file is the per-class verification discipline.

## Pass 0: Entrypoint Fingerprinting

Only files that receive remote input matter for candidate generation. Fingerprint entrypoint files by routing/handler signatures — do not scan tests, fixtures, CLI scripts, migrations, or vendored code.

### Python

```regex
# Flask / Quart / Bottle
@(app|bp|blueprint|\w+)\.(route|get|post|put|delete|patch|add_url_rule)\b
# FastAPI / Starlette
@(router|app|api)\.(get|post|put|delete|patch|websocket|route)\b
APIRouter\(|FastAPI\(|Starlette\(
# Django
path\(|re_path\(|url\(|urlpatterns|@require_http_methods|class \w+\((View|APIView|ViewSet)
# Tornado
class \w+\((RequestHandler|WebSocketHandler)\)|Application\(\[|add_handlers\(
# aiohttp
web\.(get|post|put|delete|patch|route)\(|add_routes\(|RouteTableDef
# Sanic
@(app|bp)\.(route|get|post|put|delete|patch|websocket)\b|Sanic\(
# GraphQL (Graphene / Strawberry / Ariadne)
graphene\.ObjectType|@strawberry\.(type|mutation|query)|QueryType\(|MutationType\(
# Serverless / workers
def (lambda_handler|handler)\(|@app\.lambda_function|azure\.functions|functions_framework
```

### Node.js / TypeScript

```regex
# Express / Koa / generic router
(app|router|server)\.(get|post|put|delete|patch|use|all)\s*\(
# Fastify
fastify\.(get|post|put|delete|patch|route|register)\s*\(
# NestJS
@(Controller|Get|Post|Put|Delete|Patch|MessagePattern|EventPattern)\s*\(
# Hono / Restify / raw
\.(on|route|handler)\s*\(|createServer\s*\(
```

### Go

```regex
# net/http
http\.(HandleFunc|Handle|ListenAndServe)\b|ServeMux
# Gin
\.(GET|POST|PUT|DELETE|PATCH|Group|Use)\s*\(|gin\.(Default|New)\(
# Chi / Echo / Fiber / Gorilla
chi\.NewRouter|r\.(Get|Post|Put|Delete|Route|Mount)\s*\(
e\.(GET|POST|PUT|DELETE|Add)\s*\(|echo\.New\(
app\.(Get|Post|Put|Delete|Use)\s*\(|fiber\.New\(
```

Files matching none of these are Pass-2 context only — pull from them when a taint chain leads there, never as candidate origins.

## Pass 1: Permissive Candidate Generation

For each entrypoint file, enumerate candidate source→sink pairs across all 7 classes. Be generous: if there is a *possibility* a flow exists, record it — Pass 2 exists to kill false positives, so a missed candidate here is never recovered.

For each candidate record: class, source (the request-derived value), sink (file:line), and the intermediate calls you can see. Do not evaluate controls yet.

## Pass 2: Skeptical Verification

Verify one candidate at a time, one class at a time. Your stance is disbelief: the candidate is false until the trace proves otherwise.

**Demand-driven symbol expansion.** When the chain calls a function or method you cannot see, fetch *only that symbol's definition* — the enclosing function body, not the whole file. Use `sg`/tree-sitter, `jedi`, or targeted `grep` for the `def`/`func`/`function` boundary. Never dump entire files into context to follow one call. If the symbol is third-party (framework, ORM, stdlib), do not fetch it — apply its known semantics and continue.

**Hop discipline.** Chains longer than ~7 hops rarely converge; if you hit the limit with the flow still unresolved, record `needs_follow_up` with the chain so far rather than forcing a verdict.

**Control evaluation.** A sanitizer only counts if you verified it: it runs on *this* path, *before* the sink, and neutralizes *this* class in *this* context. An HTML escaper does nothing in a JS context; a path joiner is not a containment check; a validator that can fail open is not a control.

## Per-Class Source → Sink Checklists

### RCE — command/code execution

- Sources: any request param, header, cookie, uploaded filename/content, deserialized body.
- Sinks: `os.system`, `subprocess.*(shell=True)`, `eval`/`exec`, `pickle.loads`, `yaml.load` (non-safe), `child_process.exec`, `vm.runIn*`, `os/exec.Command`, template render with user-controlled template text.
- Check: input reaches the command/code position (not just an argument position with fixed binary); shell metacharacters survive; no allowlist on the executable; deserialization sinks reachable with attacker bytes.

### SQLi

- Sources: params, path segments, JSON fields, headers (`X-Forwarded-For` logged to DB), cookies.
- Sinks: `cursor.execute`/`executemany` with f-string/format/concat, `Model.objects.raw`, `extra(where=...)`, `knex.raw`, `sequelize.query`, `db.Query`/`Exec` with `fmt.Sprintf`, string-built `ORDER BY`/`IN`/identifier positions.
- Check: concatenation vs parameterization — partial parameterization (`IN (%s)` built by join) still counts; dynamic identifiers (table/column names) need quoting, not binding; ORM "raw" escape hatches.

### LFI — file read / path traversal

- Sources: filename/path params, `?file=`, download/export endpoints, archive member names.
- Sinks: `open(path)` read mode, `send_file`/`send_from_directory`, `fs.readFile`, `os.Open`, `include`/`require`, template inclusion.
- Check: `../` sequences survive normalization; allowlist is prefix-based (bypassable via `allowed/../..`); `os.path.join` with absolute second arg discards the base; symlink following; URL-encoded/double-encoded traversal decoded before the check.

### AFO — arbitrary file overwrite (its own class, not LFI)

- Sources: upload filenames, `rename`/`move` targets, extraction paths, config/cache paths, log paths.
- Sinks: `open(path, 'w'/'a'/'x')`, `os.rename`, `os.replace`, `shutil.move`/`copy`, `fs.writeFile`/`rename`, `os.WriteFile`, `ZipFile.extract`/`extractall` (zip-slip writes), tar extraction without member filtering.
- Check: attacker controls the *destination* path, not just content; traversal in archive member names (`../../etc/cron.d/x`); write reaches sensitive targets (config, `.ssh/authorized_keys`, templates, code); extension allowlist bypassed via `evil.php%00.jpg`, `;.jpg`, trailing dot, or case.

### SSRF

- Sources: URL params, webhook/callback URLs, `avatar_url`, import-from-URL, feed readers, PDF/image fetchers.
- Sinks: `requests.get`/`urllib`/`httpx`, `fetch`/`axios`, `http.Get`, `curl_*`, headless-browser navigations, SDK clients built from user URLs.
- Check: scheme allowlist (`file://`, `gopher://`, `dict://` survive?); DNS rebinding between check and fetch; redirect following re-checks the target; IP literal/decimal/hex forms bypass host allowlists; cloud metadata reachability (`169.254.169.254`).

### XSS

- Sources: any stored or reflected input reaching a render path.
- Sinks: `render_template_string`/`Markup`|`|safe`, `innerHTML`/`dangerouslySetInnerHTML`, `document.write`, `v-html`, template autoescape disabled, JSON embedded in `<script>` without escaping.
- Check: output context (HTML body vs attribute vs JS vs URL vs CSS) — the payload must match the context; encoding applied is correct *for that context*; stored paths reach other users.

### IDOR — object reference without ownership binding

- Sources: IDs in path/query/body (`id`, `user_id`, `org`, `doc`, `invoice`), GraphQL node IDs.
- Sinks: ORM fetches (`get`, `filter`, `findById`, `First`), raw queries by ID, file/object-store lookups by key.
- Check: the fetch is not additionally constrained by the caller's identity (`WHERE owner = <caller>`); no decorator/middleware performs the ownership check on *this* route; batch/bulk paths check only the first element.

## Confidence Rule

Score each verified candidate 0–10:

- **Hard cap at ≤6** if the PoC does not start with remote user input via remote networking calls (HTTP, API, RPC). CLI-only, local-file, and developer-workstation bugs are hypotheses, not findings.
- `<7`: do not report — record `needs_follow_up` with the trace.
- `7`: reportable, but flag for manual review.
- `8+`: high-certainty — unbroken remote source→sink trace with controls shown absent or bypassed.

## Validation

1. Name the source (request-derived value) and the sink (file:line) for every candidate.
2. Show the unbroken chain — every hop's callee definition was actually read, not assumed.
3. State the control that fails, or that none exists on this path.
4. Prefer a dynamic PoC when the app can run; a complete static trace at confidence ≤6–7 is the fallback, never the goal.

## False Positives

- Sink reached only by trusted callers (admin CLI, internal cron) — cap applies.
- A control verified on this exact path, before the sink, correct for this class.
- Input traced to a trusted origin (server-generated, signed, allowlisted constant).
- Dead code: entrypoint registered but unreachable (commented route, feature-flagged off and confirmed off).

## Pro Tips

1. Run Pass 1 per file, Pass 2 per candidate — never both at once.
2. Fetch definitions, not files; whole-file reads are how context dies.
3. Third-party symbols get semantics, not source.
4. AFO is not LFI: write-side traversal has different sinks (`open(w)`, `os.rename`, `shutil.move`, archive extraction) and different bypasses.
5. The ≤6 cap is the filter that keeps internal helpers out of the report.
6. Record unresolved chains as `needs_follow_up`, not `ruled_out` — missing evidence is not evidence of absence.
