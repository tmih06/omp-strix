---
name: bola-idor-sweeps
description: Adaptive object-reference harvesting and replay — harvest IDs and tokens from every response, then sweep sibling IDs horizontally and low-priv tokens vertically across endpoints
---

# BOLA / IDOR Sweeps

Authorization bugs only surface when identifiers and tokens harvested from one response are replayed against sibling endpoints. Testing each endpoint in isolation misses them entirely. Harvest continuously, replay systematically.

This skill is the sweep mechanics; `idor` covers the full class taxonomy and `broken_function_level_authorization` the vertical theory.

## Harvesting

From **every** response — yours and other agents' — extract into shared artifacts (`create_note` / scan artifacts):

- **Object IDs**: UUIDs, numeric IDs, hashes, slugs, composite keys (`{org}:{user}`), base64 node IDs (GraphQL Relay).
- **Auth material**: bearer tokens, session cookies, API keys, signed URLs — tagged by principal and privilege level.
- **Endpoint shapes**: normalized routes (`/user/:id`) with the param names that carry IDs.

Sources beyond responses: JS bundles, emails, exports, notifications, error messages, list/search endpoints (richest ID seeders).

Maintain at least **two principals** — owner and non-owner, plus admin and low-priv where roles exist — each with auth material and at least one valid object ID.

## The Sweep

For each authenticated endpoint carrying an object reference, replay in two directions:

- **Horizontal (BOLA)**: same token, sibling ID — another user's object at the same privilege level.
- **Vertical (BFLA)**: low-priv token, privileged route — admin/staff endpoints with a user credential.

Vary transport too: REST ↔ GraphQL ↔ export endpoints often enforce differently. Batch endpoints frequently check only the first element — put foreign IDs mid-array.

## Recipes

### BOLA

1. Authenticate (or observe token); capture a valid object ID for your own principal.
2. Replay `GET /api/v2/resource/<OTHER_USER_ID>` with your `Authorization` header.
3. A `200` returning another user's data is the finding. An empty `200` is not — compare against the owner's view.

### Mass Assignment

1. Resend a legitimate `POST`/`PUT`/`PATCH` with an extra privileged field: `"is_admin": true`, `"role": "admin"`, `"tenant_id": <other>`, `"balance": 0`.
2. Check the field took effect — not just persisted in a response echo, but usable (admin routes now open, role reflected in a fresh fetch).

### BFLA (vertical privesc)

1. Authenticate as a **low-privilege** user; capture the token.
2. Call privileged routes: `POST`/`DELETE` on `/api/v2/admin/*`, `/internal/*`, user management, impersonation, feature flags.
3. A `2xx` performing the action is vertical privesc. A `200` on `OPTIONS` or an empty no-op is not — confirm state change.

### Auth-Bypass Mutations

Apply after a real `401`/`403`, not randomly:

- Headers: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`.
- Path tweaks: trailing slash (`/admin/`), `%2e` (`/%2e/admin`), case (`/ADMIN`), double slash, `;.json`, method override (`X-HTTP-Method-Override`, `_method=`).

## Evidence Standard

- Horizontal: protected **data returned** or a real state change on another principal's object.
- Vertical: the privileged **action performed** — a 200 on a no-op proves nothing.
- Always pair the proof with the control: same request with the correct principal/role succeeding or failing as designed.

## False Positives

- Public/anonymous resources by design.
- Empty `200` responses — silent enforcement, not access; diff against the owner's view.
- Cached CDN responses keyed without auth headers — verify the origin enforces, not just the edge.
- IDs you were legitimately granted (shared resources, org-wide objects).

## Rules

1. Harvest from every response — the ID you need for endpoint N is usually in response N−3.
2. Replay sibling IDs on every authenticated route, not just obvious `/users/:id`.
3. Two principals minimum; three when roles exist (user, other-user, admin).
4. Record each sweep cell (endpoint × principal × result) in coverage — an unswept route is a gap, not a zero.
5. Blind channels count: status/size/ETag/timing differentials confirm existence when bodies are masked.
