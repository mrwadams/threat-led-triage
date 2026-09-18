# Threat-led triage: crAPI

Ranking of 20 findings by reachability, trust boundary and chaining, against the STRIDE-GPT threat
model (`crapi-threat-model.json`, 74 threats) and the checked-out code (`~/Documents/dev/crapi`).
This is the third column of the comparison: static scanners reported 1031 findings and caught 1 of
these 20; a frontier model reading the code scored abstract severity with no reachability. This
column asks what an attacker can actually reach and chain in crAPI's architecture.

Trust model (from the DFD): one boundary between the Untrusted External Zone and the Internal
Application Cluster. Everything reaches through the API Gateway. Reachability therefore turns on
per-endpoint authentication, which was verified in code, not assumed.

Provenance: the ranking, reachability calls, chains and reasoning below are the skill's output from
the 2026-08-26 run and are otherwise unedited. The `frontier-AI:` priors, where the run quoted them
in section headers and in the rank 3 explanation, were corrected on 2026-09-15 to match the
`frontier_ai_severity` field in `crapi-findings.json`, the input of record; the run had restated
several from its own judgement rather than reading the input. No rank, reachability call or chain
depends on the prior, so none changed.

## Fix order

| Rank | Finding | Reachability | Boundary crossed | Chains | Priority |
|------|---------|--------------|------------------|--------|----------|
| 1 | F15 JWT forgery → admin | unauthenticated | untrusted → authz decision | promotes entire authenticated band | Critical |
| 2 | F3 OTP brute → account takeover | unauthenticated | untrusted → identity data store | standalone ATO | Critical |
| 3 | F10 mass-assign `conversion_params` → RCE | authenticated (unauth via F15) | untrusted → OS/shell | F5→F10→convert_video | Critical |
| 4 | F18 unauth path traversal → arbitrary file read | unauthenticated | untrusted → filesystem/secrets | →F15, →F2 | Critical |
| 5 | F19 unauth order + customer PII disclosure | unauthenticated | untrusted → order/identity data | standalone | Critical |
| 6 | F5 leak internal `conversion_params` | authenticated | within cluster | entry of RCE chain (→F10) | High |
| 7 | F20 unauth service-request write | unauthenticated | untrusted → workshop data store | standalone | High |
| 8 | F14 unauthenticated workshop endpoints | unauthenticated | untrusted → workshop data | class of F18/F19 | High |
| 9 | F7 BFLA delete another user's video | authenticated | user → admin function | inherits F15 | High |
| 10 | F13 SQL injection in coupon redemption | authenticated | untrusted → SQL data store | standalone | High |
| 11 | F11 SSRF to internal network | authenticated | app → internal services | →gateway creds | High |
| 12 | F17 chatbot leaks another user's credentials | authenticated | tenant → tenant | →account access | High |
| 13 | F2 BOLA mechanic reports | authenticated | tenant → tenant | fed by F18 | High |
| 14 | F1 BOLA vehicle details | authenticated | tenant → tenant | standalone | High |
| 15 | F12 NoSQL injection, free coupons | authenticated | untrusted → Mongo data store | standalone | High |
| 16 | F4 excessive PII in list response | authenticated | tenant → tenant | feeds BOLA targeting | Medium |
| 17 | F16 chatbot prompt injection (client-side) | authenticated | user → own session | standalone | Medium |
| 18 | F9 inflate balance via refund | authenticated | user → own account | fed by F8 | Medium |
| 19 | F8 mass-assign order to get item free | authenticated | user → own order | →F9 | Medium |
| 20 | F6 rate-limit DoS via contact-mechanic | authenticated | availability only | standalone | Low |

## Reasoning

### 1. F15 JWT forgery → admin (frontier-AI: Critical, scanner: missed, now: Critical)
Reachability: unauthenticated. `JwtProvider.validateJwtToken` trusts the alg in the token header;
for HS256 it derives the HMAC secret from the RSA public key, or returns the hardcoded `'AA=='`
when the `kid` header contains `/dev/null` (`identity/.../config/JwtProvider.java`). The public key
is served pre-auth at `/identity/api/auth/jwks.json` (`AuthController.java:101`, and
`/identity/api/auth/**` is `permitAll` in `WebSecurityConfig.java:81`). An attacker signs a token
with `sub=admin@...` and is admin.
Boundary: untrusted external → the authorization decision itself.
Chains: this is the master key. A forged admin token makes every `authenticated()` finding below
reachable pre-auth, so the practical reachability of the whole High band collapses to
unauthenticated. That is why it ranks first even though several findings have larger single-shot
impact.
Why this rank: unauthenticated, full-admin, and it amplifies everything else. Nothing outranks it.

### 2. F3 OTP brute-force → account takeover (frontier-AI: Critical, now: Critical)
Reachability: unauthenticated. `/identity/api/auth/forget-password` and `/verify` are under the
`permitAll` auth path (`AuthController.java:88,111`). No rate limiting on OTP verification, so any
user's password is resettable by brute force.
Boundary: untrusted external → identity data store, resulting in account takeover.
Chains: standalone, but ATO of a chosen victim.
Why this rank: moved up from High. Pre-auth account takeover of an arbitrary user is Critical in
this architecture regardless of the abstract label.

### 3. F10 mass-assignment of `conversion_params` → RCE (frontier-AI: Medium, scanner: missed, now: Critical)
Reachability: authenticated directly; unauthenticated in practice via F15. `PUT
/identity/api/v2/user/videos/{id}` binds `VideoForm` including `conversion_params`
(`ProfileController.java:95`, `ProfileServiceImpl.updateProfileVideo`). `GET
.../videos/convert_video` (`ProfileController.java:145`) reads that stored value into
`String.format("convertVideo -i %s %s", ...)` and passes it to `BashCommand.exec` →
`Runtime.getRuntime().exec` (`ProfileServiceImpl.java:242`, `utils/BashCommand.java:44`). A test
fixture already stores `"-v codec h264 && ping 8.8.8.8"`.
Boundary: authenticated user → OS command execution on the identity host.
Chains: F5 (discover the field exists) → F10 (set it to a shell payload) → convert_video (RCE).
Why this rank: the frontier model called this Medium because in isolation it looks like editing a
metadata field. Reachability plus the convert_video sink turns it into RCE. This is exactly the
multi-primitive chain per-finding severity misses. Note the location in the source finding set
(`shop/views.py`) is wrong; the code is in identity `ProfileController`. See limits.

### 4. F18 unauthenticated path traversal → arbitrary file read (frontier-AI: High, now: Critical)
Reachability: unauthenticated. `DownloadReportView.get` has no `@jwt_auth_required`
(`mechanic/views.py:381`). `validate_filename` allows `%HH` sequences and validates the *encoded*
string, then `unquote`s it before building the path (`mechanic/views.py:389-397`), so `%2e%2e%2f`
passes the allowlist and becomes `../`. Validate-before-decode.
Boundary: untrusted external → filesystem, including Django `SECRET_KEY`, DB passwords and gateway
credentials the cross-cutting threats flag as on-disk.
Chains: reading secrets feeds F15 and broad credential compromise; reading `reports/` directly
yields other users' mechanic reports (an unauth path to F2's data).
Why this rank: the one arbitrary-read primitive that is pre-auth. Secrets on disk make it a
force-multiplier, not just a file leak.

### 5. F19 unauthenticated order + customer disclosure (frontier-AI: High, now: Critical)
Reachability: unauthenticated. `OrderControlView.get` has no decorator; the decorator sits on
`post`/`put` below it (`shop/views.py:109` vs `:167`). The docstring even claims "should be
authorised by the jwt token", but the code does not enforce it. It fetches any order by sequential
integer id and returns the owner's email, phone and name.
Boundary: untrusted external → order and identity data, cross-tenant.
Chains: standalone, but enumerable over sequential ids so it is a bulk PII leak, not a single record.
Why this rank: up from Medium. Unauthenticated, sequential, cross-tenant PII at scale.

### 6. F5 leak internal `conversion_params` (frontier-AI: Low, now: High)
Reachability: authenticated. `GET /identity/api/v2/user/videos/{id}` (`ProfileController.java:42`)
returns the video object including the internal `conversion_params`.
Boundary: within the authenticated zone.
Chains: this is the entry of the RCE chain (→F10). On its own it is a minor info leak; as the
thing that tells the attacker the injectable field exists, it earns High.
Why this rank: promoted from Low purely by its role in the chain, per the rubric.

### 7. F20 unauthenticated service-request write (frontier-AI: Medium, now: High)
Reachability: unauthenticated. The mechanic service exposes handlers with no `@jwt_auth_required`
(`ReceiveReportView.get` `mechanic/views.py:169`; `ServiceRequestView.get` `:368`), reachable
pre-auth through the gateway.
Boundary: untrusted external → workshop data store, write/injection of records.
Chains: class-related to F14/F18.
Why this rank: unauthenticated write, but lower blast radius than the account-takeover and RCE
items above it.

### 8. F14 unauthenticated workshop endpoints (frontier-AI: High, now: High)
Reachability: unauthenticated. Confirmed handlers with no decorator: `ReceiveReportView.get`,
`ServiceRequestView.get`, `DownloadReportView.get`, `OrderControlView.get`, `ReturnQRCodeView.get`
(`shop/views.py:349`), and merchant `UserServiceRequestsView.get` (`merchant/views.py:166`).
Boundary: untrusted external → workshop data.
Chains: this finding is the class that F18/F19/F20 are specific instances of.
Why this rank: real and pre-auth, but it is partly a summary of findings already ranked
individually, so it sits below them to avoid double-counting.

### 9. F7 BFLA delete another user's video (frontier-AI: High, now: High)
Reachability: authenticated; unauthenticated via F15. `DELETE /identity/api/v2/admin/videos/{id}`
(`ProfileController.java:129`) calls `deleteAdminProfileVideo` with no role check, so a normal user
reaches an admin function.
Boundary: authenticated user → admin function (function-level authz).
Chains: inherits F15's forged-admin reach.
Why this rank: cross-privilege but destructive-only (delete), below the RCE and disclosure items.

### 10. F13 SQL injection in coupon redemption (frontier-AI: Critical, scanner: DETECTED, now: High)
Reachability: authenticated. `ApplyCouponView.post` carries `@jwt_auth_required`
(`shop/views.py:365`). Injectable coupon query.
Boundary: authenticated → SQL data store.
Chains: standalone.
Why this rank: the one finding the scanners actually caught. Real and serious, but authenticated,
so it sits in the High band rather than above the pre-auth criticals.

### 11. F11 SSRF to internal network (frontier-AI: High, now: High)
Reachability: authenticated. `ContactMechanicView.post` (`merchant/views.py:45`) takes a
`mechanic_api` URL and does `requests.get(request_url, verify=False)` (`:43-47`).
Boundary: app → internal services behind the gateway, which the DFD shows holds databases and the
`vendorcrapi` gateway credential.
Chains: internal reach can pull gateway/DB credentials the cross-cutting threats flag.
Why this rank: authenticated, but the internal blast radius keeps it high in the band.

### 12. F17 chatbot leaks another user's credentials (frontier-AI: High, now: High)
Reachability: authenticated. Chatbot behind gateway auth; can be induced to disclose another user's
credentials.
Boundary: tenant → tenant.
Chains: leaked credentials → direct account access.
Why this rank: cross-tenant credential disclosure, top of the info-disclosure group.

### 13-15. F2, F1 BOLA and F12 NoSQL (now: High)
F2 (`mechanic/views.py:213`, GetReportView, authenticated but no ownership check on report id) and
F1 (identity `VehicleController`, vehicle by id without ownership) are authenticated cross-tenant
reads. F2 is additionally reachable unauth through F18's file read of `reports/`. F12 (community
`coupon_controller.go`) is an authenticated NoSQL injection for free coupons, lower business impact
than the BOLAs but a real injection into the Mongo store.

### 16-17. F4 excessive PII, F16 prompt injection (now: Medium)
F4 (`community/api/controllers/post_controller.go`) over-returns PII; authenticated, and its value
is mostly as an enabler for BOLA targeting rather than a standalone breach. F16 (chatbot prompt
injection to client-side rendering) is authenticated and scoped to the attacker's own session
unless combined with a delivery vector not in this set.

### 18-19. F8, F9 mass-assignment refund chain (frontier-AI: High, now: Medium)
F8 (`shop/views.py` order edit) → F9 (inflate balance). Authenticated, and the attacker acts on
their own account and balance. Real fraud, but self-scoped: no cross-tenant or system compromise,
so Medium despite F9's "High" abstract label.

### 20. F6 rate-limit DoS via contact-mechanic (frontier-AI: Medium, now: Low)
Reachability: authenticated. `ContactMechanicView.post` is decorated (`merchant/views.py:45`), so
the L7 DoS requires a logged-in user, and the impact is availability only with no data or privilege
consequence.
Why this rank: the clearest demotion. Labelled Medium on impact alone, but authenticated and
availability-only puts it at the bottom.

## Chains

- **F5 → F10 → convert_video (RCE).** Leak that `conversion_params` exists, mass-assign it to a
  shell payload, trigger conversion. Individually the frontier model scored these Low/Low. As a
  path they are remote code execution on the identity host. The chain outranks its links because
  none of them is RCE alone.
- **F18 → F15 / F18 → F2.** Unauthenticated arbitrary file read yields on-disk secrets (feeding
  token forgery and wide credential compromise) and other users' mechanic reports directly (an
  unauth route to F2's data).
- **F15 → entire authenticated band.** A forged admin token promotes every `authenticated()`
  finding to unauthenticated reach. This is why the reachability ceiling for crAPI is soft: the
  High band is one forged token away from Critical.
- **F8 → F9.** Order mass-assignment enables the balance inflation. Self-scoped, so the chain stays
  Medium.

## Limits of this analysis

- **Two source-location errors, corrected here.** F5, F7 and F10 were listed against
  `services/workshop/crapi/shop/views.py`; the video code is in `identity` `ProfileController` /
  `ProfileServiceImpl`. I ranked the real code and flagged the mismatch rather than marking them
  unresolved. A findings feed with wrong locations would mislead a purely location-based triage,
  which is itself a point worth making.
- **F15 promotion is judgement, not proof.** Treating the authenticated band as effectively
  unauthenticated because F15 exists is a defensible reading of the chain, but if F15 were fixed
  first the band genuinely reverts to authenticated ceilings. The ranking assumes the current
  state, where F15 is open.
- **Not in the finding set, observed in code.** `WebSecurityConfig.java:89` marks
  `/identity/management/admin/**` as `permitAll` — an unauthenticated admin path broader than any
  listed finding. Flagged here separately; not folded into the ranking because it was not an input.
- **Chatbot findings (F16/F17) traced shallowly.** Reachability was taken from the gateway auth
  topology and the challenge description, not a line-level trace of the MCP server, which is a
  heavier read than the time here allowed.
- **No ground truth.** crAPI's documented challenge order is a difficulty guide, not an
  exploitability ranking, so there is no oracle that says this order is correct. This is a
  defensible ordering with its reasoning exposed per finding, not a verified answer.
