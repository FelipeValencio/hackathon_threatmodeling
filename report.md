# SCOPE
## In scope components
- API Gateway: DoS and availability (rate-limiting, resource exhaustion, resilience).
- Auth Service: Impersonation, account takeover (ATO), and identity/session security; plus how Auth supports Safe Environment (age flagging, session security for minors).
- External Payment Service: Unauthorized purchases, secure payment processing, and account protection (participant and provider perspective).

## Out of scope
- Chat, Upload/Media, Moderation, Game Server, Marketplace logic, CDN, etc. Dependencies on these are noted where relevant (e.g. “payment assumes valid identity from Auth”) but are not analyzed in depth.

## Dependencies
- Auth is used by the API Gateway for request validation and by the Payment Service for identity; analysis assumes these integrations exist and focuses on threats at each component.

## Dependencies out of scope (acknowledged)
- **Persistence & Logging** and **Secrets Vault** are dependencies of the Auth Service (e.g. Auth stores sessions, user data, and event logs; Auth may use secrets for signing keys). They are out of scope for this threat model; analysis assumes they exist and are appropriately secured.
- **DevOps / CI/CD** is a dependency of the API Gateway mitigation that recommends a dedicated staging environment to test Gateway configuration and code updates before production. Pipeline and deployment practices are out of scope; the report assumes staging can be used as described.

## Priorities reasoning
- Safe Environment is partially in scope via Auth (age flagging, session security for minors, and identity/MFA as a control against misuse). Chat, moderation, and content are out of scope.
- TODO: Add about the priorities that are in scope, e.g. Finance, Availability

ASSUMPTIONS:
- Infrastructure is hosted on AWS
- WAF is deployed in front of all requests to the API gateway
- **Hardening:** All in-scope assets (Auth Service, API Gateway, External Payment Service) are assumed to be hardened and following security best practices (e.g. patching, secure config, encryption at rest). Threats in this report focus on **design choices** and **inherent risks** of the architecture, not baseline configuration gaps.
- **Persistence:** Persistence & Logging represents all backend persistence; other services’ DB access is implicit and out of scope for this diagram.
- **Secrets:** Only Marketplace and Chat are modeled as secret consumers; other components’ use of secrets is out of scope.
- **CDN:** Static assets and CDN are out of scope; only API and backend are modeled.
- **Diagram scope:** Other services’ persistence and secret use are implicit or out of scope (single Persistence flow and two Secrets flows in the diagram).
- **Token integrity:** Tokens are issued and signed by Auth; API Gateway and each service verify token signature (and aud where applicable) before trusting any claims (identity, roles, scopes).
- **Payment / CHD:** Cardholder data (CHD) is not stored or processed by the system. The payment collection UI is delegated to the third-party payment provider (hosted payment page or hosted fields); CHD flows only from browser to provider. The Gateway and backend handle only tokenized references, session identifiers, or non-CHD payment parameters.

---

## Threat model (STRIDE, design-focused)

Threats below arise from **design choices** and **inherent risks** of the three in-scope components. They are mapped with STRIDE, severity, and the hackathon priorities.

**Priorities (from system description):**
- **P1 Safe Environment** – Safe/inclusive atmosphere; child data (COPPA, GDPR-K); no unauthorized data collection/profiling/exposure.
- **P2 Financial Loss** – Provider: fraud, chargebacks, ATO, virtual asset theft. Participant: scams, phishing, unauthorized purchases; secure payment and account protection.
- **P3 DoS** – Service disruption (DDoS, resource exhaustion); resilience and availability; monitoring and mitigation.
- **+1 Other** – Integrity, compliance, reputation, operational risk.

**Severity:** Critical | High | Medium

---

### 1. API Gateway

| STRIDE | Threat | Severity | Priorities | Actionable mitigation (for engineering) |
|--------|--------|----------|-------------|------------------------------------------|
| **S** | Tokens stolen; Gateway accepts requests as the victim. | High | P2 | Issue short-lived, binding tokens (e.g. JWT): **exp** short TTL limits abuse window if stolen; **sub** binds token to a single identity so Gateway and services know who the principal is; **aud** restricts use to the intended API/service so a token stolen from one context cannot be used against another. Scope tokens per service or per sensitivity (e.g. one token/aud for real-time or gaming, one for purchases/payment, one for auth-sensitive operations such as password change or MFA) so a stolen token has limited blast radius. Revoke on logout and support token revocation list or short TTL. |
| **S** | Auth bypassed; Gateway accepts forged or invalid token as victim. | High | P2 | Auth must sign tokens with a secure method (e.g. JWT with RS256/ES256; signing key private to Auth, public key or JWKS available to Gateway and services). Validate signature and `aud` at API Gateway on every request; reject unsigned or invalid tokens. |
| **T** | Request/response tampering in transit between Gateway and backends or third party services (if any hop is not TLS or integrity is not enforced). | High | P2, +1 | Enforce TLS 1.2+ for all Gateway–backend connections; disable TLS downgrade; consider mTLS or signed requests for Gateway–Auth and Gateway–Payment. |
| **R** | No sufficient audit trail of which identity called which API/payment; dispute or forensics impossible. | Medium | P2, +1 | Log at Gateway: request ID, timestamp, principal ID (from Auth), method/path, and optionally redacted payment intent only. Retain logs per compliance; send to SIEM. |
| **I** | Misrouting leaks PII or payment-related data to wrong service. | High | P1, P2 | Route by path/header only; do not route based on request body or untrusted input; validate path and headers so each request reaches only the intended backend service. |
| **I** | Overly verbose logging leaks PII or payment-related data to log sinks. | High | P1, P2 | Do not log request/response bodies for auth or payment; restrict log access. |
| **D** | Gateway is single point of entry; rate limiting bypass or exhaustion causes platform-wide outage. | Critical | P3 | Implement rate limiting per identity and per IP (e.g. token bucket); use WAF + Gateway quotas; circuit-break backends; auto-scale Gateway; maintain a dedicated staging environment to test API Gateway configuration and code updates (rate limits, routes, quotas) before production rollout. |
| **E** | Backends reachable without going through Gateway, or admin/internal routes exposed; privilege escalation. | High | P2, +1 | Ensure Auth and Payment services are not directly internet-reachable; only Gateway (and WAF) have public exposure; restrict admin/internal routes by IP or VPN and require strong authn and authz. |

---

### 2. Auth Service (Identity)

| STRIDE | Threat | Severity | Priorities | Actionable mitigation (for engineering) |
|--------|--------|----------|-------------|------------------------------------------|
| **S** | Credential stuffing or phishing leads to account takeover. | Critical | P1, P2 | Enforce MFA for sensitive actions and high-risk logins; use strong password policy and breach-list checks. |
| **S** | Session token theft allows acting as user. | Critical | P1, P2 | Bind sessions to device/fingerprint and rotate on privilege change; short session TTL and refresh flow. |
| **T** | Password reset flow tampered (e.g. token leaked or reused); attacker resets victim password. | High | P1, P2 | One-time, short-lived reset tokens; bind to email and rate-limit resets. |
| **T** | Age flag tampered to bypass child protections. | High | P1, P2 | Store age flag in Auth and enforce at service level; integrity-check or sign age/attributes. |
| **I** | PII (especially minors) disclosed via Auth DB, logs, or API response to downstream. | Critical | P1 | Minimize stored PII; encrypt sensitive fields at rest; never log passwords or full tokens; restrict Auth API responses to what Gateway/Payment need; enforce COPPA/GDPR-K for underage data (consent, retention, access). |
| **D** | Auth endpoint exhausted (e.g. login floods); all services depending on Auth fail. | Critical | P3 | Rate limit login/register/reset per IP and per account; CAPTCHA or similar for unauthenticated auth endpoints; circuit-breaker and health checks; scale Auth independently; consider backoff or queue for auth. |
| **E** | Privilege escalation (e.g. gaining admin). | Critical | P1, P2 | Enforce RBAC; store roles in token or in Auth DB; each service should validate the roles from the token sent by the API Gateway (or from Auth) on each request, using only claims from a cryptographically verified token (see scope/role tampering mitigation). |
| **E** | Attacker adds or modifies scopes/roles in token to escalate privileges (e.g. add admin scope). | High | P1, P2 | Auth signs all tokens (e.g. JWT with RS256/ES256) so any change to claims invalidates the signature; Gateway and each service must verify the token signature before trusting any claims (sub, aud, roles/scopes)—reject tokens that are unsigned, tampered, or have invalid signature; for high-privilege actions consider validating roles against Auth as the authoritative source. |
| **E** | MFA bypass via recovery codes or social engineering. | High | P1, P2 | Limit MFA recovery options and audit recovery use; train support to avoid social-engineering bypass. |

---

### 3. External Payment Service

**Payment flow design (cardholder data — CHD):** The design avoids storing or processing cardholder data (CHD) to limit risk and PCI scope. The intended design is to **delegate the payment collection UI to the third-party payment provider** so that CHD never transits or touches the system. Two common patterns support this:

- **Hosted payment page (redirect):** The user is sent to the provider’s page to enter card details; CHD goes only to the provider. The backend receives a token, session ID, or success callback (no PAN/CVV).
- **Hosted fields / embedded component:** The provider’s JS or iframe renders the card field in the application page; form submission goes directly to the provider. The backend only ever receives a tokenized reference (e.g. payment method ID) to complete the transaction.

In both cases, **card data flows Browser → provider only**; the API Gateway and backend never see CHD. The diagram’s “Credit Card Data” on Browser→WAF→Gateway should be interpreted as either (a) not applicable for the payment step (CHD goes browser→provider only), or (b) only tokenized references or non-CHD payment parameters transit the Gateway. The mitigations in this section assume this design (e.g. ensure Payment receives only tokenized ref; use provider tokenization or hosted fields so card data does not touch the system). Remaining in-scope concerns: **identity binding** (verified user ID when initiating payment or when the system calls the provider with a token), **amount/currency verification** server-side, **audit trail** (payment intent, provider transaction ID, receipts), and **authorization** for refunds—all without handling CHD.

| STRIDE | Threat | Severity | Priorities | Actionable mitigation (for engineering) |
|--------|--------|----------|-------------|------------------------------------------|
| **S** | Payment initiated as another user because payment request is not strongly bound to authenticated identity. | Critical | P2 | Gateway/Auth must pass a stable, verified user ID to the payment flow; Payment (or the orchestrator) must reject requests that do not match the authenticated user; never trust client-supplied identity for payment. |
| **T** | Amount, currency, or refund request tampered in transit or by client, causing financial loss or dispute. | High | P2 | Verify amount and currency server-side from the order/cart; use idempotency keys for payment and refund; sign or integrity-check payment parameters; the Payment provider should return and the system should verify the final amount. |
| **R** | Dispute or chargeback with no clear proof of user consent or transaction; no audit trail. | High | P2, +1 | Store payment intent (amount, currency, user ID, idempotency key) before calling Payment; log provider transaction ID and outcome; issue receipts and retain per PCI/regulatory requirements. |
| **I** | PII or payment-related data exposed in logs or API responses. | Critical | P1, P2 | The backend and Gateway accept only tokenized refs or payment method IDs—never accept, log, or store PAN/CVV. Use provider tokenization or hosted fields; restrict Payment API responses to non-sensitive data. |
| **I** | PII or payment-related data exposed to wrong tenant or service. | Critical | P1, P2 | Apply same PII controls as for Auth; restrict access by tenant/service. |
| **D** | Payment API unavailable so users cannot complete purchases; revenue and trust impact. | High | P3 | Use provider SLA and status page; implement retries with backoff and idempotency; graceful degradation (e.g. “payments temporarily unavailable”); monitor payment success rate and latency. |
| **E** | Unauthorized refund or subscription change because Payment API is called without proper authorization. | High | P2 | All payment and refund calls must be initiated server-side and tied to authenticated operator or user; enforce “refund only for same user or support with audit”; no client-side direct Payment API keys; RBAC for admin refunds. |

---

## Summary and priorities

| Severity | Count | Focus for engineering |
|----------|-------|------------------------|
| Critical | 8 | Gateway DoS; ATO and session theft (Auth); PII/minors (Auth); Auth DoS; Payment identity binding; Payment PII in logs/responses and wrong tenant |
| High | 16 | Gateway: token theft, Auth bypass, TLS, misrouting, verbose logging, backend exposure. Auth: password reset, age flag, privilege escalation, scope/role tampering in token, MFA bypass. Payment: tampering, repudiation, availability, refund/subscription auth. |
| Medium | 2 | Gateway and Auth audit trails. |

**TOP PRIORITY (squad actions):**
1. **Payment–identity binding:** Ensure every payment and refund is tied to a verified identity from Auth; reject any payment request not matching the authenticated user.
2. **Auth MFA and session design:** Enforce MFA for high-risk and payment-related actions; short-lived, binding sessions; no sensitive data in logs.
3. **Gateway rate limiting and DoS:** Enforce per-identity and per-IP limits; staging environment for Gateway updates; ensure backends are not directly reachable.
4. **PII and minors (Auth):** Minimize and protect underage and PII in Auth store and logs; enforce COPPA/GDPR-K and access control.

**NEXT STEPS:**
- Implement mitigations above in order of severity; treat Critical items as sprint 0 / security backlog must-haves.
- Add Gateway request/response logging and Auth event logging to SIEM; define alerts for auth failures, payment anomalies, and Gateway errors.
- Re-validate payment orchestration (see `hypothesis to be modeled.md`) and ensure design matches “strong identity binding” and server-side-only payment calls. 