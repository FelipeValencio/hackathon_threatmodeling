# SCOPE
## In scope components
- API Gateway: DoS and availability (rate-limiting, resource exhaustion, resilience).
- Auth Service: Impersonation, account takeover (ATO), and identity/session security; plus how Auth supports Safe Environment (age flagging, session security for minors).
- External Payment Service: Unauthorized purchases, secure payment processing, and account protection (participant and provider perspective).

## Out of scope
- Chat, Upload/Media, Moderation, Game Server, Marketplace logic, CDN, etc. Dependencies on these are noted where relevant (e.g. “payment assumes valid identity from Auth”) but are not analyzed in depth.

## Dependencies
- Auth is used by the API Gateway for request validation and by the Payment Service for identity; analysis assumes these integrations exist and focuses on threats at each component.

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
| **S** | Gateway trusts Auth for identity; if tokens are stolen or Auth is bypassed, Gateway accepts requests as the victim. | High | P2 | Issue short-lived, binding tokens (e.g. JWT with `sub`, `aud`, `exp`); validate signature and `aud` at Gateway on every request; revoke on logout and support token revocation list or short TTL. |
| **T** | Request/response tampering in transit between Gateway and backends (if any hop is not TLS or integrity is not enforced). | High | P2, +1 | Enforce TLS 1.2+ for all Gateway–backend connections; disable TLS downgrade; consider mTLS or signed requests for Gateway–Auth and Gateway–Payment. |
| **R** | No sufficient audit trail of which identity called which API/payment; dispute or forensics impossible. | Medium | P2, +1 | Log at Gateway: request ID, timestamp, principal ID (from Auth), method/path, and optionally redacted payment intent (no card data). Retain logs per compliance; send to SIEM. |
| **I** | Misrouting or overly verbose logging leaks PII or payment data to wrong service or log sinks. | High | P1, P2 | Route by path/header only; do not log request/response bodies for auth or payment; restrict log access; ensure Payment receives only what it needs (e.g. tokenized ref, not raw card). |
| **D** | Gateway is single point of entry; rate limiting bypass or exhaustion causes platform-wide outage. | Critical | P3 | Implement rate limiting per identity and per IP (e.g. token bucket); use WAF + Gateway quotas; circuit-break backends; auto-scale Gateway; define and test DDoS playbook with WAF/proxy provider. |
| **E** | Backends reachable without going through Gateway, or admin/internal routes exposed; privilege escalation. | High | P2, +1 | Ensure Auth and Payment are not directly internet-reachable; only Gateway (and WAF) have public exposure; restrict admin/internal routes by IP or VPN and require strong auth. |

---

### 2. Auth Service (Identity)

| STRIDE | Threat | Severity | Priorities | Actionable mitigation (for engineering) |
|--------|--------|----------|-------------|------------------------------------------|
| **S** | Credential stuffing or phishing leads to account takeover; session token theft allows acting as user. | Critical | P1, P2 | Enforce MFA for sensitive actions and high-risk logins; use strong password policy and breach-list checks; bind sessions to device/fingerprint and rotate on privilege change; short session TTL and refresh flow. |
| **T** | Password reset flow tampered (e.g. token leaked or reused); attacker resets victim password. Age flag tampered to bypass child protections. | High | P1, P2 | One-time, short-lived reset tokens; bind to email and rate-limit resets; store age flag in Auth and enforce at Gateway/backends; integrity-check or sign age/attributes. |
| **R** | User denies having logged in or performed action; no non-repudiation. | Medium | P2, +1 | Log all auth events (login, logout, MFA, reset, failure) with identity, timestamp, IP, outcome; retain for dispute and compliance; protect log integrity. |
| **I** | PII (especially minors) disclosed via Auth DB, logs, or API response to downstream. | Critical | P1 | Minimize stored PII; encrypt sensitive fields at rest; never log passwords or full tokens; restrict Auth API responses to what Gateway/Payment need; enforce COPPA/GDPR-K for underage data (consent, retention, access). |
| **D** | Auth endpoint exhausted (e.g. login floods); all services depending on Auth fail. | Critical | P3 | Rate limit login/register/reset per IP and per account; CAPTCHA or similar for unauthenticated auth endpoints; circuit-breaker and health checks; scale Auth independently; consider backoff or queue for auth. |
| **E** | Privilege escalation (e.g. gaining admin); MFA bypass via recovery codes or social engineering. | High | P1, P2 | Enforce RBAC; store roles in token or in Auth DB and validate on each request; limit MFA recovery options and audit recovery use; train support to avoid social-engineering bypass. |

---

### 3. External Payment Service

| STRIDE | Threat | Severity | Priorities | Actionable mitigation (for engineering) |
|--------|--------|----------|-------------|------------------------------------------|
| **S** | Payment initiated as another user because payment request is not strongly bound to authenticated identity. | Critical | P2 | Gateway/Auth must pass a stable, verified user ID to the payment flow; Payment (or your orchestrator) must reject requests that do not match the authenticated user; never trust client-supplied identity for payment. |
| **T** | Amount, currency, or refund request tampered in transit or by client, causing financial loss or dispute. | High | P2 | Verify amount and currency server-side from your order/cart; use idempotency keys for payment and refund; sign or integrity-check payment parameters; Payment provider should return and you should verify final amount. |
| **R** | Dispute or chargeback with no clear proof of user consent or transaction; no audit trail. | High | P2, +1 | Store payment intent (amount, currency, user ID, idempotency key) before calling Payment; log provider transaction ID and outcome; issue receipts and retain per PCI/regulatory requirements. |
| **I** | Card data or PII exposed in logs, responses, or to wrong tenant/service. | Critical | P1, P2 | Never log or store full PAN/CVV; use provider tokenization or hosted fields so card data does not touch your stack; restrict Payment API responses to non-sensitive data; apply same PII controls as for Auth. |
| **D** | Payment API unavailable so users cannot complete purchases; revenue and trust impact. | High | P3 | Use provider SLA and status page; implement retries with backoff and idempotency; graceful degradation (e.g. “payments temporarily unavailable”); monitor payment success rate and latency. |
| **E** | Unauthorized refund or subscription change because Payment API is called without proper authorization. | High | P2 | All payment and refund calls must be initiated server-side and tied to authenticated operator or user; enforce “refund only for same user or support with audit”; no client-side direct Payment API keys; RBAC for admin refunds. |

---

## Summary and priorities

| Severity | Count | Focus for engineering |
|----------|-------|------------------------|
| Critical | 5 | ATO (Auth), PII/minors (Auth), identity binding and card handling (Payment), Gateway DoS. |
| High | 10 | Token/session design, TLS, logging, Gateway exposure, Auth reset/age, Auth DoS, Payment tampering/repudiation/availability, Payment authorization. |
| Medium | 2 | Gateway and Auth audit trails. |

**TOP PRIORITY (squad actions):**
1. **Payment–identity binding:** Ensure every payment and refund is tied to a verified identity from Auth; reject any payment request not matching the authenticated user.
2. **Auth MFA and session design:** Enforce MFA for high-risk and payment-related actions; short-lived, binding sessions; no sensitive data in logs.
3. **Gateway rate limiting and DoS:** Enforce per-identity and per-IP limits; validate DDoS runbook with WAF; ensure backends are not directly reachable.
4. **PII and minors (Auth):** Minimize and protect underage and PII in Auth store and logs; enforce COPPA/GDPR-K and access control.

**NEXT STEPS:**
- Implement mitigations above in order of severity; treat Critical items as sprint 0 / security backlog must-haves.
- Add Gateway request/response logging and Auth event logging to SIEM; define alerts for auth failures, payment anomalies, and Gateway errors.
- Re-validate payment orchestration (see `hypothesis to be modeled.md`) and ensure design matches “strong identity binding” and server-side-only payment calls. 