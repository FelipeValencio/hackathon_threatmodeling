# Executive Summary

This threat model focuses on three foundational components of a city-building game platform: **API Gateway**, **Auth Service**, and **External Payment Service**. These components were chosen because they provide root-level security as if they are compromised, attackers can impersonate players, exhaust the platform, or abuse in-game purchases. The analysis uses STRIDE and addresses the priorities Financial Loss, Denial of Service, and Safe Environment.

Key findings: Approximately 20 design-level threats were raised; 10 were retained as those requiring major design or architectural changes. The retained threats span 4 Critical, 6 High across API Gateway, Auth Service, and External Payment Service. The most urgent risks are: payment–identity binding (ensuring every payment is tied to a verified user from Auth); account takeover and session theft via Auth (credential stuffing, stolen tokens); platform-wide DoS if the Gateway or Auth is exhausted; and PII/minors data exposure in Auth (COPPA/GDPR-K).

**Top actions for engineering:** (1) Bind all payment and refund flows to verified identity from Auth. (2) Enforce MFA for high-risk and payment-related actions, with short-lived, binding sessions. (3) Implement per-identity and per-IP rate limiting at the Gateway and use a staging environment for Gateway changes. (4) Minimize and protect PII and underage data in Auth; enforce COPPA/GDPR-K.

# Diagram

The diagram (Annex A) depicts the city-building game architecture with trust zones (e.g. Internet, AWS, Private Subnet, Trusted Partner), the main components (Browser, WAF, API Gateway, Auth Service, 3rd Party Payment Service, and other game services), and the data flows between them. The **in-scope components** for this report, **API Gateway**, **Auth Service (Identity)**, and **External (3rd Party) Payment Service**, correspond to the diagram elements: the Gateway as the single public entry (Browser → WAF → API Gateway), the Auth Service as the identity provider, and the 3rd Party Payment Service as the external payment provider. Key flows relevant to this threat model are: Browser → WAF → API Gateway; API Gateway → Auth Service (credentials, tokens); API Gateway → 3rd Party Payment Service (payment requests and tokenized references). Threats and mitigations in this report are written with this architecture in consideration.

# Scope

## In scope components

* **API Gateway** – The single public entry point for all game traffic. We analyze risks that could exhaust or overwhelm it (denial of service), causing players to be unable to log in or play.  
* **Auth Service** – The component that verifies player identity, manages logins and sessions, and stores age flags for child protection. We analyze risks of impersonation (attackers acting as other players), account takeover (stolen credentials or sessions), and exposure of minor players' data.  
* **External Payment Service** – The third-party provider that processes in-game purchases (e.g. cosmetics, currency, upgrades). We analyze risks of unauthorized charges, refund abuse, and payment flows that are not correctly tied to the authenticated player.

## Out of scope

* Chat, Upload/Media, Moderation, Game Server, Marketplace logic (catalog, order creation, entitlement issuance), CDN, Background Workers (e.g. payment batch reconciliation, image processing), and third-party mods. Dependencies on these are noted where relevant (e.g. “payment assumes valid identity from Auth and that orders/entitlements are created by Marketplace”) but are not analyzed in depth.

## Dependencies

* Auth is used by the API Gateway for request validation and by the Payment Service for identity; analysis assumes these integrations exist and focuses on threats at each component.

## Dependencies out of scope (acknowledged)

* **Persistence & Logging** and **Secrets Vault** are dependencies of the Auth Service (e.g. Auth stores sessions, user data, and event logs; Auth may use secrets for signing keys). They are out of scope for this threat model; analysis assumes they exist and are appropriately secured.  
* **DevOps / CI/CD** is a dependency of the API Gateway mitigation that recommends a dedicated staging environment to test Gateway configuration and code updates before production. Pipeline and deployment practices are out of scope; the report assumes staging can be used as described.

# Priorities reasoning

Scope was defined around the three components above because they provide foundational level security for the game platform: Auth Service, API Gateway act as foundational controls and External Payment Service is the service responsible for all payments. Additionally, these assets are of interest because the participant is focused on threat modeling foundational services to learn more about foundation security controls and threats to Auth, API Gateway, and External Payment services.

Within that scope, the priorities are mapped as:

* **Financial Loss** is in scope via Auth (account takeover, identity binding) and Payment (unauthorized purchases, secure processing, refunds). Marketplace catalog and entitlement logic are out of scope; we assume payment is invoked in the context of orders/entitlements from the Marketplace.  
* **Denial of Service** is in scope via API Gateway (rate-limiting, resilience, platform-wide availability) and Auth (login/register exhaustion). Game Server and Chat DoS are out of scope.  
* **Safe Environment** is partially in scope via Auth (age flagging, session security for minors, and identity/MFA as a control against misuse). Chat, moderation, and content are out of scope.

# Assumptions

* Infrastructure is hosted on AWS  
* WAF is deployed in front of all requests to the API gateway  
* All in-scope assets (Auth Service, API Gateway, External Payment Service) are assumed to be hardened and follow security best practices (e.g. patching, secure config, encryption at rest). Threats in this report focus on **design choices** and **inherent risks** of the architecture, not baseline configuration gaps.  
* Persistence & Logging represents all backend persistence; other services’ DB access is implicit and out of scope for this diagram.  
* Only Marketplace and Chat are modeled as secret service consumers; other components’ use of secrets is out of scope.  
* Tokens are issued and signed by Auth; API Gateway and each service verify token signature (and aud where applicable) before trusting any claims (identity, roles, scopes).  
* Cardholder data (CHD) is not stored or processed by the system. The payment collection UI is delegated to the third-party payment provider (hosted payment page or hosted fields); CHD flows only from browser to provider. The Gateway and backend handle only tokenized references, session identifiers, or non-CHD payment parameters.

**Ambiguities addressed** The system description notes that some elements may be incomplete or insufficiently detailed. The assumptions above were chosen to resolve the following ambiguities:

* **Infrastructure and WAF:** we assumed infrastructure is AWS and that a WAF is deployed in front of all requests to the API Gateway so that recommendations are concrete and common attacks (e.g. DDoS) are mitigated.  
* **Payment flow and CHD:** The exact payment flow (where card data enters the system) was not fully specified. We assumed the design delegates payment collection to the provider (hosted page or hosted fields) so that CHD never transits or touches the game platform—this keeps PCI scope minimal and is reflected in the diagram interpretation (tokenized references only on Gateway/Payment flows).  
* **Token and identity model:** The system description does not detail how tokens are issued, signed, or validated. We assumed Auth issues and signs tokens (e.g. JWT with RS256/ES256), and that the API Gateway and each service verify signature and claims (e.g. `aud`, `sub`) before trusting identity—so that spoofing and privilege-escalation threats are well-defined.  
* **Persistence and secrets in the diagram:** The diagram shows a single Persistence & Logging component and limited Secrets flows. We assumed this represents all backend persistence and that other components’ use of persistence or secrets is implicit and out of scope for this threat model.

# Identified Threats

Threats below arise from **design choices** and **inherent risks** of the three in-scope components. They are mapped using STRIDE and include CWE references, impact/cost estimates, OWASP Cornucopia cards, and verification guidance.

## 1. API Gateway

### Threat 1.1 – Tokens stolen; Gateway accepts attacker as victim

**Description.** Tokens stolen; Gateway accepts requests from the attacker as the victim, allowing the attacker to act as any player (e.g. access game or make in-game purchases).

**Related CWE.** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-384 (Session Fixation)

**Expected impact.** Impacted assets: player sessions, in-game currency, payment methods. Affected population: any player whose token is stolen. Industry benchmark: account takeover and fraud in F2P games can cause $10K–$500K+ per incident depending on scale; regulatory fines (e.g. COPPA, GDPR-K) add risk.

**Cost to fix.** Medium–High. Requires token design changes (short TTL, binding, scoped aud), refresh flow, and possibly revocation infrastructure.

**Suggested mitigations (ordered by cost of fixing):**
1. Short TTL and scope tokens per service/sensitivity (Low–Medium).
2. Revoke on logout; support token revocation list (Medium).
3. Binding to device/fingerprint for high-sensitivity tokens (High).

**OWASP Cornucopia cards:**
- SM3 (Session Management) – Stolen session used for maximum duration. https://cornucopia.owasp.org/cards/SM3
- SM9 (Session Management) – Session identifiers/tokens stolen via insecure channels or logging. https://cornucopia.owasp.org/cards/SM9
- SMJ (Session Management) – Reuse of stolen session identifiers without proof of possession. https://cornucopia.owasp.org/cards/SMJ

**Verification.** Pentesting: attempt to reuse stolen token across contexts. DAST: verify token expiry and binding. Design review: token lifecycle and revocation.

### Threat 1.2 – Auth bypassed; Gateway accepts forged token

**Description.** Auth bypassed; Gateway accepts forged or invalid token, allowing access to game or payment APIs as another player.

**Related CWE.** CWE-285 (Improper Authorization), CWE-345 (Insufficient Verification of Data Authenticity)

**Expected impact.** Impacted assets: game state, payment flows, PII. Full impersonation enables unauthorized purchases and data access. Benchmark: similar to 1.1; high reputational and regulatory risk.

**Cost to fix.** Medium. Requires signature validation, JWKS/key distribution, and consistent validation across services.

**Suggested mitigations (ordered by cost of fixing):**
1. Auth signs tokens with RS256/ES256; Gateway validates signature and `aud` on every request (Low–Medium).
2. Reject unsigned or invalid tokens; no fallback to unauthenticated access (Low).

**OWASP Cornucopia cards:**
- AT8 (Authentication) – Authentication bypass; fails to deny by default. https://cornucopia.owasp.org/cards/AT8
- ATJ (Authentication) – No authentication requirement or missing auth. https://cornucopia.owasp.org/cards/ATJ
- ATX (Authentication) – Bypass due to non-standard or misconfigured auth module. https://cornucopia.owasp.org/cards/ATX

**Verification.** Pentesting: submit forged or altered tokens. DAST: test endpoints without valid token. SAST: check for signature validation before trusting claims.

### Threat 1.3 – Overly verbose logging leaks PII

**Description.** Overly verbose logging leaks player PII or payment-related data to log sinks (e.g. credentials or purchase details).

**Related CWE.** CWE-200 (Exposure of Sensitive Information), CWE-201 (Insertion of Sensitive Information Into Sent Data)

**Expected impact.** Impacted assets: player PII, payment references. Log sinks become targets; exposure can affect all players whose data is logged. Benchmark: data exposure fines (GDPR up to 4% revenue; COPPA); reputational damage. Estimated range $50K–$2M+ depending on scale and jurisdiction.

**Cost to fix.** Low–Medium. Logging policy and code changes; log pipeline filtering.

**Suggested mitigations (ordered by cost of fixing):**
1. Do not log request/response bodies for auth or payment (Low).
2. Restrict log access; redact PII in existing logs (Low–Medium).

**OWASP Cornucopia cards:**
- VE2 (Data Validation & Encoding) – Information disclosure via error messages or configuration. https://cornucopia.owasp.org/cards/VE2
- AZ3 (Authorization) – Access to sensitive info via logger, cache, or reporting. https://cornucopia.owasp.org/cards/AZ3

**Verification.** SAST: detect logging of sensitive data. Manual/code review: audit logging statements. Pentesting: check log outputs for PII.

### Threat 1.4 – Gateway DoS; platform-wide outage

**Description.** Gateway is a single point of entry; rate limiting bypass or exhaustion causes platform-wide outage. Players cannot log in, play or perform transactions.

**Related CWE.** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption)

**Expected impact.** Impacted assets: entire platform availability. All players unable to log in or play. Benchmark: F2P games lose revenue during outages; estimated $5K–$50K+ per hour depending on scale; churn and trust impact.

**Cost to fix.** Medium. Rate limiting, circuit breakers, scaling, and staging for Gateway changes.

**Suggested mitigations (ordered by cost of fixing):**
1. Rate limiting per identity and per IP (Low–Medium).
2. WAF + Gateway quotas; circuit-break backends (Medium).
3. Configure a dedicated staging for config/code changes (Medium–High).

**OWASP Cornucopia cards:**
- C9 (Cornucopia) – Misuse by using a feature too fast or too frequently; resource consumption. https://cornucopia.owasp.org/cards/C9
- CK (Cornucopia) – Denial of service to users. https://cornucopia.owasp.org/cards/CK

**Verification.** Load testing: verify rate limits and circuit breakers. Config review: quotas and scaling. Pentesting: attempt rate-limit bypass.

## 2. Auth Service

### Threat 2.1 – Account takeover

**Description.** Account takeover via credential stuffing, phishing, or session token theft; attacker gains access to player's city, in-game currency, and payment methods (e.g. play as victim, make in-game purchases on their behalf).

**Related CWE.** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-200 (Exposure of Sensitive Information), CWE-613 (Insufficient Session Expiration)

**Expected impact.** Impacted assets: player accounts, cities, in-game currency, payment methods. Affected population: breached-credential users or players whose sessions are stolen. Benchmark: ATO in games drives fraud and chargebacks; industry reports cite $10K–$500K+ per incident.

**Cost to fix.** Medium–High. MFA, breach-list checks, password policy, session binding, TTL, and monitoring.

**Suggested mitigations (ordered by cost of fixing):**
1. Rate limit login attempts per IP and account (Low).
2. Strong password policy and breach-list checks (Low–Medium).
3. Short session TTL and refresh flow (Low–Medium).
4. MFA for sensitive and high-risk actions (Medium).
5. Bind sessions to device/fingerprint; rotate on privilege change (Medium–High).

**OWASP Cornucopia cards:**
- AT2 (Authentication) – Auth functions without user awareness (e.g. stolen credentials). https://cornucopia.owasp.org/cards/AT2
- AT3 (Authentication) – Obtaining password/secrets by observation, cache, transit, or leak. https://cornucopia.owasp.org/cards/AT3
- AT7 (Authentication) – Brute force/dictionary attacks without limit. https://cornucopia.owasp.org/cards/AT7
- SM3 (Session Management) – Stolen session used for maximum duration. https://cornucopia.owasp.org/cards/SM3
- SM9 (Session Management) – Stealing tokens via insecure channels or logging. https://cornucopia.owasp.org/cards/SM9

**Verification.** DAST: test for brute-force, credential stuffing, and session handling. Pentesting: validate MFA, rate limiting, and session hijacking. Design review: session lifecycle. Monitoring: detect anomalous login patterns.

### Threat 2.2 – Age flag tampered; child protections bypassed

**Description.** Age flag tampered to bypass child protections; minors exposed to age-inappropriate features or data collection in the game.

**Related CWE.** CWE-345 (Insufficient Verification of Data Authenticity), CWE-20 (Improper Input Validation)

**Expected impact.** Impacted assets: minor player data, consent flags. Regulatory: COPPA, GDPR-K fines; reputational damage. Benchmark: regulatory fines $10K–$50M+ depending on jurisdiction and severity.

**Cost to fix.** Medium. Integrity checks, server-side enforcement, signed attributes.

**Suggested mitigations (ordered by cost of fixing):**
1. Store age flag in Auth; enforce at service level (Medium).
2. Integrity-check or sign age/attributes (Medium).

**OWASP Cornucopia cards:**
- VE4 (Data Validation & Encoding) – Malicious field names or data not checked in user/process context. https://cornucopia.owasp.org/cards/VE4
- AZ8 (Authorization) – Bypass business rules by altering process or control data. https://cornucopia.owasp.org/cards/AZ8

**Verification.** Pentesting: attempt to tamper age flag. SAST/DAST: validate server-side enforcement. Compliance review: COPPA/GDPR-K controls.

### Threat 2.3 – Auth endpoint exhausted; login floods

**Description.** Auth endpoint exhausted (e.g. login floods); players cannot log in and game/marketplace become unreachable.

**Related CWE.** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption)

**Expected impact.** All players unable to authenticate; cascade failure to dependent services. Benchmark: similar to Gateway DoS; $5K–$50K+ per hour plus churn.

**Cost to fix.** Medium. Rate limiting, CAPTCHA, circuit breakers, scaling.

**Suggested mitigations (ordered by cost of fixing):**
1. Rate limit login/register/reset per IP and per account (Low–Medium).
2. CAPTCHA or similar for unauthenticated auth endpoints (Low–Medium).
3. Circuit-breaker, health checks; scale Auth independently (Medium).

**OWASP Cornucopia cards:**
- AT7 (Authentication) – Brute force/dictionary attacks without limit. https://cornucopia.owasp.org/cards/AT7
- C9 (Cornucopia) – Misuse by over-utilizing a feature; resource consumption. https://cornucopia.owasp.org/cards/C9

**Verification.** Load testing: login flood scenarios. Config review: rate limits and CAPTCHA. Pentesting: attempt to exhaust auth endpoints.

## 3. External Payment Service

### Threat 3.1 – Payment initiated as another user

**Description.** Payment initiated as another user; in-game purchase or subscription charged to victim player's payment method because request is not strongly bound to authenticated identity.

**Related CWE.** CWE-285 (Improper Authorization), CWE-862 (Missing Authorization)

**Expected impact.** Impacted assets: player payment methods, revenue. Direct financial loss; chargebacks; regulatory risk. Benchmark: unauthorized purchase and chargeback costs $10K–$500K+ per incident; PCI and consumer protection implications.

**Cost to fix.** Medium–High. Design change: bind payment flow to verified identity from Auth; reject mismatched requests.

**Suggested mitigations (ordered by cost of fixing):**
1. Gateway/Auth pass stable, verified user ID to payment flow (Medium).
2. Payment/orchestrator reject requests not matching authenticated user; never trust client-supplied identity (Medium).

**OWASP Cornucopia cards:**
- AZ5 (Authorization) – Access to resources due to missing auth or excessive privileges. https://cornucopia.owasp.org/cards/AZ5
- AZ6 (Authorization) – Access to data without permission despite access to form/page/URL. https://cornucopia.owasp.org/cards/AZ6
- SMJ (Session Management) – Reuse of stolen tokens; no proof of possession. https://cornucopia.owasp.org/cards/SMJ

**Verification.** Pentesting: attempt payment with altered user ID. DAST: test payment endpoints for identity binding. Design review: payment flow and identity propagation.

### Threat 3.2 – Payment API unavailable

**Description.** Payment API unavailable so players cannot complete in-game purchases (currency, cosmetics, upgrades); revenue and trust impact.

**Related CWE.** CWE-400 (Uncontrolled Resource Consumption), CWE-754 (Improper Check for Unusual or Exceptional Conditions)

**Expected impact.** Revenue loss during outage; player churn; trust impact. Benchmark: $5K–$50K+ per hour depending on scale; cumulative impact on LTV.

**Cost to fix.** Medium. Retries, backoff, idempotency, monitoring, graceful degradation.

**Suggested mitigations (ordered by cost of fixing):**
1. Retries with backoff and idempotency (Low–Medium).
2. Provider SLA and status page monitoring (Low).
3. Graceful degradation (e.g. "payments temporarily unavailable") (Medium).

**OWASP Cornucopia cards:**
- C9 (Cornucopia) – Resource consumption; feature over-utilization. https://cornucopia.owasp.org/cards/C9
- CK (Cornucopia) – Denial of service to users. https://cornucopia.owasp.org/cards/CK

**Verification.** Chaos/resilience testing: simulate payment provider failure. Monitoring: success rate and latency. Config review: retry and backoff settings.

### Threat 3.3 – Unauthorized refund or subscription change

**Description.** Unauthorized refund or subscription change; Payment API called without proper authorization (e.g. attacker triggers refund for in-game purchases).

**Related CWE.** CWE-285 (Improper Authorization), CWE-863 (Incorrect Authorization)

**Expected impact.** Direct financial loss; chargebacks; revenue and trust impact. Benchmark: fraudulent refunds and subscription abuse $10K–$500K+ depending on scale.

**Cost to fix.** Medium. Server-side initiation; RBAC; audit trail for refunds.

**Suggested mitigations (ordered by cost of fixing):**
1. All payment and refund calls initiated server-side; tied to authenticated operator or user (Medium).
2. Enforce "refund only for same user or support with audit"; RBAC for admin refunds (Medium).
3. No client-side direct Payment API keys (Low).

**OWASP Cornucopia cards:**
- AZ5 (Authorization) – Access to resources due to missing auth. https://cornucopia.owasp.org/cards/AZ5
- AZ7 (Authorization) – Access to functions/objects without permission. https://cornucopia.owasp.org/cards/AZ7
- AZ8 (Authorization) – Bypass business rules by altering process flow. https://cornucopia.owasp.org/cards/AZ8

**Verification.** Pentesting: attempt unauthorized refund. DAST: test refund endpoints for authz. Design review: refund flow and RBAC.

# Summary and priorities

| Severity | Count | Focus for engineering |
| :---- | :---- | :---- |
| Critical | 4 | Gateway DoS (1.4); Account takeover (2.1); Auth endpoint exhausted (2.3); Payment initiated as another user (3.1) |
| High | 6 | Gateway: token theft (1.1), Auth bypass (1.2), verbose logging/PII (1.3). Auth: age flag tampered (2.2). Payment: API unavailable (3.2), unauthorized refund (3.3) |

**TOP PRIORITY (squad actions):**

1. **Payment–identity binding:** Ensure every payment and refund is tied to a verified identity from Auth; reject any payment request not matching the authenticated user.  
2. **Auth MFA and session design:** Enforce MFA for high-risk and payment-related actions; short-lived, binding sessions; no sensitive data in logs.  
3. **Gateway rate limiting and DoS:** Enforce per-identity and per-IP limits; staging environment for Gateway updates; ensure backends are not directly reachable.  
4. **PII and minors (Auth):** Minimize and protect underage and PII in Auth stores and logs; enforce COPPA/GDPR-K and access control.

# Conclusion

This threat modeling exercise demonstrates the value of identifying design-level risks **early**, before they become costly to fix in production.

**Early identification.** The 10 retained threats may require design or architectural changes; addressing them during design is significantly cheaper than after deployment. Threats such as payment–identity binding and token design (short TTL, scoped audiences) are easier to implement correctly from the start.

**Cost comparison.** Fixing design flaws in production typically involves rework, coordination across teams, migration of existing data or sessions, and potential customer impact. The relative fix costs (Low/Medium/High) in this report reflect this: Low and Medium mitigations are often config or incremental code changes; High typically implies design changes affecting multiple services.

**Business alignment.** The threats map directly to the hackathon priorities: Financial Loss (payment binding, refund auth, ATO), Denial of Service (Gateway and Auth exhaustion, payment availability), and Safe Environment (age flag integrity, PII protection). Addressing these supports revenue protection, platform availability, and regulatory compliance (COPPA, GDPR-K).

**Use as input.** The verification methods (SAST, DAST, SCA, pentesting, design review, load testing) identified per threat can be used to scope security testing. Use this report to define pentest scope, SAST/DAST rules, and config review checklists for the API Gateway, Auth Service, and Payment integrations.

# Annex A
