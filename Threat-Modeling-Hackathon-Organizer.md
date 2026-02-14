# Threat Modeling Hackathon – Focus & Notes Organizer

Use this as a checklist and note-taking guide while you work on the city-building game threat model.

---

## 1. Scope: What to Focus On

### Rule from the hackathon
- **Pick 2–3 specific areas** from the system design (not the whole system).
- **State clearly** what is in scope and what is out of scope.
- If an area depends on another component, **note the dependency** but do **not** expand scope unless you explicitly choose that component.

### System components you can choose from (pick 2–3)

| Component | Good fit for priorities |
|-----------|-------------------------|
| **Auth Service** | Safe Environment, Financial Loss (account takeover) |
| **User Profile Service + Storage** | Safe Environment (child data, privacy), Financial Loss |
| **Upload & Media Service** | Safe Environment (content moderation, malware, abuse) |
| **Chat Service** | Safe Environment (harassment, grooming, parental controls) |
| **Game Server Cluster** | DoS, integrity, Financial Loss (virtual assets) |
| **Marketplace** | Financial Loss (fraud, scams, entitlements) |
| **Payment Service (External)** | Financial Loss (chargebacks, refunds, secure processing) |
| **Moderation & Admin Tools** | Safe Environment (reporting, bans, audit) |
| **API Gateway** | DoS (rate-limiting), Auth delegation |
| **Persistence & Logging** | Audit, compliance, data exposure |
| **CDN & Asset Hosting** | Access control, exclusive content, availability |
| **Secrets Vault** | Cross-cutting (secrets, RBAC) |

**Suggestions:**
- **Safe Environment:** Chat Service + Upload & Media Service (or Moderation & Admin Tools).
- **Financial Loss:** Marketplace + Payment Service (or Auth for account takeover).
- **DoS:** API Gateway + Game Server Cluster (or Chat).

---

## 2. Threat Modeling Priorities (from the brief)

Keep these in mind when identifying and ranking threats:

| Priority | What to look for |
|----------|-------------------|
| **1. Safe Environment** | Harassment, grooming, inappropriate content, unsafe interactions; moderation/reporting; **child data** (COPPA, GDPR-K); unauthorized data collection/profiling/exposure. |
| **2. Financial Loss** | **Provider:** fraud, chargebacks, account takeover, virtual asset theft, IP/revenue. **Participants:** scams, phishing, unauthorized purchases; secure payments and account protection. |
| **3. Denial of Service** | DDoS, resource exhaustion, resilience, availability, monitoring and mitigation. |
| **+1 Additional** | One other legitimate concern (e.g. integrity of game state, mod security, supply-chain, compliance). |

---

## 3. What to Keep Notes On During Modeling

### A. Assumptions (required)
- **Document every assumption** when information is missing or unclear.
- Add a dedicated section or appendix: “Assumptions” and list them explicitly so reviewers understand context.

### B. Scope boundaries
- **In scope:** Which 2–3 components and which data flows.
- **Out of scope:** What you are not analyzing (and why, if brief).
- **Dependencies:** Components you depend on but did not expand into (e.g. “Auth is out of scope but we assume valid tokens from Auth Service”).

### C. Threats
- **Per threat:** description, affected component/flow, priority (Safe Environment / Financial / DoS / Other), and severity or impact if you use them.
- **Keep the list concise:** quality over quantity; only genuine threats.

### D. Mitigations & recommendations
- **Mitigations** per threat (existing or proposed).
- **Priorities:** which threats to fix first and why.
- **Actionable wording:** written for a developer team (clear, implementable).

### E. Practical process
- **Timebox** each of your 2–3 focus areas.
- **Balance:** at least one high-impact area + one that is technically or creatively interesting.
- **Follow-up:** short rationale for prioritization and next steps.

---

## 4. Quick Checklist Before Submission

- [ ] Exactly **2–3** focus areas chosen from the system design.
- [ ] **In scope / out of scope** clearly stated.
- [ ] **Assumptions** documented (in main text or appendix).
- [ ] Threats aligned with **Safe Environment / Financial Loss / DoS** (and optionally +1).
- [ ] Threat list **concise** (quality over quantity).
- [ ] **Recommendations / mitigations** and **priorities** included.
- [ ] Written to be **actionable** for developers.
- [ ] Diagram link (e.g. IriusRisk) included if required.

---

## 5. One-Page Note Template (copy per focus area)

Use one block per focus area (e.g. Chat Service, Marketplace).

```
FOCUS AREA: ___________________________
In scope: _______________________________
Out of scope: ___________________________
Dependencies (not in scope): ____________

ASSUMPTIONS:
• 
• 

THREATS (brief):
1. [Threat] – Priority: [Safe / Financial / DoS / Other] – Mitigation: 
2. 
3. 

TOP PRIORITY: 
NEXT STEPS: 
```

---

*Based on: Team42 - TMC Global Threat Modeling Hackathon 2026 – System Description.*
