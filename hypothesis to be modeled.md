# Hypothesis to Be Modeled

Items to investigate or explicitly model during threat modeling. These are open design/architecture questions or areas that should be represented in the threat model.

---

## 1. Payment orchestration

**Finding:** Clarify how payment is orchestrated.

The system description mentions both a **Marketplace** (order creation, entitlements) and an **External Payment Service** (gateway, subscriptions, refunds). The current diagram shows payment data going **API Gateway → 3rd Party Payment** directly.

**To be investigated during threat modeling:**

- Whether an internal service (e.g. Marketplace or a dedicated payment service) sits between API Gateway and the external payment provider (API Gateway → internal service → 3rd Party Payment).
- Or whether the design is “API Gateway calls the payment provider directly” (no internal payment orchestration in scope).
- Impact on threats: who handles order context, refunds, and PCI scope; where card data is processed and stored.

**Action:** Resolve the payment flow (internal orchestration vs. direct Gateway–provider) and document the chosen design; model threats accordingly.

---

## 2. WebSockets via API Gateway (game and real-time traffic)

**Recommendation:** Model real-time traffic entry via API Gateway.

The system description states that real-time game and chat use “persistent secure channels” to Game/Chat services. Real-time traffic entry should be explicit in the threat model.

**To be modeled:**

- **WebSockets via API Gateway:** Assume (or confirm) that WebSocket/long-lived connections go through the same API Gateway (e.g. API Gateway WebSocket API) to Game Server and Chat.
- Add or validate dataflows: **API Gateway → Game Server Cluster** and **API Gateway → Chat Service** for real-time traffic.
- Threat model: authentication/authorization of WebSocket connections, rate limiting and abuse of long-lived connections, integrity and confidentiality of real-time channels, and DoS via connection exhaustion.

**Action:** Represent WebSocket/real-time entry (e.g. via API Gateway) in the diagram and include related threats and mitigations in the threat model.
