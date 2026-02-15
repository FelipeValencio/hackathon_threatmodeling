# Interpretation of Hackathon-team42.xml (IriusRisk Diagram)

This document interprets the threat model diagram exported from IriusRisk (`Hackathon-team42.xml`) for the TMC Global Threat Modeling Hackathon 2026 city-building game.

---

## 1. Project & format

- **Project:** Hackathon-team42  
- **Format:** IriusRisk project export (XML)  
- **Tags:** ThreatModelingHackathon2026  
- **Model updated:** 2026-02-14  
- **Workflow state:** Draft  

The file defines a **diagram** (layout), **trust zones**, **assets**, **components**, **dataflows**, and for each component: weaknesses (CWE), countermeasures, and STRIDE-style threats (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege).

---

## 2. Trust zones

| Trust zone       | Trust rating | Description                    | Typical use in diagram      |
|------------------|-------------|--------------------------------|-----------------------------|
| **Internet**     | 1           | Untrusted public zone          | User-facing client (Browser) |
| **Trusted Partner** | 30      | Vetted and trusted partner     | 3rd Party Payment Service   |
| **AWS**          | 60          | (No description)                | Edge / gateway (WAF, API Gateway) |
| **Private Subnet** | 80        | (No description)                 | All backend ECS/Lambda/Secrets |

Trust increases from Internet (1) to Private Subnet (80). The only component in **Trusted Partner** is the external payment provider; the only one explicitly in **AWS** (from the component list) is **AWS API Gateway**. **AWS WAF** is also in the AWS edge. All other services (Auth, Chat, Game Server, Marketplace, Moderation, Persistence, Upload/Media, User Profile, Background workers, Secrets manager) sit in **Private Subnet**.

---

## 3. Assets (sensitive data)

| Asset                          | Description / classification |
|--------------------------------|------------------------------|
| **Credit Card Data**           | Cardholder data (PAN, CVV); PCI-relevant; high confidentiality & integrity (100), lower availability (30). |
| **Customer Data**              | Data that uniquely identifies customers; PII-like; confidentiality/integrity 80, availability 20. |
| **Personally Identifiable Information** | Standard PII definition (identifiable natural person); confidentiality/integrity 80, availability 20. |

These three assets are used to tag **dataflows** and **components** so the model knows where sensitive data moves and is stored/processed.

---

## 4. Components (14 total)

| # | Component name                         | Trust zone     | Type (conceptual)     |
|---|----------------------------------------|----------------|------------------------|
| 1 | **Browser**                            | Internet       | Client (SPA)          |
| 2 | **AWS WAF**                            | AWS            | Web Application Firewall |
| 3 | **AWS API Gateway**                    | AWS            | API Gateway            |
| 4 | **3rd Party Payment Service**          | Trusted Partner| External payment API   |
| 5 | **AWS ECS - Auth Service (Identity)** | Private Subnet | Identity / auth        |
| 6 | **AWS ECS - User Profile Service + Storage** | Private Subnet | User metadata, profiles |
| 7 | **AWS ECS - Chat Service**            | Private Subnet | Real-time chat         |
| 8 | **AWS ECS - Game Server Cluster**      | Private Subnet | Authoritative game state |
| 9 | **AWS ECS - Marketplace**              | Private Subnet | Catalog, orders, entitlements |
|10 | **AWS ECS - Upload and Media Service** | Private Subnet | Uploads, moderation, storage |
|11 | **AWS ECS - Moderation and Admin Tools** | Private Subnet | Flags, bans, content approval |
|12 | **AWS ECS - Persistence and Logging**  | Private Subnet | DBs, audit logs, SIEM |
|13 | **AWS Lambda - Background workers**    | Private Subnet | Async jobs (e.g. email, ML, payments) |
|14 | **AWS Secrets manager**                | Private Subnet | Secrets, RBAC          |

All ECS/Lambda/Secrets components are in **Private Subnet**; only Browser, WAF, API Gateway, and the external payment service are in other zones.

---

## 5. Dataflows (16 flows)

Dataflows define **direction** of data and, where specified, **which assets** travel on them.

### 5.1 User-to-edge (sensitive assets)

| From       | To           | Assets on flow                    |
|------------|--------------|------------------------------------|
| Browser    | AWS WAF      | Credit Card Data, Customer Data, PII |
| AWS WAF    | AWS API Gateway | Credit Card Data, Customer Data, PII |

So the diagram models **Credit Card, Customer Data, and PII** as flowing from the client through WAF to the API Gateway. This matches login, profile, and payment-related requests.

### 5.2 API Gateway to backend services

| From            | To                              | Assets      |
|-----------------|----------------------------------|-------------|
| AWS API Gateway | AWS ECS - Auth Service (Identity) | Customer Data, PII |
| AWS API Gateway | AWS ECS - User Profile Service + Storage | (none listed) |
| AWS API Gateway | AWS ECS - Chat Service          | (none listed) |
| AWS API Gateway | 3rd Party Payment Service       | Credit Card Data, Customer Data, PII |

So:
- **Auth** receives credentials/identity data (Customer Data, PII).
- **User Profile** and **Chat** are reached via API Gateway but no assets are explicitly tagged on those flows (could be refined).
- **Payment** receives the same sensitive set as the client→WAF→Gateway path (card + customer + PII).

There are **no** dataflows in the file from API Gateway to: Game Server Cluster, Marketplace, or Upload and Media Service. So in this diagram, game state, marketplace, and uploads are reached indirectly (e.g. via other services or different channels like WebSocket), not as direct API Gateway→service flows.

### 5.3 Backend-to-backend (no assets tagged)

| From                    | To                                |
|-------------------------|------------------------------------|
| AWS ECS - User Profile Service + Storage | AWS ECS - Game Server Cluster |
| AWS ECS - Upload and Media Service      | AWS ECS - Game Server Cluster |
| AWS ECS - Game Server Cluster          | AWS ECS - Marketplace |
| AWS ECS - Game Server Cluster          | AWS ECS - Chat Service |
| AWS ECS - Game Server Cluster          | AWS ECS - Moderation and Admin Tools |
| AWS ECS - Game Server Cluster          | AWS ECS - Persistence and Logging |
| AWS ECS - Marketplace                  | AWS Secrets manager |
| AWS ECS - Chat Service                 | AWS Secrets manager |
| AWS ECS - Persistence and Logging      | AWS Lambda - Background workers |
| AWS ECS - Moderation and Admin Tools   | AWS Lambda - Background workers |

Interpretation:
- **Game Server Cluster** is a hub: it receives data from User Profile and Upload/Media; it sends data to Marketplace, Chat, Moderation, and Persistence & Logging.
- **Secrets manager** is used by Marketplace and Chat (e.g. API keys, tokens).
- **Background workers** are fed from Persistence & Logging and from Moderation (e.g. async tasks, batch jobs).

---

## 6. High-level architecture (as shown in the diagram)

```
[ Internet ]
    Browser
       |
       | Credit Card, Customer Data, PII
       v
[ AWS ]
    AWS WAF  -->  AWS API Gateway
                       |
       +---------------+---------------+------------------+
       |               |               |                  |
       v               v               v                  v
   Auth Service   User Profile     Chat Service    3rd Party Payment
   (Customer,     (no assets       (no assets     (Credit Card,
    PII)           on flow)         on flow)       Customer, PII)
       |               |               |                  ^
       |               v               ^                  |
       |         Game Server Cluster --+                  |
       |               |                                 |
       |         +-----+-----+--------+--------+          |
       v         v     v     v        v        v          |
   (implied     Marketplace  Chat  Moderation  Persistence & Logging
    use by          |         |        |              |
    other           v         v        v              v
    services)   Secrets   Secrets   Background workers (Lambda)
               manager   manager
```

- **Single entry path for user traffic:** Browser → WAF → API Gateway → various backends (Auth, Profile, Chat, Payment).  
- **Game Server** is not directly connected to the API Gateway in this diagram; it gets data from User Profile and Upload/Media and talks to Marketplace, Chat, Moderation, and Persistence.  
- **Payment** is the only component in Trusted Partner; payment data flows from Gateway to 3rd Party Payment Service.  
- **Secrets** are used by Marketplace and Chat; **Background workers** are triggered from Persistence & Logging and Moderation.

---

## 7. Alignment with your report scope

Your **report.md** focuses on:

- **API Gateway** – DoS, availability, rate-limiting.  
- **Auth Service** – Impersonation, ATO, identity/session, age flagging, Safe Environment.  
- **External Payment Service** – Unauthorized purchases, secure processing, account protection.

In the diagram:

- **API Gateway** is in the **AWS** trust zone, with flows from WAF (incoming) and to Auth, User Profile, Chat, and 3rd Party Payment. So all user-facing API traffic (including auth and payment) passes through it—good for analyzing DoS and availability.  
- **Auth Service** is in **Private Subnet**, receives Customer Data and PII from API Gateway, and has no direct flow to Payment in the diagram (identity is likely passed via API Gateway or tokens when calling Payment).  
- **3rd Party Payment Service** is in **Trusted Partner**, and the only flow to it is **API Gateway → 3rd Party Payment** with Credit Card Data, Customer Data, and PII. So the diagram explicitly models payment and PII flow for your Payment Service analysis.

**Gaps or assumptions you might state:**

- No explicit flow **API Gateway → Game Server / Marketplace / Upload**; real-time or game-specific traffic may be modeled as a different path (e.g. WebSocket) or omitted.  
- Asset tagging is only on the Browser→WAF→Gateway→Auth and →Payment paths; Chat and User Profile flows could be refined with PII/Customer Data if relevant for your scope.  
- WAF is in front of API Gateway (matches your report assumption: “WAF is deployed in front of all requests to the API gateway”).

---

## 8. Threat model content in the XML

The file contains, per component:

- **Weaknesses:** CWE items (e.g. CWE-20, CWE-201, CWE-285, CWE-311, CWE-319, CWE-345, CWE-770 on 3rd Party Payment Service).  
- **Countermeasures:** From rule libraries (e.g. “Use HTTPS”, “Encrypt sensitive data before transmitting”, “Implement user authentication”, “Validate and sanitize data received from API”) with states like Implemented / N/A.  
- **STRIDE use cases:** e.g. Tampering, Spoofing, Information Disclosure, Denial of Service, with specific threat names (e.g. “Attackers manipulate the data obtained from the Third Party API Service”, “Attackers exhaust API Service resources”).  

So the diagram is not only topology and assets, but a full IriusRisk threat model with threats and mitigations that you can reference or export for your report (e.g. for API Gateway, Auth, and Payment).

---

## 9. Summary

- **14 components** in 4 **trust zones** (Internet, Trusted Partner, AWS, Private Subnet).  
- **3 assets** (Credit Card Data, Customer Data, PII) flow **Browser → WAF → API Gateway**, then to **Auth** (Customer, PII) and **3rd Party Payment** (all three).  
- **Backend** is centered on **Game Server Cluster** (fed by User Profile and Upload/Media; talks to Marketplace, Chat, Moderation, Persistence); **Secrets** and **Background workers** are used as in the system description.  
- The diagram **aligns with your report scope** (API Gateway, Auth, Payment) and your **WAF assumption**; you can cite it as the in-scope architecture and reference the embedded threats/countermeasures for those three components.

If you want, the next step can be to extract concrete **threat titles and mitigations** from the XML for **API Gateway**, **Auth Service**, and **3rd Party Payment Service** and drop them into your report’s threat list and mitigations.
