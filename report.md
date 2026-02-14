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

THREATS (brief):
1. [Threat] – Priority: [Safe / Financial / DoS / Other] – Mitigation: 
2. 
3. 

TOP PRIORITY: 
NEXT STEPS: 