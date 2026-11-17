# MediLink Health Threat and Risk Register

## Scope and scoring

This initial register covers the six hospitals, 14 diagnostic laboratories,
patient portal/mobile service, cloud patient database, 2,500 staff, medical
IoT, MSP access, and payment-provider connection described in the project
brief. The dark-web claim is unverified; it is treated as a possible exposure
signal, not as proof of a breach.

Likelihood and impact are scored from 1 (rare/minor) to 5 (almost certain/
catastrophic). Risk score is likelihood multiplied by impact:

| Score | Rating |
|---:|---|
| 1–4 | Low |
| 5–9 | Moderate |
| 10–15 | High |
| 16–25 | Critical |

CIA columns identify the principal confidentiality, integrity, and availability
consequences. Initial scores are inherent estimates and must be recalibrated
after asset discovery, control testing, and clinical/business impact analysis.

## Register

| ID | Threat actor / event and attack path | L | I | Score | CIA | Evidence / rationale | Priority treatment | Owner |
|---|---|---:|---:|---:|---|---|---|---|
| R1 | Phishing crew steals staff credentials through email, then accesses patient or administrative services | 4 | 5 | 20 Critical | C, I, A | Phishing campaign observed; 2,500 staff rely on email and shared workstations | Phishing-resistant MFA, email protection, endpoint detection, rapid session revocation, and role-based access; track reporting and simulation rates | Security + IT |
| R2 | Criminal or opportunistic actor exploits appointment-module input handling to read or alter records | 4 | 5 | 20 Critical | C, I | Suspicious SQL errors observed; patient records have high sensitivity | Triage the errors, parameterize every query, validate input, run an authorized code review, and use a restricted DB account | Application + DBA |
| R3 | DDoS actor overwhelms the public patient portal or API | 3 | 4 | 12 High | A | Short DDoS attack observed; service supports a large patient population | Upstream DDoS protection, WAF/API limits, tested failover, capacity monitoring, and patient communications | Cloud + Network |
| R4 | Ransomware group compromises a workstation or MSP path, steals records, and encrypts systems | 4 | 5 | 20 Critical | C, I, A | Phishing activity and an unconfirmed sale claim increase urgency; clinical continuity is safety-critical | EDR, network containment, JIT privileged access, immutable isolated backups, restore exercises, and evidence-preservation procedures | Security + IT + Clinical |
| R5 | Cloud credential, security-group, or database configuration error exposes the central records store | 3 | 5 | 15 High | C, I, A | Central cloud database is a high-impact concentration point | Private networking, least privilege, managed encryption, key separation, database auditing, configuration monitoring, and tested recovery | Cloud + DBA |
| R6 | MSP account, remote-management tool, or software supply chain is compromised | 3 | 5 | 15 High | C, I, A | MSP has remote administrative access; SolarWinds and Kaseya are relevant precedents | Per-person JIT access, MFA, approved jump host, scoped session recording, signed-update validation, and independent log storage | Vendor Manager + Security |
| R7 | Legacy or vulnerable medical IoT device is compromised and used to disrupt care or move laterally | 3 | 5 | 15 High | I, A, C | ICU monitors and infusion pumps are on hospital LAN; patching may be constrained | Dedicated clinical/IoT zones, default-deny allowlists, passive monitoring, no direct internet, clinical change approval, and tested safe isolation | Biomedical + Network |
| R8 | Payment integration or provider account is abused to expose payment data or falsify transaction status | 3 | 4 | 12 High | C, I | Online payments are in scope; current project workflow is explicitly simulated | Use provider-hosted/tokenized payment flows, signed webhook verification, reconciliation, and separation of payment data from clinical records | Finance + Application |
| R9 | Ransomware or operator error destroys both production data and recovery material, or backup integrity cannot be established | 3 | 5 | 15 High | I, A | Existing lab report records a blocked recovery when the integrity baseline was unavailable | Cross-account/object-lock backups, separate credentials, independent integrity manifests, restore tests, and approved RTO/RPO | Backup Owner + DBA |
| R10 | Insider or shared-workstation session misuse exposes or alters records | 3 | 4 | 12 High | C, I | 2,500 staff and shared workstations increase attribution and session-control risk | Individual accounts, short idle lock, step-up for sensitive actions, audit review, and safe emergency access | HR + IT + Clinical |

## Immediate validation actions

1. Establish an authoritative asset and data-flow inventory, including each
   hospital, lab, cloud account, device class, MSP connection, and payment
   boundary.
2. Preserve and correlate the appointment SQL-error logs, portal DDoS telemetry,
   authentication events, and the dark-web claim. Do not treat the claim as
   confirmed until evidence is assessed.
3. Assign accountable owners, approved residual-risk decisions, and target dates
   to the treatments above. Re-score after controls are tested.
4. Have Pakistani counsel identify the current applicable data-protection,
   health-record, cybercrime, payment, and breach-notification obligations.
   This register is not a legal determination.
5. Perform all vulnerability demonstrations only in the isolated local lab with
   synthetic data. Do not test production, hospital devices, or third-party
   systems without written authorization and a clinical safety plan.
