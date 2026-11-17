# Task 7: Evaluation and Comparison of Alternative Architectures

## 1. Introduction

MediLink Health needs a secure and reliable architecture to support its web portal, mobile application, central patient database, diagnostic laboratories, hospital networks, and medical IoT devices.

The organization has a budget of PKR 40 million and a 12-week implementation timeline. The architecture must protect confidential patient information, maintain at least 99.9% availability for clinical systems, and avoid downtime for life-critical medical devices.

This evaluation compares two alternative architectures and recommends the most suitable design.

## 2. Alternative Architectures

### Architecture A: Centralized Cloud Architecture

In this architecture, most hospital applications, the patient database, and supporting services are hosted in a centralized cloud environment.

Hospitals, laboratories, staff, and patients connect to the cloud through secure network connections.

**Main characteristics:**
- Centralized patient database hosted in the cloud.
- Web portal and mobile application hosted in the cloud.
- Centralized authentication and access management.
- Cloud-based backups and security monitoring.
- Hospital medical devices connect through hospital networks and controlled gateways.

### Architecture B: Hybrid, Segmented Architecture

In this architecture, cloud services are combined with separated hospital networks.

The web portal, mobile application, and central patient database use secure cloud infrastructure. Hospital networks are divided into separate security zones, including clinical systems, staff networks, administrative systems, and medical IoT devices.

**Main characteristics:**
- Centralized patient database hosted in a secure cloud environment.
- Separate network segments for hospital departments.
- Medical IoT devices isolated in dedicated network zones.
- Controlled communication between medical devices and other systems.
- Secure remote access for third-party maintenance providers.
- Centralized security monitoring and protected backups.
## 3. Architecture Comparison

The two architectures are evaluated using four important criteria: implementation cost, security effectiveness, usability, and clinical impact.

| Evaluation Criteria | Architecture A: Centralized Cloud | Architecture B: Hybrid, Segmented |
|---|---|---|
| Cost | Potentially lower initial infrastructure cost because most services use centralized cloud resources. However, cloud usage and connectivity costs may increase over time. | Higher initial cost due to network segmentation, secure gateways, and additional infrastructure. |
| Security Effectiveness | Centralized security controls simplify monitoring, but a compromise of central services could affect multiple hospitals. | Stronger network isolation limits lateral movement and reduces the impact of attacks on medical IoT devices and hospital systems. |
| Usability | Provides centralized access to applications and patient records, making management relatively simple. | Provides secure access, but additional authentication and network controls may require staff training. |
| Clinical Impact | Cloud outages or connectivity problems could affect access to centralized clinical services across multiple hospitals. | Local network segmentation helps isolate problems, while controlled connectivity and appropriate redundancy support clinical operations. |
| Scalability | Cloud resources can be expanded as the number of patients and hospitals increases. | Can scale through additional cloud resources and properly segmented hospital networks. |
| Maintenance | Centralized infrastructure can simplify software updates and monitoring. | Requires coordination between cloud services, hospital networks, and medical device environments. |

### 3.1 Evaluation Summary

Architecture A is easier to manage centrally and may have lower initial infrastructure costs. However, it creates greater dependency on centralized services and requires careful planning to limit the impact of cloud outages or security breaches.

Architecture B requires more planning and initial investment, but network segmentation provides stronger isolation between clinical systems, staff networks, and medical IoT devices. It also allows security controls to be applied according to the needs of each hospital environment.
## 4. Recommended Architecture

After comparing both alternatives, Architecture B: Hybrid, Segmented Architecture is recommended for MediLink Health.

Although it requires a higher initial investment and more maintenance, it provides stronger protection for hospital networks and medical devices.

The recommendation is based on the following reasons:

1. **Improved security:** Network segmentation separates medical IoT devices, staff networks, administrative systems, and clinical applications. This helps prevent attackers from moving freely between network zones.

2. **Patient data protection:** Centralized cloud services can use encryption, multi-factor authentication, role-based access control, and secure database connections to protect confidential patient records.

3. **Clinical availability:** Separating critical medical devices from general-purpose networks reduces the risk that an attack on office computers will directly affect life-critical equipment.

4. **Controlled third-party access:** Vendors and managed service providers receive restricted, time-limited access with session monitoring and audit logging.

5. **Scalability:** Cloud infrastructure can support additional hospitals, laboratories, and patients as MediLink Health grows.

6. **Backup and recovery:** Encrypted backups, immutable backup storage, and regular recovery testing help the organization recover from ransomware and other incidents.

## 5. Implementation Considerations

To implement the recommended architecture within the PKR 40 million budget and 12-week timeline, MediLink Health should:

- Prioritize network segmentation and protection of critical medical devices.
- Deploy multi-factor authentication and role-based access control.
- Encrypt patient information during transmission and storage.
- Implement centralized logging, monitoring, and intrusion detection.
- Configure secure, time-limited vendor access.
- Maintain immutable or offline backups and test recovery procedures.
- Train hospital staff to recognize phishing and report suspicious activity.
- Test the architecture before deployment to avoid disrupting clinical operations.

The implementation must maintain the 99.9% availability target for clinical systems. Any changes affecting life-critical devices must be coordinated with clinical and technical teams to prevent unsafe downtime.

## 6. Evidence and Security Frameworks

The recommended architecture is supported by established cybersecurity frameworks and security principles:

- **NIST Cybersecurity Framework 2.0:** Supports governance, identification, protection, detection, response, and recovery.
- **ISO/IEC 27001:2022:** Provides requirements for establishing and maintaining an information security management system.
- **Network segmentation:** Limits unauthorized communication between different network zones and helps contain security incidents.
- **Defense in depth:** Uses multiple security controls rather than relying on a single protective measure.

These frameworks support the security controls and risk-management approach used in the recommended architecture.

## 7. Conclusion

Architecture B: Hybrid, Segmented Architecture is the most suitable option for MediLink Health because it balances security, usability, scalability, and clinical availability.

It provides stronger isolation for medical IoT devices, protects sensitive patient information,
## 8. References

1. National Institute of Standards and Technology (NIST). (2024). *The NIST Cybersecurity Framework (CSF) 2.0*. NIST Cybersecurity White Paper 29. https://doi.org/10.6028/NIST.CSWP.29

2. International Organization for Standardization (ISO). (2022). *ISO/IEC 27001:2022 — Information security management systems: Requirements*. https://www.iso.org/standard/27001

These references provide recognized guidance for cybersecurity risk management and information security management systems.

## 9. Layered Target Architecture

This is a target design, not a claim that the controls are deployed.

1. **Public edge:** Use a managed DDoS service and WAF/API gateway in front of
   the portal and API. Terminate TLS at an approved edge, reject malformed
   requests, apply per-account and per-client limits, and alert on abuse.
2. **Identity and privileged access:** Use a central identity provider, unique
   staff identities, phishing-resistant MFA for staff and MSPs, role-based
   access, and a privileged-access jump host. Grant vendor access just in time,
   to named targets and for a fixed duration. Keep clinician emergency access
   separately governed and audited.
3. **Application tier:** Keep application services in private subnets; expose
   only the gateway. Use parameterized SQL, server-side authorization, managed
   secrets, dependency monitoring, and authenticated payment-provider callbacks.
   Do not store card data unless a formally approved payment design requires it.
4. **Patient-data tier:** Make the SQL database reachable only from required
   application services. Require TLS for database connections and managed
   encryption at rest with separately controlled keys. Audit privileged queries
   and access to sensitive tables.
5. **Hospital zones:** Separate staff/administrative endpoints, clinical
   workstations, medical IoT, guest access, and network management. Apply
   default-deny rules and explicitly allow only required device-to-controller
   flows. IoT devices should not have direct internet access.
6. **IoT safety:** Use passive monitoring and staged allowlisting first. For
   legacy devices, place compensating controls at the switch/firewall or
   gateway. Biomedical engineering and clinical leadership must approve any
   change affecting device traffic. Do not place an unvalidated inline proxy in
   a life-critical control path.
7. **Detection and recovery:** Forward identity, application, database, endpoint,
   network, cloud, and MSP-jump-host logs to a restricted central platform with
   immutable retention. Keep encrypted, cross-account backups with object lock
   or equivalent immutability, separate credentials, and scheduled restore
   exercises.

The availability objective must be translated into service-specific SLOs,
approved RTO/RPO values, tested failover, and clinical downtime procedures.
The 99.9% target alone does not demonstrate availability.

## 10. Resolution of Conflicting Requirements

| Conflict | Recommended resolution and safety condition |
|---|---|
| MFA and session timeouts vs. emergency clinical access | MFA remains the normal path. Provide a separately controlled break-glass workflow with a reason code, minimum scope, short expiry, immediate alert, and next-shift review. Maintain a clinical downtime procedure if identity services are unavailable. |
| Encryption vs. ICU latency | Encrypt data in transit and at rest by default. Keep time-critical device control local where possible; use gateways only after device-vendor and clinical latency testing. Do not weaken encryption globally to solve an unmeasured latency concern. |
| Unpatchable legacy devices vs. zero-days | Isolate devices in dedicated zones, allowlist necessary flows, deny internet access, monitor passively, and apply vendor-approved compensating controls. Patch only under biomedical change control; do not interrupt life-critical operation. |
| Vendor monitoring vs. fast MSP response | Route access through a preconfigured JIT jump host with recording and named accounts. Adopt operational targets for routine and emergency approval only after the MSP and clinical on-call teams validate them; emergency access is time-limited and reviewed immediately afterward. |
| PKR 40 million vs. broad coverage | Fund high-consequence patient, clinical, identity, and recovery risks first. Use the indicative allocation below, retain contingency, and defer lower-risk features rather than removing baseline controls. Validate all amounts through procurement. |

## 11. Indicative PKR 40 Million Allocation

These are planning allowances, not vendor quotes or a statement of current
spending. Procurement must validate licensing, tax, connectivity, managed
service, and recurring costs before approval.

| Workstream | Allowance (PKR million) |
|---|---:|
| Hospital/Lab segmentation, firewalls, and safe IoT visibility across sites | 9.0 |
| Identity, MFA, privileged access, and JIT vendor access | 5.0 |
| Endpoint/email protection and staff training | 5.0 |
| Cloud hardening, WAF, API protection, and DDoS service | 6.0 |
| Isolated immutable backups and recovery capacity | 6.0 |
| Central logging, alerting, and initial managed monitoring | 4.0 |
| Application security assessment, remediation, and load testing | 2.0 |
| Legal/privacy review, tabletop exercises, and governance | 1.0 |
| Contingency | 2.0 |
| **Total** | **40.0** |

## 12. Twelve-Week Delivery Roadmap

| Weeks | Deliverable and gate |
|---|---|
| 1–2 | Inventory assets/data flows; approve risk owners, legal review, service criticality, RTO/RPO, and pilot plan. No production changes to life-critical devices. |
| 3–4 | Configure identity/MFA and privileged-access pilot; deploy edge protections and central log collection; establish backup isolation and recovery baselines. |
| 5–7 | Pilot hospital segmentation with biomedical approval, then stage rollout across the remaining hospitals and laboratories. Validate each change and rollback before proceeding. |
| 8–9 | Complete application remediation, payment-provider design review, and isolated security tests. Run capacity/load tests against agreed targets. |
| 10–11 | Perform database/portal restore exercises, failover tests, MSP-access exercise, and ransomware/DDoS tabletop. Record results and corrective actions. |
| 12 | Clinical and business acceptance, residual-risk approval, evidence pack, operations handover, and funded remediation backlog. |

The sequencing depends on procurement, cloud/MSP cooperation, and clinical
change windows. If a site cannot pass safety or rollback criteria, defer that
site's change rather than risk device availability.

## 13. Legal and Framework Mapping

Use NIST CSF 2.0 across Govern, Identify, Protect, Detect, Respond, and Recover,
and map selected controls and evidence to ISO/IEC 27001:2022. Pakistani counsel
must review PECA 2016 as amended and identify the current applicable
data-protection, health-record, payment, data-residency, and breach-notification
requirements. This project document does not certify legal or ISO compliance.

## 14. Repository Implementation Status

The following target controls remain deployment or product work, not completed
implementation in this repository:

- The root `schema.sql` is empty; the other SQL files are partial table changes,
  so a reviewed, repeatable database migration set is still required.
- Payment records and API behavior are explicitly simulated; no payment
  provider integration is present.
- The project contains a React web portal, not a native patient mobile app.
- MFA, clinical break-glass, cloud network segmentation, managed database TLS,
  WAF/DDoS service, centralized IDS/SIEM, and immutable cloud backups are not
  wired into the application source.
- The local rate-limit and backup tools are learning/test demonstrations and
  must not be used as the production availability or recovery control.

Acceptance should therefore require infrastructure evidence, clinical
validation, legal review, and successful recovery/failover tests before any
claim that the target architecture is operational.