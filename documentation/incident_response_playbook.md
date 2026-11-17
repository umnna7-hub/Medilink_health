# MediLink Health – Ransomware Incident Response Playbook

## 1. Purpose

This playbook defines how MediLink Health will respond to a ransomware double-extortion attack. It aims to protect patient confidentiality, maintain critical clinical services, minimize operational disruption, and restore affected systems safely.

## 2. Simulated Incident Scenario

An attacker compromises an employee account through phishing and gains unauthorized access to MediLink's network.

The attacker:
- Steals sensitive patient information.
- Encrypts files and disrupts hospital systems.
- Attempts to affect the patient-records database.
- Demands ransom payment.
- Threatens to publish stolen patient information.

This is a double-extortion ransomware incident because both data encryption and data theft are involved.

## 3. Incident Response Team

| Role | Responsibility |
|---|---|
| Incident Commander | Coordinates the overall response |
| Security Team | Detects, investigates, and contains the attack |
| IT Team | Isolates affected systems and restores services |
| Database Administrator | Protects and recovers patient databases |
| Hospital Management | Makes operational decisions |
| Legal and Compliance Team | Handles legal obligations and reporting |
| Communications Team | Communicates with staff, patients, and stakeholders |

## 4. Phase 1 – Detection and Identification

The security team must:
- Monitor IDS, security alerts, and endpoint protection systems.
- Identify unusual login attempts and privileged account activity.
- Detect suspicious file encryption and unauthorized data transfers.
- Investigate ransomware messages and unusual system behavior.
- Identify affected systems, networks, and possible patient data exposure.
- Preserve relevant logs and forensic evidence.

Once confirmed, the incident must be classified as a major security incident and escalated to the Incident Commander.

## 5. Phase 2 – Containment

The priority is to stop the attack from spreading.

Actions:
- Isolate infected computers and servers from the network.
- Disable compromised accounts and revoke active sessions.
- Restrict suspicious VPN and MSP remote access.
- Block identified malicious network traffic.
- Protect backup systems from unauthorized access.
- Segment affected networks from critical clinical systems.
- Coordinate with hospital IT teams to maintain life-critical operations.

**Important:** ICU monitors, infusion pumps, and other life-critical medical devices must not be disconnected or shut down without clinical and technical authorization. Patient safety comes first.

## 6. Phase 3 – Eradication and Investigation

After containment:
- Identify the initial entry point.
- Remove ransomware and malicious software.
- Investigate compromised accounts and credentials.
- Check for persistence mechanisms and unauthorized access.
- Assess whether patient information was accessed or stolen.
- Patch exploited vulnerabilities.
- Reset affected credentials and strengthen access controls.
- Preserve forensic evidence for investigation.

Systems must not be restored until the security team has reasonable confidence that the threat has been removed.

## 7. Phase 4 – Recovery

MediLink will recover systems using verified, clean backups. The lab prototype
encrypts each backup, authenticates the ciphertext-hash manifest with a
separate HMAC key, verifies that HMAC before checking the ciphertext and
decrypting, and refuses corrupted backups. Its configured destination is not
immutable merely because it is a separate or offline path.

Recovery steps:
1. Identify unaffected or isolated backup copies.
2. Verify the manifest HMAC and ciphertext SHA-256 before decryption.
3. Confirm backups are clean and suitable for restoration.
4. Restore critical clinical services in a controlled order.
5. Validate database consistency and application functionality.
6. Conduct security checks before reconnecting systems.
7. Monitor restored systems for signs of reinfection.

Clinical services should receive recovery priority based on patient safety and business impact.

The recovery process must support the 99.9% availability objective for clinical systems while avoiding downtime to life-critical devices.

## 8. Phase 5 – Stakeholder Communication

Communication must be timely, accurate, and coordinated.

**Hospital Management**
- Receive incident updates and operational impact reports.
- Approve major recovery and continuity decisions.

**Hospital Staff**
- Receive instructions about affected systems.
- Be warned not to open suspicious links or attachments.
- Be informed about alternative procedures where necessary.

**Patients**
- Be informed if their personal information is affected, in accordance with applicable legal requirements.
- Receive accurate guidance about protecting their accounts and personal information.

**Regulators and Authorities**
- Relevant Pakistani authorities must be notified where legally required.
- Legal and compliance teams must assess applicable reporting obligations.

**Third-Party Vendors**
- Affected vendors must cooperate with the investigation.
- Compromised vendor access must be suspended or restricted.

Only authorized spokespersons should communicate externally.

## 9. Phase 6 – Ransom Payment Decision

MediLink should not automatically agree to ransom demands.

The decision must involve hospital management, legal counsel, cybersecurity specialists, and relevant authorities.

Considerations:
- Paying does not guarantee that encrypted files will be restored.
- Attackers may still publish stolen patient information.
- Payment may encourage further attacks.
- Payment may create legal or sanctions-related concerns.
- Verified backups and alternative recovery methods should be assessed first.

**Recommended position:** Do not pay the ransom by default. Prioritize containment, investigation, verified backup recovery, legal advice, and patient protection. Any exceptional decision must undergo formal legal and executive review.

## 10. Post-Incident Activities

After recovery:
- Conduct a lessons-learned review.
- Identify security weaknesses that enabled the attack.
- Update security policies and controls.
- Improve staff phishing awareness training.
- Review vendor and remote-access permissions.
- Test backup and recovery procedures.
- Document the incident and corrective actions.

## 11. Prevention and Preparedness

MediLink should maintain:
- Multi-factor authentication.
- Endpoint detection and response.
- Network segmentation.
- Regular vulnerability assessments.
- Employee security awareness training.
- Immutable and offline backups.
- Centralized security logging and monitoring.
- Restricted third-party administrative access.
- Tested incident response and business continuity plans.

## 12. Conclusion

This playbook provides MediLink Health with a structured response to ransomware double-extortion attacks. It prioritizes patient safety, confidentiality, rapid containment, reliable recovery, and responsible communication.

It supports the organization's cybersecurity objectives and alignment with the NIST Cybersecurity Framework and ISO/IEC 27001.

## 13. Triage of the Current Warning Signals

The phishing campaign, portal DDoS, appointment-module SQL errors, and dark-web
claim must be handled as separate but potentially related workstreams:

- **Phishing:** Preserve the original message and mail-security telemetry;
  identify recipients and sign-in activity; revoke affected sessions and
  credentials; check for mailbox forwarding rules and privileged access.
- **Portal DDoS:** Engage the upstream hosting/DDoS provider immediately, retain
  edge and application metrics, and communicate service status. Do not rely on
  the local demonstration limiter as the sole availability control.
- **Suspicious SQL errors:** Preserve application and database logs, identify
  affected versions and request IDs, review database access/audit records, and
  patch or disable the affected path if needed. Do not test the suspected issue
  against production without written authorization and a controlled change
  window.
- **Dark-web sale claim:** Treat it as unverified, preserve the source and time
  of observation, and have legal/privacy and security teams validate exposure
  using authorized records and logs. Do not download, redistribute, or use
  purported patient data as a test dataset.

Maintain a single incident timeline and evidence register with restricted
access. Record decisions, evidence hashes, custodians, and approved transfers.
Keep patient identifiers out of general chat and vendor tickets.

## 14. Legal and Clinical Decision Gates

Legal/privacy counsel must determine the current applicable Pakistani laws,
competent authorities, and notification deadlines; this playbook does not
substitute for that advice. Record the decision and rationale even if no
notification is required. Clinical leadership must approve any action that
could change device connectivity, patient-care workflow, or restoration order.

## 15. Exercise Acceptance Criteria

At least annually and after material architecture changes, exercise a synthetic
double-extortion scenario. Pass criteria include documented containment
ownership, verified out-of-band communications, a successful clean restore
within approved RTO/RPO, clinical sign-off before reconnecting affected zones,
and a completed legal/privacy notification decision. The current lab report
records a blocked restore; that is a useful failure result, not a successful
recovery test.