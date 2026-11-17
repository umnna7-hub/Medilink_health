# MediLink Health – Third-Party and Supply Chain Security Policy

## 1. Purpose

This policy establishes security requirements for third-party vendors and the Managed Service Provider (MSP) accessing MediLink Health systems. Its purpose is to prevent unauthorized access, insider threats, supply-chain attacks, and misuse of privileged accounts.

## 2. Scope

This policy applies to:
- Managed Service Providers (MSPs).
- Software and cloud service providers.
- IT maintenance personnel.
- Third-party technical support staff.
- Any external party accessing MediLink networks, databases, applications, or medical systems.

## 3. Just-in-Time (JIT) Vendor Access

- Vendors must not have permanent administrative access.
- Access must be requested through an authorized MediLink employee.
- Each request must specify the reason, target system, required permissions, and access duration.
- A MediLink security administrator must approve privileged access.
- Access must be time-limited and automatically revoked when the approved period expires.
- Multi-factor authentication (MFA) is mandatory.
- Vendors must use individual accounts; shared administrative accounts are prohibited.
- Access must follow the principle of least privilege.

## 4. Session Logging and Monitoring

- All privileged vendor sessions must be logged.
- Record login and logout times, account identity, source IP address, target system, and administrative activities.
- Record remote sessions where technically and legally appropriate.
- Security teams must monitor unusual activity and unauthorized access attempts.
- Logs must be protected against modification and unauthorized deletion.
- Suspicious activity must generate security alerts.

## 5. Non-Repudiation

MediLink must maintain reliable evidence of vendor activities so that actions can be attributed to individual users.

Controls include:
- Unique vendor accounts.
- MFA-based authentication.
- Timestamped and centrally stored audit logs.
- Cryptographic protection of audit records.
- Restricted access to log-management systems.
- Periodic review of vendor activity.

## 6. Vendor Access Lifecycle

**Before access:**
- Verify vendor identity and authorization.
- Review contractual security requirements.
- Approve the specific access request.

**During access:**
- Enforce MFA and least privilege.
- Monitor and record privileged sessions.
- Detect suspicious administrative activity.

**After access:**
- Revoke temporary permissions.
- Review session logs.
- Investigate unusual activity.
- Remove accounts when the vendor relationship ends.

## 7. Supply-Chain Security

MediLink must:
- Assess vendors before onboarding.
- Review software updates and verify their authenticity.
- Require vulnerability disclosure and incident notification.
- Monitor vendor security performance.
- Maintain an inventory of third-party services and dependencies.
- Require contractual security obligations and audit rights.

## 8. Lessons from Supply-Chain Attacks

**SolarWinds (2020):** The attack demonstrated how compromised software updates can introduce malicious code into trusted organizations. MediLink should verify software updates, monitor vendor activity, and restrict software deployment privileges.

**Kaseya (2021):** The ransomware incident demonstrated how attackers can abuse trusted remote management software to affect many downstream organizations. MediLink should restrict MSP privileges, monitor remote-management tools, and maintain independent backups.

## 9. Emergency Vendor Access

Emergency access may be granted when necessary to restore critical clinical services.

- Require authorization from an on-call security administrator or designated incident commander.
- Use a dedicated emergency account with MFA.
- Grant only the minimum required permissions.
- Log and monitor the entire session.
- Review the activity immediately after the emergency.
- Revoke emergency access as soon as it is no longer required.

## 10. Review and Compliance

This policy must be reviewed periodically and whenever a significant vendor, system, or security risk changes.

It supports MediLink's security objectives under ISO/IEC 27001 and the NIST Cybersecurity Framework.

## 11. Operational Service Targets

The MSP and MediLink must agree and test response targets for routine and
emergency access requests. A proposed starting target is 15 minutes for
pre-approved routine requests and 5 minutes for an emergency clinical-service
request routed to the on-call incident commander. These are service objectives,
not automatic approvals; access still requires identity verification, a named
requester, a defined scope, and an expiry time.

Emergency access must be reviewed by the next business day. The review must
confirm the request, session recording, commands/actions, changes made, and
revocation. Any failure to record or revoke access must be treated as a security
incident.

## 12. Production Evidence and Non-Repudiation

The local vendor demos are simulations only. A production implementation must
use an identity provider and privileged-access gateway; this policy does not
grant network access by itself.

For defensible attribution, store session and approval records outside the
vendor-controlled environment in centrally managed, access-restricted,
tamper-resistant storage. Use synchronized trusted timestamps, individual MFA
identities, retention controls, and independently protected signing keys.
A local unkeyed hash chain can detect accidental edits but does not by itself
provide non-repudiation or prevent a privileged attacker from rewriting the
entire log.
