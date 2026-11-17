
from datetime import datetime
import json
from integrity_checker import verify_integrity
# MediLink Health - Incident Response Simulation
# Safe demonstration using fictional data only.

incident = {
    "incident_id": "MLH-IR-001",
    "type": "Ransomware / Double Extortion",
    "severity": "Critical",
    "status": "Detected",
    "detected_at": datetime.now().isoformat(),
    "compromised_account": "employee_test_01",
    "affected_systems": [
        "Workstation-01",
        "Workstation-02",
        "Patient-Portal-Test"
    ],
    "entry_point": "Outdated appointment application",
    "actions": []
}


def log_action(stage, action):
    record = {
        "timestamp": datetime.now().isoformat(),
        "stage": stage,
        "action": action
    }

    incident["actions"].append(record)
    print(f"[{stage}] {action}")


def detect_incident():
    print("\n=== STAGE 1: DETECTION ===")

    log_action(
        "DETECTION",
        "Ransomware alert detected on test workstations."
    )

    log_action(
        "DETECTION",
        "Suspicious employee account activity identified."
    )

    incident["status"] = "Under Investigation"


def contain_incident():
    print("\n=== STAGE 2: CONTAINMENT ===")

    log_action(
        "CONTAINMENT",
        "Compromised test account temporarily disabled."
    )

    log_action(
        "CONTAINMENT",
        "Affected test workstations isolated."
    )

    log_action(
        "CONTAINMENT",
        "Suspicious remote access restricted."
    )

    log_action(
        "CONTAINMENT",
        "Backup systems protected from unauthorized access."
    )

    incident["status"] = "Contained"


def investigate_incident():
    print("\n=== STAGE 3: INVESTIGATION ===")

    log_action(
        "INVESTIGATION",
        "Entry point identified: outdated appointment application."
    )

    log_action(
        "INVESTIGATION",
        "Database and access logs reviewed for unauthorized activity."
    )

    log_action(
        "INVESTIGATION",
        "Potentially affected patient records identified for assessment."
    )


def eradicate_threat():
    print("\n=== STAGE 4: ERADICATION ===")

    log_action(
        "ERADICATION",
        "Malware removal simulated on affected test systems."
    )

    log_action(
        "ERADICATION",
        "Application vulnerability patched in the test environment."
    )

    log_action(
        "ERADICATION",
        "Compromised credentials scheduled for secure replacement."
    )

    incident["status"] = "Threat Removed"



def recover_services():
    print("\n=== STAGE 5: RECOVERY ===")

    print("\nChecking sample medical report integrity...")

    integrity_passed = verify_integrity()

    if integrity_passed:
        log_action(
            "RECOVERY",
            "Sample report passed SHA-256 integrity verification."
        )

        log_action(
            "RECOVERY",
            "Test recovery may proceed after malware scanning and other safety checks."
        )

        incident["status"] = "Recovered"

    else:
        log_action(
            "RECOVERY",
            "Integrity verification failed or baseline is unavailable."
        )

        log_action(
            "RECOVERY",
            "Recovery blocked until a trusted file is verified."
        )

        incident["status"] = "Recovery Blocked"

    log_action(
        "RECOVERY",
        "Clinical systems require clinical and technical approval before restoration."
    )


def communicate_incident():
    print("\n=== STAGE 6: STAKEHOLDER COMMUNICATION ===")

    log_action(
        "COMMUNICATION",
        "Management and incident response team notified."
    )

    log_action(
        "COMMUNICATION",
        "IT staff instructed to follow containment procedures."
    )

    log_action(
        "COMMUNICATION",
        "Legal and compliance teams informed to assess reporting obligations."
    )

    log_action(
        "COMMUNICATION",
        "Affected patients will be notified if required after assessing the data breach."
    )

    log_action(
        "COMMUNICATION",
        "Only an authorized spokesperson may issue public statements."
    )


def evaluate_ransom_demand():
    print("\n=== STAGE 7: RANSOM PAYMENT DECISION ===")

    ransom_decision = "DO NOT PAY BY DEFAULT"

    log_action(
        "RANSOM DECISION",
        "Ransom payment is not automatically authorized."
    )

    log_action(
        "RANSOM DECISION",
        "Management, legal experts, and cybersecurity specialists must assess the demand."
    )

    log_action(
        "RANSOM DECISION",
        "Payment does not guarantee data recovery or prevent stolen data from being published."
    )

    print("Final policy:", ransom_decision)

def generate_report():
    print("\n=== FINAL STAGE: INCIDENT REPORT ===")

    incident["status"] = "Simulation Completed"

    print(json.dumps(incident, indent=4))

    with open("incident_report.json", "w") as file:
        json.dump(incident, file, indent=4)

    print("\nIncident report saved as incident_report.json")


def main():
    print("======================================")
    print(" MEDILINK HEALTH INCIDENT RESPONSE")
    print("======================================")

    detect_incident()
    contain_incident()
    investigate_incident()
    eradicate_threat()
    recover_services()
    communicate_incident()
    evaluate_ransom_demand()
    generate_report()

if __name__ == "__main__":
    main()
