#!/usr/bin/env python3
"""
NIST 800-82 Rev. 3 Control Mapping Engine
Maps security controls to OT assets based on Purdue level, asset type,
and criticality. Each control maps to a NIST CSF function.
"""

CONTROLS = [
    {
        "control_id": "AC-3",
        "title": "Access Enforcement",
        "csf_function": "PROTECT",
        "description": "Enforce approved authorizations for logical access to ICS components.",
        "severity": "Critical",
        "severity_weight": 4,
        "check_field": "auth_enabled",
        "expected": True,
        "applicable_levels": ["Level_0", "Level_1", "Level_2", "Level_3"],
        "remediation": "Implement role-based access control (RBAC) on all ICS components. "
                        "For legacy PLCs/RTUs that lack native authentication, deploy a jump host "
                        "or bastion with MFA as a compensating control.",
    },
    {
        "control_id": "SC-8",
        "title": "Transmission Confidentiality and Integrity",
        "csf_function": "PROTECT",
        "description": "Protect the confidentiality and integrity of transmitted ICS data.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "encrypted_comms",
        "expected": True,
        "applicable_levels": ["Level_1", "Level_2", "Level_3"],
        "remediation": "Enable TLS/SSL on OPC-UA and historian connections. For legacy protocols "
                        "(Modbus, DNP3) that cannot support encryption natively, deploy an encrypted "
                        "tunnel or VPN between endpoints.",
    },
    {
        "control_id": "SC-7",
        "title": "Boundary Protection (Network Segmentation)",
        "csf_function": "PROTECT",
        "description": "Segment ICS networks at Purdue level boundaries using firewalls or DMZs.",
        "severity": "Critical",
        "severity_weight": 4,
        "check_field": "network_segmented",
        "expected": True,
        "applicable_levels": ["Level_0", "Level_1", "Level_2", "Level_3"],
        "remediation": "Deploy industrial firewalls or unidirectional security gateways between "
                        "Purdue levels. Ensure Level 0/1 field devices are isolated from Level 3 "
                        "operations traffic. Validate with network traffic analysis.",
    },
    {
        "control_id": "SI-2",
        "title": "Flaw Remediation (Patch Management)",
        "csf_function": "IDENTIFY",
        "description": "Identify, report, and correct ICS software and firmware flaws in a timely manner.",
        "severity": "Critical",
        "severity_weight": 4,
        "check_field": "patch_age_days",
        "expected": "within_365",
        "applicable_levels": ["Level_0", "Level_1", "Level_2", "Level_3"],
        "remediation": "Establish a patch management program with vendor-validated patches tested "
                        "in a staging environment before deployment. For assets that cannot be patched, "
                        "document compensating controls (network isolation, application whitelisting).",
    },
    {
        "control_id": "CP-9",
        "title": "System Backup",
        "csf_function": "RECOVER",
        "description": "Conduct backups of ICS configurations, firmware, and logic programs.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "backup_exists",
        "expected": True,
        "applicable_levels": ["Level_1", "Level_2", "Level_3"],
        "remediation": "Implement automated backup of PLC/RTU logic, DCS configurations, and "
                        "historian databases. Store backups offline in a secure location. "
                        "Test restoration procedures quarterly.",
    },
    {
        "control_id": "SI-3",
        "title": "Malicious Code Protection",
        "csf_function": "DETECT",
        "description": "Implement malicious code protection mechanisms on ICS workstations and servers.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "has_antivirus",
        "expected": True,
        "applicable_levels": ["Level_2", "Level_3"],
        "remediation": "Deploy application whitelisting (preferred for ICS) or signature-based "
                        "antivirus on all Windows/Linux endpoints in Levels 2-3. For firmware-only "
                        "devices, this control is not applicable.",
    },
    {
        "control_id": "PE-3",
        "title": "Physical Access Control",
        "csf_function": "PROTECT",
        "description": "Enforce physical access authorizations at facility entry points and ICS areas.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "physical_access_controlled",
        "expected": True,
        "applicable_levels": ["Level_0", "Level_1", "Level_2", "Level_3"],
        "remediation": "Install badge readers, cameras, and visitor logs at all ICS access points. "
                        "Implement a physical security zone model aligned with Purdue levels.",
    },
    {
        "control_id": "CM-3",
        "title": "Configuration Change Control",
        "csf_function": "IDENTIFY",
        "description": "Document, approve, and track changes to ICS configurations and software.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "change_mgmt_documented",
        "expected": True,
        "applicable_levels": ["Level_1", "Level_2", "Level_3"],
        "remediation": "Implement a Management of Change (MOC) process for all ICS modifications. "
                        "Require approval from both IT security and process engineering before changes.",
    },
    {
        "control_id": "IR-4",
        "title": "Incident Handling",
        "csf_function": "RESPOND",
        "description": "Implement incident handling capability for ICS security incidents.",
        "severity": "Critical",
        "severity_weight": 4,
        "check_field": "incident_response_plan",
        "expected": True,
        "applicable_levels": ["Level_0", "Level_1", "Level_2", "Level_3"],
        "remediation": "Develop an ICS-specific incident response plan that includes OT-aware "
                        "procedures, communication protocols with process operators, and safe "
                        "shutdown procedures. Conduct tabletop exercises annually.",
    },
    {
        "control_id": "RA-5",
        "title": "Vulnerability Monitoring and Scanning",
        "csf_function": "IDENTIFY",
        "description": "Monitor and scan for vulnerabilities in ICS components and networks.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "patch_age_days",
        "expected": "within_180",
        "applicable_levels": ["Level_2", "Level_3"],
        "remediation": "Conduct passive vulnerability scanning (never active scanning on Level 0/1) "
                        "using OT-aware tools. Subscribe to ICS-CERT advisories for all deployed "
                        "vendors. Track vulnerabilities in a risk register.",
    },
    {
        "control_id": "AU-6",
        "title": "Audit Log Review, Analysis, and Reporting",
        "csf_function": "DETECT",
        "description": "Review and analyze ICS audit logs for indications of inappropriate or unusual activity.",
        "severity": "High",
        "severity_weight": 3,
        "check_field": "auth_enabled",
        "expected": True,
        "applicable_levels": ["Level_2", "Level_3"],
        "remediation": "Forward ICS logs to a centralized SIEM or log collector. Establish baseline "
                        "behavior profiles and alert on deviations. Review critical asset logs daily.",
    },
]


def get_all_controls() -> list[dict]:
    return CONTROLS


def get_controls_by_csf(function: str) -> list[dict]:
    return [c for c in CONTROLS if c["csf_function"] == function.upper()]


def get_applicable_controls(asset: dict) -> list[dict]:
    level = asset.get("purdue_level", "")
    applicable = []
    for control in CONTROLS:
        if level not in control["applicable_levels"]:
            continue
        if control["control_id"] == "SI-3":
            os_val = asset.get("os", "None").lower()
            if os_val in ("none", "firmware only", "n/a", ""):
                continue
        if control["control_id"] == "RA-5":
            os_val = asset.get("os", "None").lower()
            if os_val in ("none", ""):
                continue
        applicable.append(control)
    return applicable


def evaluate_control(asset: dict, control: dict) -> dict:
    field = control["check_field"]
    expected = control["expected"]
    actual = asset.get(field)

    passed = False

    if expected is True:
        passed = actual is True
    elif expected == "within_365":
        if actual is None:
            passed = False
        else:
            passed = actual <= 365
    elif expected == "within_180":
        if actual is None:
            passed = False
        else:
            passed = actual <= 180

    risk_score = 0 if passed else control["severity_weight"] * asset.get("criticality_weight", 2)

    return {
        "asset_id": asset["asset_id"],
        "asset_name": asset["asset_name"],
        "control_id": control["control_id"],
        "control_title": control["title"],
        "csf_function": control["csf_function"],
        "severity": control["severity"],
        "passed": passed,
        "actual_value": actual,
        "expected_value": expected,
        "risk_score": risk_score,
        "remediation": control["remediation"],
    }
