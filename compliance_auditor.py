#!/usr/bin/env python3
"""
NIST 800-82 Rev. 3 Compliance Auditor
Evaluates OT assets against applicable controls, calculates risk-weighted
compliance scores, and generates aggregate metrics by CSF function.
"""

from ot_asset_parser import load_inventory, get_inventory_stats, summarize_by_purdue_level
from nist_controls import get_applicable_controls, evaluate_control, get_all_controls


def audit_asset(asset: dict) -> dict:
    controls = get_applicable_controls(asset)
    findings = [evaluate_control(asset, ctrl) for ctrl in controls]

    total = len(findings)
    passed = sum(1 for f in findings if f["passed"])
    failed = [f for f in findings if not f["passed"]]
    risk_score = sum(f["risk_score"] for f in findings)
    compliance_pct = (passed / total * 100) if total > 0 else 100.0

    return {
        "asset": asset,
        "total_controls": total,
        "passed": passed,
        "failed_count": len(failed),
        "compliance_pct": round(compliance_pct, 1),
        "risk_score": risk_score,
        "findings": findings,
        "failed_findings": failed,
    }


def run_full_audit(filepath: str) -> dict:
    assets = load_inventory(filepath)
    inventory_stats = get_inventory_stats(assets)
    purdue_summary = summarize_by_purdue_level(assets)

    asset_results = [audit_asset(asset) for asset in assets]

    total_findings = sum(r["total_controls"] for r in asset_results)
    total_passed = sum(r["passed"] for r in asset_results)
    total_failed = sum(r["failed_count"] for r in asset_results)
    total_risk = sum(r["risk_score"] for r in asset_results)
    fully_compliant = sum(1 for r in asset_results if r["failed_count"] == 0)

    overall_compliance = (total_passed / total_findings * 100) if total_findings > 0 else 100.0

    csf_compliance = _calc_csf_compliance(asset_results)

    critical_findings = []
    high_findings = []
    for result in asset_results:
        for finding in result["failed_findings"]:
            if finding["severity"] == "Critical":
                critical_findings.append(finding)
            else:
                high_findings.append(finding)

    all_failed = []
    for result in asset_results:
        all_failed.extend(result["failed_findings"])
    all_failed.sort(key=lambda f: f["risk_score"], reverse=True)

    return {
        "metadata": {
            "framework": "NIST SP 800-82 Rev. 3",
            "csf_version": "NIST CSF 2.0",
            "total_controls_evaluated": len(get_all_controls()),
            "scope": "OT/ICS Security Compliance Assessment",
        },
        "inventory_stats": inventory_stats,
        "purdue_summary": purdue_summary,
        "overall_compliance": round(overall_compliance, 1),
        "total_findings": total_failed,
        "critical_findings_count": len(critical_findings),
        "high_findings_count": len(high_findings),
        "total_risk_score": total_risk,
        "fully_compliant_assets": fully_compliant,
        "total_assets": len(assets),
        "csf_compliance": csf_compliance,
        "asset_results": asset_results,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "top_risks": all_failed[:10],
    }


def _calc_csf_compliance(asset_results: list[dict]) -> dict:
    csf_totals = {}
    csf_passed = {}

    for result in asset_results:
        for finding in result["findings"]:
            func = finding["csf_function"]
            csf_totals[func] = csf_totals.get(func, 0) + 1
            if finding["passed"]:
                csf_passed[func] = csf_passed.get(func, 0) + 1

    csf_compliance = {}
    for func in ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
        total = csf_totals.get(func, 0)
        passed = csf_passed.get(func, 0)
        pct = (passed / total * 100) if total > 0 else 100.0
        csf_compliance[func] = {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "compliance_pct": round(pct, 1),
        }

    return csf_compliance


def get_remediation_roadmap(audit_report: dict) -> list[dict]:
    seen = set()
    roadmap = []

    for finding in audit_report["top_risks"]:
        key = (finding["control_id"], finding["remediation"])
        if key in seen:
            continue
        seen.add(key)

        affected_assets = [
            f["asset_id"]
            for result in audit_report["asset_results"]
            for f in result["failed_findings"]
            if f["control_id"] == finding["control_id"]
        ]

        roadmap.append({
            "priority": len(roadmap) + 1,
            "control_id": finding["control_id"],
            "control_title": finding["control_title"],
            "severity": finding["severity"],
            "csf_function": finding["csf_function"],
            "affected_assets": affected_assets,
            "affected_count": len(affected_assets),
            "remediation": finding["remediation"],
        })

    return roadmap
