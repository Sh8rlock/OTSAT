#!/usr/bin/env python3
"""
OTSAT - OT Security Assessment Toolkit
=======================================
Automated NIST 800-82 Rev. 3 compliance auditor for ICS/SCADA/DCS/PCN environments.
Zero-dependency Python toolkit with risk-weighted scoring and professional HTML reporting.

Usage:
    python run_assessment.py --input sample_data/ot_asset_inventory.csv
    python run_assessment.py --input assets.csv --output report.html
    python run_assessment.py --input assets.csv --json-only
    python run_assessment.py --input assets.csv --html-only --quiet

Author: Larry Odeyemi
License: MIT
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from compliance_auditor import run_full_audit, get_remediation_roadmap
from report_generator import generate_html_report, generate_json_report


def _print_banner():
    print(r"""
  ___  _____ ____    _  _____
 / _ \|_   _/ ___|  / \|_   _|
| | | | | | \___ \ / _ \ | |
| |_| | | |  ___) / ___ \| |
 \___/  |_| |____/_/   \_\_|

  OT Security Assessment Toolkit
  NIST 800-82 Rev. 3 Compliance Auditor
""")


def _print_summary(report: dict):
    comp = report["overall_compliance"]
    bar_len = 20

    print(f"  Overall Compliance:       {comp}%")
    print(f"  Total Findings:           {report['total_findings']} "
          f"({report['critical_findings_count']} Critical, {report['high_findings_count']} High)")
    print(f"  Aggregate Risk Score:     {report['total_risk_score']}")
    print(f"  Fully Compliant Assets:   {report['fully_compliant_assets']} of {report['total_assets']}")
    print()

    print("  CSF Compliance:")
    for func in ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
        pct = report["csf_compliance"][func]["compliance_pct"]
        filled = int(pct / 100 * bar_len)
        bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
        print(f"    {func:<12} {bar} {pct:>5.1f}%")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="OTSAT - Automated NIST 800-82 Rev. 3 OT Security Compliance Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", required=True, help="Path to asset inventory file (CSV or JSON)")
    parser.add_argument("--output", "-o", default=None, help="Output file path")
    parser.add_argument("--json-only", action="store_true", help="Generate JSON report only")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")

    args = parser.parse_args()

    if not args.quiet:
        _print_banner()

    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"  Loading inventory: {args.input}")

    start = time.time()
    report = run_full_audit(args.input)
    elapsed = time.time() - start

    if not args.quiet:
        print(f"  Audit completed in {elapsed:.3f}s")
        print(f"  Assets evaluated: {report['total_assets']}")
        print()
        _print_summary(report)

    outputs = []

    if not args.json_only:
        html_path = args.output if args.output and args.output.endswith(".html") else "otsat_report.html"
        generate_html_report(report, html_path)
        outputs.append(html_path)
        if not args.quiet:
            print(f"  HTML report saved: {html_path}")

    if not args.html_only:
        json_path = args.output if args.output and args.output.endswith(".json") else "otsat_report.json"
        generate_json_report(report, json_path)
        outputs.append(json_path)
        if not args.quiet:
            print(f"  JSON report saved: {json_path}")

    if not args.quiet:
        print()
        print("  Assessment complete. Open the HTML report in a browser to view results.")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
