# OTSAT - OT Security Assessment Toolkit

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![NIST](https://img.shields.io/badge/NIST-800--82%20Rev.3-orange) ![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)

Automated NIST 800-82 Rev. 3 compliance auditor for ICS/SCADA/DCS/PCN environments. Zero-dependency Python toolkit with risk-weighted scoring and professional HTML reporting.

Built for air-gapped OT networks. No pip installs. No internet required. Just Python 3.8+.

## Why OTSAT?

Most OT security assessments are manual, spreadsheet-driven, and inconsistent. OTSAT automates the entire workflow:

- Parse asset inventories (CSV/JSON) across Purdue Model levels 0-3
- Evaluate 11 NIST 800-82 Rev. 3 controls mapped to all 5 CSF functions
- Calculate risk-weighted compliance scores (severity x criticality)
- Generate professional HTML reports with executive scorecards and remediation roadmaps
- Complete assessment in under 1 second

## Quick Start

```bash
git clone https://github.com/Sh8rlock/OTSAT.git
cd OTSAT
python run_assessment.py --input sample_data/ot_asset_inventory.csv
```

## Sample Output

```
Overall Compliance:       70.1%
Total Findings:           43 (18 Critical, 25 High)
Aggregate Risk Score:     450
Fully Compliant Assets:   3 of 15

CSF Compliance:
  IDENTIFY     ████████████░░░░░░░░  61.5%
  PROTECT      █████████████░░░░░░░  66.1%
  DETECT       █████████████████░░░  88.2%
  RESPOND      ████████████████░░░░  80.0%
  RECOVER      ███████████████░░░░░  78.6%
```

## Architecture

```
ot_asset_parser.py      CSV/JSON inventory parser with Purdue level mapping
nist_controls.py        11 NIST 800-82 Rev. 3 control definitions (5 CSF functions)
compliance_auditor.py   Risk-weighted compliance engine with aggregate scoring
report_generator.py     Professional HTML report builder with executive dashboard
run_assessment.py       CLI entry point with multiple output format options
```

## NIST 800-82 Control Mapping

| CSF Function | Control | Severity |
|---|---|---|
| IDENTIFY | Asset Inventory & Classification | High |
| IDENTIFY | Network Architecture Documentation | High |
| PROTECT | Network Segmentation | Critical |
| PROTECT | Access Control & Authentication | Critical |
| PROTECT | Encrypted Communications | High |
| PROTECT | Patch Management | Critical |
| PROTECT | Backup & Recovery Validation | High |
| PROTECT | Endpoint Protection | High |
| DETECT | Physical Access Monitoring | High |
| RESPOND | Change Management Process | High |
| RECOVER | Incident Response Planning | Critical |

## CLI Options

```bash
python run_assessment.py --input assets.csv                    # Full assessment
python run_assessment.py --input assets.csv --output report.html  # Custom output path
python run_assessment.py --input assets.csv --json-only          # JSON report only
python run_assessment.py --input assets.csv --html-only --quiet   # Silent HTML generation
```

## Simulated Environment

The included sample data models a 15-asset chemical processing plant:

- **Level 0 (Field):** Sensors, transmitters
- **Level 1 (Safety/Control):** PLCs, RTUs, SIS
- **Level 2 (Process Control):** DCS, SCADA, HMI, network switches
- **Level 3 (Operations):** Historian, engineering workstations, physical security

Asset types include Honeywell DCS, Allen-Bradley PLCs, Siemens SCADA, Yokogawa SIS, Schweitzer RTUs, and OSIsoft Historian.

## Author

**Larry Odeyemi** - OT/ICS Security Engineer

## License

MIT License - see [LICENSE](LICENSE) for details.
