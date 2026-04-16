#!/usr/bin/env python3
"""
HTML Report Generator
Produces professional, self-contained HTML compliance reports with
executive scorecards, CSF compliance bars, risk heatmaps, per-asset
findings cards, and a prioritized remediation roadmap.
"""

import json
from datetime import datetime
from compliance_auditor import get_remediation_roadmap


def generate_html_report(audit_report: dict, output_path: str = "otsat_report.html") -> str:
    roadmap = get_remediation_roadmap(audit_report)
    html = _build_html(audit_report, roadmap)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_json_report(audit_report: dict, output_path: str = "otsat_report.json") -> str:
    def _serialize(obj):
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(audit_report, fh, indent=2, default=_serialize)
    return output_path


def _severity_color(severity: str) -> str:
    return {"Critical": "#e74c3c", "High": "#f39c12", "Medium": "#3498db", "Low": "#2ecc71"}.get(severity, "#95a5a6")


def _compliance_color(pct: float) -> str:
    if pct >= 90: return "#2ecc71"
    elif pct >= 70: return "#f39c12"
    else: return "#e74c3c"


def _bar_html(label, pct):
    color = _compliance_color(pct)
    return f'<div class="csf-row"><span class="csf-label">{label}</span><div class="csf-bar-bg"><div class="csf-bar-fill" style="width:{pct}%;background:{color};"></div></div><span class="csf-pct">{pct:.1f}%</span></div>'


def _score_card(value, label, card_class=""):
    return f'<div class="score-card {card_class}"><div class="label">{label}</div><div class="value">{value}</div></div>'


def _finding_row(f):
    color = _severity_color(f["severity"])
    status = "PASS" if f["passed"] else "FAIL"
    sc = "pass" if f["passed"] else "fail"
    return f'<tr><td><span class="badge" style="background:{color}">{f["severity"]}</span></td><td><strong>{f["control_id"]}</strong></td><td>{f["control_title"]}</td><td>{f["csf_function"]}</td><td><span class="status-{sc}">{status}</span></td></tr>'


def _asset_card(result):
    a = result["asset"]
    cc = _compliance_color(result["compliance_pct"])
    rows = "".join(_finding_row(f) for f in result["findings"])
    rem = ""
    if result["failed_findings"]:
        items = "".join(f'<li><strong>{f["control_id"]}:</strong> {f["remediation"]}</li>' for f in result["failed_findings"])
        rem = f'<div class="remediation-box"><h4>Recommended Remediations</h4><ul>{items}</ul></div>'
    return f'''<div class="asset-card"><div class="asset-header"><div><h3>{a["asset_name"]} ({a["asset_id"]})</h3><span class="asset-meta">{a["asset_type"]} | {a["purdue_level"]} | {a["zone"]} | {a["vendor"]}</span></div><div class="asset-score" style="border-color:{cc}"><div class="asset-score-value" style="color:{cc}">{result["compliance_pct"]}%</div><div class="asset-score-label">Compliance</div></div></div><div class="asset-details"><table class="details-grid"><tr><td><strong>IP:</strong> {a["ip_address"]}</td><td><strong>Protocol:</strong> {a["protocol"]}</td><td><strong>OS:</strong> {a["os"]}</td></tr><tr><td><strong>Firmware:</strong> {a["firmware_version"]}</td><td><strong>Criticality:</strong> {a["criticality"]}</td><td><strong>Last Patched:</strong> {a["last_patched"]}</td></tr></table></div><table class="findings-table"><thead><tr><th>Severity</th><th>Control</th><th>Title</th><th>CSF</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>{rem}</div>'''


def _roadmap_row(item):
    color = _severity_color(item["severity"])
    assets_str = ", ".join(item["affected_assets"][:5])
    if len(item["affected_assets"]) > 5:
        assets_str += f' (+{len(item["affected_assets"]) - 5} more)'
    return f'<tr><td><strong>#{item["priority"]}</strong></td><td><span class="badge" style="background:{color}">{item["severity"]}</span></td><td><strong>{item["control_id"]}</strong> - {item["control_title"]}</td><td>{item["affected_count"]}</td><td><small>{assets_str}</small></td><td>{item["remediation"]}</td></tr>'


def _build_html(report, roadmap):
    now = datetime.now().strftime("%B %d, %Y at %H:%M")
    score_cards = "".join([
        _score_card(f'{report["overall_compliance"]}%', "Overall Compliance", "success" if report["overall_compliance"] >= 80 else "warning" if report["overall_compliance"] >= 60 else "critical"),
        _score_card(report["total_findings"], "Total Findings", "critical" if report["total_findings"] > 10 else "warning"),
        _score_card(report["critical_findings_count"], "Critical Findings", "critical"),
        _score_card(f'{report["fully_compliant_assets"]}/{report["total_assets"]}', "Fully Compliant Assets", "success" if report["fully_compliant_assets"] == report["total_assets"] else "warning"),
        _score_card(report["total_risk_score"], "Aggregate Risk Score", "critical" if report["total_risk_score"] > 500 else "warning"),
    ])
    csf = report["csf_compliance"]
    csf_bars = "".join(_bar_html(f, csf[f]["compliance_pct"]) for f in ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
    asset_cards = "".join(_asset_card(r) for r in report["asset_results"])
    roadmap_rows = "".join(_roadmap_row(item) for item in roadmap)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OTSAT - NIST 800-82 Rev. 3 OT Security Compliance Report</title>
<style>
:root {{--primary:#1a1a2e;--secondary:#16213e;--accent:#0f3460;--highlight:#e94560;--success:#2ecc71;--warning:#f39c12;--danger:#e74c3c;--bg:#f5f6fa;--card:#ffffff;--text:#2c3e50;--muted:#7f8c8d;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}}
.header{{background:linear-gradient(135deg,var(--primary),var(--accent));color:white;padding:40px;text-align:center;}}
.header h1{{font-size:2em;margin-bottom:10px;}}
.header .meta{{opacity:0.85;font-size:0.95em;}}
.container{{max-width:1200px;margin:0 auto;padding:30px;}}
h2{{color:var(--primary);margin:30px 0 15px;border-bottom:2px solid var(--accent);padding-bottom:8px;}}
.score-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin:30px 0;}}
.score-card{{background:var(--card);border-radius:12px;padding:25px;text-align:center;box-shadow:0 2px 15px rgba(0,0,0,0.08);border-top:4px solid var(--accent);}}
.score-card.critical{{border-top-color:var(--danger);}}
.score-card.warning{{border-top-color:var(--warning);}}
.score-card.success{{border-top-color:var(--success);}}
.score-card .value{{font-size:2.2em;font-weight:700;margin:10px 0;}}
.score-card .label{{color:var(--muted);font-size:0.85em;text-transform:uppercase;letter-spacing:1px;}}
.csf-bar-container{{background:var(--card);border-radius:12px;padding:25px;box-shadow:0 2px 15px rgba(0,0,0,0.08);}}
.csf-row{{display:flex;align-items:center;margin:12px 0;}}
.csf-label{{width:110px;font-weight:600;font-size:0.9em;}}
.csf-bar-bg{{flex:1;height:28px;background:#ecf0f1;border-radius:14px;overflow:hidden;}}
.csf-bar-fill{{height:100%;border-radius:14px;transition:width 0.5s ease;}}
.csf-pct{{width:65px;text-align:right;font-weight:600;font-size:0.9em;}}
.asset-card{{background:var(--card);border-radius:12px;padding:25px;margin:20px 0;box-shadow:0 2px 15px rgba(0,0,0,0.08);}}
.asset-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;}}
.asset-header h3{{color:var(--primary);}}
.asset-meta{{color:var(--muted);font-size:0.85em;}}
.asset-score{{width:90px;height:90px;border-radius:50%;border:4px solid;display:flex;flex-direction:column;align-items:center;justify-content:center;}}
.asset-score-value{{font-size:1.3em;font-weight:700;}}
.asset-score-label{{font-size:0.65em;text-transform:uppercase;color:var(--muted);}}
.details-grid{{width:100%;margin-bottom:15px;}}
.details-grid td{{padding:4px 12px;font-size:0.9em;}}
.findings-table{{width:100%;border-collapse:collapse;font-size:0.85em;}}
.findings-table th{{background:var(--primary);color:white;padding:8px 12px;text-align:left;}}
.findings-table td{{padding:8px 12px;border-bottom:1px solid #ecf0f1;}}
.badge{{color:white;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:600;}}
.status-pass{{color:var(--success);font-weight:700;}}
.status-fail{{color:var(--danger);font-weight:700;}}
.remediation-box{{background:#fff3cd;border-left:4px solid var(--warning);padding:15px;margin-top:15px;border-radius:8px;}}
.remediation-box h4{{color:var(--warning);margin-bottom:8px;}}
.remediation-box ul{{margin-left:20px;}}
.remediation-box li{{margin:5px 0;font-size:0.9em;}}
.roadmap-table{{width:100%;border-collapse:collapse;font-size:0.85em;}}
.roadmap-table th{{background:var(--primary);color:white;padding:10px 12px;text-align:left;}}
.roadmap-table td{{padding:10px 12px;border-bottom:1px solid #ecf0f1;vertical-align:top;}}
.footer{{text-align:center;padding:30px;color:var(--muted);font-size:0.85em;margin-top:40px;border-top:1px solid #ddd;}}
</style>
</head>
<body>
<div class="header"><h1>NIST 800-82 Rev. 3 OT Security Compliance Assessment</h1><div class="meta">Generated by OTSAT (OT Security Assessment Toolkit) | {now}<br>Framework: NIST SP 800-82 Rev. 3 | CSF 2.0 Mapping | {report["total_assets"]} Assets Evaluated</div></div>
<div class="container">
<h2>Executive Summary</h2><div class="score-grid">{score_cards}</div>
<h2>NIST CSF Function Compliance</h2><div class="csf-bar-container">{csf_bars}</div>
<h2>Per-Asset Compliance Details</h2>{asset_cards}
<h2>Prioritized Remediation Roadmap</h2><table class="roadmap-table"><thead><tr><th>#</th><th>Severity</th><th>Control</th><th>Assets</th><th>Affected</th><th>Remediation</th></tr></thead><tbody>{roadmap_rows}</tbody></table>
</div>
<div class="footer">OTSAT - OT Security Assessment Toolkit | Automated NIST 800-82 Rev. 3 Compliance Auditor<br>Report generated {now} | Zero external dependencies | github.com/Sh8rlock/OTSAT</div>
</body></html>'''
