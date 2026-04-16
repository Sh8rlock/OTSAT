#!/usr/bin/env python3
"""
OT Asset Inventory Parser
Parses CSV/JSON asset inventories, normalizes data, calculates patch age,
and generates summaries by Purdue level.
"""

import csv
import json
import os
from datetime import datetime, date


CRITICALITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}

PURDUE_LEVELS = {
    "Level_0": "Physical Process (Sensors/Actuators)",
    "Level_1": "Basic Control (PLCs/RTUs/SIS)",
    "Level_2": "Process Control (DCS/SCADA/HMI)",
    "Level_3": "Operations & Site Business",
    "Level_4": "Enterprise Network",
    "Level_5": "External/DMZ",
}


def parse_csv(filepath: str) -> list[dict]:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Asset inventory not found: {filepath}")
    assets = []
    with open(filepath, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            asset = _normalize(row)
            assets.append(asset)
    return assets


def parse_json(filepath: str) -> list[dict]:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Asset inventory not found: {filepath}")
    with open(filepath, encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, dict):
        raw = raw.get("assets", [raw])
    return [_normalize(item) for item in raw]


def load_inventory(filepath: str) -> list[dict]:
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".json":
        return parse_json(filepath)
    return parse_csv(filepath)


def _normalize(row: dict) -> dict:
    def _bool(val):
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("yes", "true", "1")

    last_patched_raw = str(row.get("last_patched", "Never")).strip()
    patch_age_days = _calc_patch_age(last_patched_raw)

    return {
        "asset_id": str(row.get("asset_id", "")).strip(),
        "asset_name": str(row.get("asset_name", "")).strip(),
        "asset_type": str(row.get("asset_type", "")).strip(),
        "purdue_level": str(row.get("purdue_level", "")).strip(),
        "zone": str(row.get("zone", "")).strip(),
        "ip_address": str(row.get("ip_address", "")).strip(),
        "protocol": str(row.get("protocol", "")).strip(),
        "os": str(row.get("os", "None")).strip(),
        "firmware_version": str(row.get("firmware_version", "N/A")).strip(),
        "vendor": str(row.get("vendor", "")).strip(),
        "criticality": str(row.get("criticality", "Medium")).strip(),
        "criticality_weight": CRITICALITY_WEIGHTS.get(
            str(row.get("criticality", "Medium")).strip(), 2
        ),
        "last_patched": last_patched_raw,
        "patch_age_days": patch_age_days,
        "network_segmented": _bool(row.get("network_segmented", False)),
        "auth_enabled": _bool(row.get("auth_enabled", False)),
        "encrypted_comms": _bool(row.get("encrypted_comms", False)),
        "backup_exists": _bool(row.get("backup_exists", False)),
        "has_antivirus": _bool(row.get("has_antivirus", False)),
        "physical_access_controlled": _bool(row.get("physical_access_controlled", False)),
        "change_mgmt_documented": _bool(row.get("change_mgmt_documented", False)),
        "incident_response_plan": _bool(row.get("incident_response_plan", False)),
    }


def _calc_patch_age(last_patched: str) -> int | None:
    if last_patched.lower() in ("never", "", "n/a", "none"):
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d-%b-%Y"):
        try:
            patch_date = datetime.strptime(last_patched, fmt).date()
            return (date.today() - patch_date).days
        except ValueError:
            continue
    return None


def summarize_by_purdue_level(assets: list[dict]) -> dict:
    summary = {}
    for asset in assets:
        level = asset["purdue_level"]
        if level not in summary:
            summary[level] = {
                "description": PURDUE_LEVELS.get(level, "Unknown"),
                "count": 0,
                "criticality_breakdown": {},
                "assets": [],
            }
        summary[level]["count"] += 1
        crit = asset["criticality"]
        summary[level]["criticality_breakdown"][crit] = (
            summary[level]["criticality_breakdown"].get(crit, 0) + 1
        )
        summary[level]["assets"].append(asset["asset_id"])
    return summary


def get_inventory_stats(assets: list[dict]) -> dict:
    total = len(assets)
    never_patched = sum(1 for a in assets if a["patch_age_days"] is None)
    no_auth = sum(1 for a in assets if not a["auth_enabled"])
    no_encryption = sum(1 for a in assets if not a["encrypted_comms"])
    no_segmentation = sum(1 for a in assets if not a["network_segmented"])
    no_backup = sum(1 for a in assets if not a["backup_exists"])
    critical_assets = sum(1 for a in assets if a["criticality"] == "Critical")

    return {
        "total_assets": total,
        "critical_assets": critical_assets,
        "never_patched": never_patched,
        "no_auth": no_auth,
        "no_encryption": no_encryption,
        "no_segmentation": no_segmentation,
        "no_backup": no_backup,
        "unique_vendors": len({a["vendor"] for a in assets}),
        "unique_protocols": len({a["protocol"] for a in assets}),
    }
