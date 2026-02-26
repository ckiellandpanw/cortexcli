import requests
import json
import time
import os
import sys
import re
from datetime import datetime, timezone

# --- CONFIGURATION ---
CORTEX_API_URL = os.getenv("CORTEX_API_URL", "<YOUR_API_URL>")
CORTEX_API_KEY_ID = os.getenv("CORTEX_API_KEY_ID", "<YOUR_API_KEY")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "<YOUR_API_KEY")

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "x-xdr-auth-id": CORTEX_API_KEY_ID,
    "Authorization": CORTEX_API_KEY
}

# --- 1. FIELD MAPPER ---
FIELD_MAP = {
    "AFFECTED_SOFTWARE": "xdm.software_package.id",
    "DERIVED_FROM_BASE_IMAGE": "xdm.vulnerability.derived_from_base_image",
    "CVE_DESCRIPTION": "xdm.finding.description",
    "CVE_ID": "xdm.vulnerability.cve_id",
    "CVE_PUBLISH_DATE": "xdm.vulnerability.publish_date",
    "CVE_RISK_FACTORS": "xdm.vulnerability.cve_risk_factors",
    "CORTEX_VULNERABILITY_RISK_SCORE": "extended_fields.cortex_vulnerability_risk_score",
    "CVSS_SCORE": "xdm.vulnerability.cvss_score",
    "CVSS_SEVERITY": "xdm.vulnerability.severity",
    "DISK_NAME": "xdm.disk.name",
    "EPSS_SCORE": "xdm.vulnerability.epss_score",
    "EXPLOIT_LEVEL": "xdm.vulnerability.cve_risk_factors",
    "EXPLOITABLE": "xdm.vulnerability.exploitable",
    "FILE_PATH": "xdm.file.path",
    "FINDING_SOURCES": "xdm.finding_sources",
    "FIRST_OBSERVED": "extended_fields.merged_fields.first_observed",
    "FIX_AVAILABLE": "xdm.vulnerability.has_a_fix",
    "FIX_DATE": "xdm.vulnerability.fix_date",
    "FIX_VERSIONS": "xdm.vulnerability.fix_versions",
    "HAS_KEV": "xdm.vulnerability.cve_risk_factors",
    "IMAGE": "extended_fields.CWP.xdm.finding.image_name",
    "IMAGE_NAME": "extended_fields.CWP.xdm.finding.image_name",
    "INTERNET_EXPOSED": "xdm.network.internet_exposed",
    "IPV4_ADDRESSES": "xdm.host.ipv4_addresses",
    "IPV6_ADDRESSES": "xdm.host.ipv6_addresses",
    "IS_DERIVED": "extended_fields.CWP.xdm.finding.is_derived",
    "IS_ROOT": "xdm.disk.is_root",
    "LAST_OBSERVED": "xdm.finding.last_observed",
    "LAYER_ID": "xdm.software_package.layer_id",
    "OPERATING_SYSTEM": "xdm.host.os",
    "OS_FAMILY": "xdm.host.os_family",
    "PACKAGE_FILE_CREATION_TIME": "xdm.software_package.file_creation",
    "PACKAGE_IN_USE": "xdm.software_package.is_in_use",
    "PACKAGE_LICENSES": "xdm.software_package.licenses",
    "ORIGIN_PACKAGE_NAME": "xdm.software_package.origin",
    "PACKAGE_PURL": "xdm.software_package.purl",
    "PACKAGE_TYPE": "xdm.software_package.type",
    "PARTITION_ID": "xdm.disk.partition.id",
    "PARTITION_ID_TYPE": "xdm.disk.partition.id_type",
    "PLATFORM_ID": "extended_fields.fields_per_source.0.type_id",
    "PROVIDER": "xdm.software_package.provider",
    "PUBLISHED_DATE": "xdm.vulnerability.publish_date",
    "PACKAGE_VERSION": "xdm.software_package.version",
    "TYPE_ID": "extended_fields.fields_per_source.0.type_id",
    "VOLUME_ASSET_ID": "xdm.finding.asset_id",
    "VOLUME_PATH": "xdm.file.volume_path"
}

# --- 2. UTILITIES (THE FIX IS HERE) ---

def get_cli_input():
    if not sys.stdin.isatty():
        cli_out = sys.stdin.read()
        print(cli_out) 
        match = re.search(r'(sha256:[a-f0-9]{64})', cli_out)
        if match: return match.group(1)
    return None

def parse_iso_date(date_str):
    try:
        if not date_str: return None
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except: return None

def get_value_smart(data, path):
    """
    FIXED: Handles both Flat JSON (dotted keys) and Nested JSON.
    """
    # 1. Try Direct Access (For Flattened XQL fields like 'xdm.vulnerability.severity')
    if path in data:
        return data[path]

    # 2. Try Nested Access (For 'extended_fields' or list access)
    try:
        keys = path.split('.')
        val = data
        for key in keys:
            # Auto-unpack extended_fields string
            if key == "extended_fields" and isinstance(val.get(key), str):
                try: val[key] = json.loads(val[key])
                except: pass
            
            # List Access
            if isinstance(val, list) and key.isdigit():
                idx = int(key)
                if idx < len(val): val = val[idx]
                else: return None
            # Dictionary Access
            else:
                val = val.get(key)
            
            if val is None: return None
        return val
    except: return None

# --- 3. COMPARISON LOGIC ---

def compare_values(actual, operator, expected, field_key=""):
    try:
        # Derived Handlers
        if field_key == "HAS_KEV":
            has_kev = isinstance(actual, list) and any("Exploited in the wild" in str(x) for x in actual)
            return (has_kev == (str(expected).upper() == "TRUE")), f"HAS_KEV={has_kev}"

        if field_key == "EXPLOIT_LEVEL":
            if not isinstance(actual, list): return False, "No Risk Factors"
            found_level = "NONE"
            if any("WEAPONIZED" in str(x).upper() for x in actual): found_level = "WEAPONIZED"
            elif any("POC" in str(x).upper() for x in actual): found_level = "POC"
            return (found_level == str(expected).upper()), f"ExploitLevel={found_level}"

        if field_key == "INTERNET_EXPOSED" and actual is None: actual = False

        # Logic Handlers
        if operator == "CONTAINS_IN_LIST":
            if isinstance(actual, list):
                match = str(expected) in [str(i) for i in actual]
                return match, f"Found '{expected}'"
            return False, "Not a list"

        if operator == "RELATIVE_TIMESTAMP":
            event_dt = parse_iso_date(actual)
            if not event_dt: return False, "Invalid Date"
            age_ms = (datetime.now(timezone.utc) - event_dt).total_seconds() * 1000
            limit_ms = float(expected)
            if age_ms <= limit_ms: return True, "Within Timeframe"
            else: return False, "Too Old"

        # Standard Types
        if isinstance(actual, (int, float)) or (isinstance(actual, str) and actual.replace('.','',1).isdigit()):
            f_act, f_exp = float(actual), float(expected)
            if operator == "EQ": return (f_act == f_exp), f"{f_act} == {f_exp}"
            if operator in ["GT", "GREATER_THAN"]: return (f_act > f_exp), f"{f_act} > {f_exp}"
            if operator in ["LT", "LESS_THAN"]: return (f_act < f_exp), f"{f_act} < {f_exp}"
            if operator in ["GTE", "GREATER_THAN_OR_EQUAL"]: return (f_act >= f_exp), f"{f_act} >= {f_exp}"
            if operator in ["LTE", "LESS_THAN_OR_EQUAL"]: return (f_act <= f_exp), f"{f_act} <= {f_exp}"

        # String/Enum Normalization
        s_act = str(actual).upper()
        s_exp = str(expected).upper()
        sev_map = {"SEV_070_CRITICAL": "CRITICAL", "SEV_060_HIGH": "HIGH", "SEV_050_MEDIUM": "MEDIUM", "SEV_040_LOW": "LOW", "SEV_030_INFO": "INFO"}
        s_exp = sev_map.get(s_exp, s_exp)

        if operator == "EQ": return (s_act == s_exp), f"{s_act} == {s_exp}"
        if operator == "NEQ": return (s_act != s_exp), f"{s_act} != {s_exp}"
        if operator == "CONTAINS": return (s_exp in s_act), f"'{s_exp}' in '{s_act}'"

        return False, "Mismatch"
    except Exception as e: return False, f"Err: {str(e)}"

def evaluate_recursive(criteria, finding_data):
    if not criteria: return True, "Match All"

    if isinstance(criteria, list):
        for item in criteria:
            res, reason = evaluate_recursive(item, finding_data)
            if res: return True, reason
        return False, "List Mismatch"

    if isinstance(criteria, dict):
        if "AND" in criteria:
            reasons = []
            for sub in criteria["AND"]:
                res, rsn = evaluate_recursive(sub, finding_data)
                if not res: return False, rsn
                reasons.append(rsn)
            return True, " & ".join(reasons)

        if "OR" in criteria:
            for sub in criteria["OR"]:
                res, rsn = evaluate_recursive(sub, finding_data)
                if res: return True, rsn
            return False, "No OR conditions met"

        field_key = criteria.get("SEARCH_FIELD")
        if field_key:
            xql_path = FIELD_MAP.get(field_key)
            if not xql_path: return False, f"Unknown: {field_key}"

            # USE THE FIXED SMART GETTER
            actual = get_value_smart(finding_data, xql_path)
            
            expected = criteria.get("SEARCH_VALUE")
            op = criteria.get("SEARCH_TYPE", "EQ")

            match, proof = compare_values(actual, op, expected, field_key)
            if match: 
                # Clean up Sev IDs for display
                short = str(expected).replace("SEV_040_", "").replace("SEV_050_", "").replace("SEV_060_", "").replace("SEV_070_", "")
                return True, f"{field_key}={short}"
            return False, "Criteria Mismatch"

    return True, "Structure Match"

# --- 4. ORCHESTRATION ---

def determine_policy_mode(policy):
    cat = policy.get("ACTION_CATEGORY", "").upper()
    actions = policy.get("ACTION", [])
    if cat == "BLOCK": return "BLOCKING"
    for act in actions:
        if act.get("take_action") is True:
            if "BLOCK" in str(act.get("action_type", "")).upper(): return "BLOCKING"
    
    if cat == "CREATE_ISSUE" or cat == "ISSUE": return "ALERTING"
    for act in actions:
        if act.get("take_action") is True:
            if "ISSUE" in str(act.get("category", "")).upper(): return "ALERTING"
    return "PASSIVE"

def select_active_policy(asset_groups, policies):
    applicable = []
    for p in policies:
        scope = p.get("ASSET_GROUP_SCOPE", [])
        if (not scope and p.get("POLICY_TYPE") == "STANDARD_POLICY") or set(asset_groups).intersection(set(scope)):
            applicable.append(p)
    if not applicable: return None
    
    # Priority: Low Integer > Alerting > Blocking
    def sort_key(p):
        mode = determine_policy_mode(p)
        return (p.get('PRIORITY', 999), 0 if mode == "ALERTING" else 1)
    
    return sorted(applicable, key=sort_key)[0]

def parse_findings(raw_findings, active_policy):
    rows = []
    blocking_violations = []
    
    p_mode = determine_policy_mode(active_policy) if active_policy else "PASSIVE"
    criteria = active_policy.get("MATCH_CRITERIA", {}) if active_policy else {}

    for row in raw_findings:
        raw_fields = row.get('xdm.finding.normalized_fields')
        norm = json.loads(raw_fields) if isinstance(raw_fields, str) else raw_fields
        full_data = {**norm, "finding": row}

        is_match, reason = evaluate_recursive(criteria, full_data)
        
        res = "PASS"
        if is_match and p_mode != "PASSIVE":
            if p_mode == "BLOCKING": res = "FAIL"
            elif p_mode == "ALERTING": res = "WARN"
        elif not is_match:
            reason = "Allowed"

        cve = norm.get('xdm.vulnerability.cve_id', 'N/A')
        sev = norm.get('xdm.vulnerability.severity', 'low').lower()
        pkg = f"{norm.get('xdm.software_package.id')} ({norm.get('xdm.software_package.version')})"
        fix = (norm.get('xdm.vulnerability.fix_versions') or ["None"])[0]
        base = "YES" if norm.get('xdm.vulnerability.derived_from_base_image') else "NO"
        exp = "YES" if norm.get('xdm.vulnerability.exploitable') else "no"
        link = norm.get('xdm.vulnerability.cve_vendor_link', '')

        row_data = {
            "CVE": cve, "SEV": sev.upper(), "PKG": pkg, "FIX": fix, 
            "BASE": base, "EXP": exp, "RES": res, "REASON": reason, "LINK": link
        }
        
        rows.append(row_data)
        if res == "FAIL": blocking_violations.append(row_data)

    return rows, blocking_violations

# --- 5. REPORTING & MAIN ---

def get_asset(sha):
    print(f"\n[ANALYZER] Waiting for asset ingestion ({sha})...", end="", flush=True)
    url = f"{CORTEX_API_URL}/public_api/v1/assets/"
    pl = {"request_data": {"search_from": 0, "search_to": 1, "filters": {"AND": [{"SEARCH_FIELD": "xdm.image.identifier", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": sha}, {"SEARCH_FIELD": "xdm.asset.type.id", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "CORE_IMAGE"}]}}}
    for _ in range(60): 
        try:
            r = requests.post(url, headers=HEADERS, json=pl)
            d = r.json().get('reply', {}).get('data', [])
            if d: print(" Done."); return d[0]
        except: pass
        time.sleep(5); print(".", end="", flush=True)
    print("\n[ERROR] Asset not found."); return None

def fetch_policies():
    l_url = f"{CORTEX_API_URL}/public_api/uvm_public/v1/list_policies"
    g_url = f"{CORTEX_API_URL}/public_api/uvm_public/v1/get_policy/"
    try:
        r = requests.post(l_url, headers=HEADERS, json={"filter_data": {"filter": {"AND": []}, "paging": {"from": 0, "to": 50}}})
        active = []
        for p in r.json().get("DATA", []):
            if p.get("STATUS") == "ENABLED":
                d = requests.get(f"{g_url}{p.get('ID')}", headers=HEADERS)
                if d.status_code == 200: active.append(d.json())
        return active
    except: return []

def get_vulns(asset_id):
    s_url = f"{CORTEX_API_URL}/public_api/v1/xql/start_xql_query/"
    r_url = f"{CORTEX_API_URL}/public_api/v1/xql/get_query_results/"
    q = f'dataset = findings | filter xdm.finding.asset_id = "{asset_id}" and xdm.finding.category = "VULNERABILITY"'
    try:
        s = requests.post(s_url, headers=HEADERS, json={"request_data": {"query": q}})
        qid = s.json()['reply']; qid = qid.get('query_id') if isinstance(qid, dict) else qid
    except: return []
    for _ in range(20):
        r = requests.post(r_url, headers=HEADERS, json={"request_data": {"query_id": qid, "pending_flag": False}})
        if r.json().get('reply', {}).get('status') == 'SUCCESS': return r.json()['reply']['results']['data']
        time.sleep(2)
    return []

def print_report(asset_name, policy, rows, violations):
    p_name = policy.get("NAME") if policy else "None"
    print("\n" + "="*180)
    print(f"{'CORTEX UNIFIED SECURITY REPORT':^180}")
    print("="*180)
    print(f" Target Image    : {asset_name}")
    print(f" Active Policy   : {p_name}")
    print(f" Total Findings  : {len(rows)}")
    print("-" * 180)

    # WIDER columns for Reason/Link
    h_fmt = "| {:<14} | {:<8} | {:<35} | {:<12} | {:<5} | {:<3} | {:<8} | {:<40} | {:<35} |"
    div = "+" + "-"*16 + "+" + "-"*10 + "+" + "-"*37 + "+" + "-"*14 + "+" + "-"*7 + "+" + "-"*5 + "+" + "-"*10 + "+" + "-"*42 + "+" + "-"*37 + "+"
    print(div)
    print(h_fmt.format("CVE", "SEV", "PACKAGE (VERSION)", "FIX VER", "BASE", "EXP", "RESULT", "REASON", "LINK"))
    print(div)
    
    for r in rows:
        res = "FAIL [X]" if r["RES"] == "FAIL" else ("WARN [!]" if r["RES"] == "WARN" else "PASS [ ]")
        # No truncation for Reason/Link unless huge
        #l_dsp = r['LINK'][:45]
        link_val = r.get('LINK') or ""
        l_dsp = link_val[:45]
        p_dsp = (r['PKG'][:32] + "...") if len(r['PKG']) > 35 else r['PKG']
        print(h_fmt.format(r['CVE'], r['SEV'], p_dsp, r['FIX'], r['BASE'], r['EXP'], res, r['REASON'], l_dsp))
    print(div)

    if violations:
        print(f"\n[FAIL] Pipeline blocked: {len(violations)} Blocking Violations found.")
        sys.exit(1)
    elif any(r['RES'] == "WARN" for r in rows):
        print(f"\n[PASS] Issues detected & created (Alerting (Issue Creation) Policy). No Blocking rules met.")
        sys.exit(0)
    print("\n[PASS] Image is compliant."); sys.exit(0)

def main():
    sha = get_cli_input()
    if not sha: print("[ERROR] No input."); sys.exit(1)
    asset = get_asset(sha)
    if not asset: sys.exit(1)
    
    policies = fetch_policies()
    active_policy = select_active_policy(asset.get('xdm.asset.group_ids', []), policies)
    
    #findings = get_vulns(asset.get('xdm.asset.id'))
    #rows, violations = parse_findings(findings, active_policy)
    #print_report(asset.get('xdm.image.names', ['unknown'])[0], active_policy, rows, violations)

    findings = get_vulns(asset.get('xdm.asset.id'))
    rows, violations = parse_findings(findings, active_policy)

    # --- Safe image name resolution ---
    image_names = asset.get('xdm.image.names') or []

    if image_names:
        asset_name = image_names[0]
    else:
        asset_name = (
            asset.get('xdm.image.identifier')
            or asset.get('xdm.asset.name')
            or asset.get('xdm.asset.id')
            or 'unknown'
        )

    print_report(asset_name, active_policy, rows, violations)



if __name__ == "__main__":
    main()