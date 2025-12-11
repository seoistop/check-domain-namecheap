# -*- coding: utf-8 -*-
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import requests
import xml.etree.ElementTree as ET

API_PROD = "https://api.namecheap.com/xml.response"
API_SANDBOX = "https://api.sandbox.namecheap.com/xml.response"
MAX_PER_CALL = 50  # Namecheap: tối đa 50 domain/lần

def chunked(seq: List[str], n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]

def parse_xml_with_ns(xml_text: str, debug: bool = False):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        if debug:
            sys.stderr.write(f"\n===== RAW XML (parse error) =====\n{xml_text}\n===============================\n")
        raise
    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"nc": ns_uri}
        q = lambda tag: f".//nc:{tag}"
    else:
        ns = {}
        q = lambda tag: f".//{tag}"
    return root, ns, q

def parse_domains_check(xml_text: str, debug: bool = False) -> Dict[str, Any]:
    out = {"status": "OK", "results": [], "errors": []}
    try:
        root, ns, q = parse_xml_with_ns(xml_text, debug=debug)
    except ET.ParseError as e:
        out["status"] = "ERROR"
        out["errors"].append(f"XML parse error: {e}")
        return out

    errors_node = root.find(q("Errors"), ns)
    if errors_node is not None:
        for err in errors_node:
            num = (err.attrib.get("Number") or "").strip()
            txt = (err.text or "").strip()
            msg = f"{num} {txt}".strip() if (num or txt) else "Unknown API error"
            out["errors"].append(msg)

    for n in root.findall(q("DomainCheckResult"), ns):
        domain = (n.attrib.get("Domain") or "").strip().lower()
        available = (n.attrib.get("Available", "false").lower() == "true")
        is_premium = (n.attrib.get("IsPremiumName", "false").lower() == "true")
        out["results"].append({
            "domain": domain,
            "available": available,
            "is_premium": is_premium,
            "premium_registration_price": n.attrib.get("PremiumRegistrationPrice"),
            "premium_renewal_price": n.attrib.get("PremiumRenewalPrice"),
            "premium_transfer_price": n.attrib.get("PremiumTransferPrice"),
            "icann_fee": n.attrib.get("IcannFee"),
            "eap_fee": n.attrib.get("EapFee"),
            "error": n.attrib.get("Description") or None
        })

    if not out["results"] and not out["errors"]:
        out["status"] = "ERROR"
        out["errors"].append("No DomainCheckResult found (check namespace/parameters)")
    return out

def call_domains_check(endpoint: str, api_user: str, username: str, api_key: str, client_ip: str,
                       domains: List[str], timeout: int = 20, retry: int = 2, backoff: float = 1.5,
                       debug: bool = False) -> Dict[str, Any]:
    params = {
        "ApiUser": api_user,
        "ApiKey": api_key,
        "UserName": username,
        "ClientIp": client_ip,
        "Command": "namecheap.domains.check",
        "DomainList": ",".join(domains)
    }
    attempt = 0
    while True:
        attempt += 1
        try:
            r = requests.get(endpoint, params=params, timeout=timeout)
        except requests.RequestException as e:
            if attempt <= retry:
                time.sleep(backoff ** attempt)
                continue
            return {"status": "ERROR", "results": [], "errors": [f"Network error: {e}"]}
        if r.status_code != 200:
            if attempt <= retry:
                time.sleep(backoff ** attempt)
                continue
            return {"status": "ERROR", "results": [], "errors": [f"HTTP {r.status_code}: {r.text[:300]}"]}

        parsed = parse_domains_check(r.text, debug=debug)
        # Retry nhẹ nếu do lỗi tạm thời
        if parsed["status"] == "ERROR" and attempt <= retry and parsed["errors"]:
            time.sleep(backoff ** attempt)
        return parsed

def extract_tld(domain: str) -> Optional[str]:
    if "." not in domain:
        return None
    tld = domain.rsplit(".", 1)[-1].strip().lower()
    if not tld:
        return None
    return tld

def parse_users_get_pricing(xml_text: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    try:
        root, ns, q = parse_xml_with_ns(xml_text, debug=debug)
    except ET.ParseError:
        return out
    for prod in root.findall(".//*[@Name]"):
        name = prod.attrib.get("Name")
        if not name: 
            continue
        tld_key = name.strip().upper()
        prices = {"register_price": None, "renew_price": None, "transfer_price": None, "currency": None}
        for node in list(prod.iter()):
            action = node.attrib.get("Action", "").strip().upper() if hasattr(node, "attrib") else ""
            if action in {"REGISTER", "RENEW", "TRANSFER"}:
                price = node.attrib.get("Price") or node.attrib.get("RetailPrice") or node.attrib.get("RegularPrice")
                currency = node.attrib.get("Currency")
                key = {"REGISTER": "register_price", "RENEW": "renew_price", "TRANSFER": "transfer_price"}.get(action)
                if key and price and prices[key] is None:
                    prices[key] = price
                if not prices["currency"] and currency:
                    prices["currency"] = currency
        if any([prices["register_price"], prices["renew_price"], prices["transfer_price"]]):
            out[tld_key] = prices
    return out

def call_users_get_pricing(endpoint: str, api_user: str, username: str, api_key: str, client_ip: str,
                           timeout: int = 20, retry: int = 1, backoff: float = 1.5,
                           debug: bool = False) -> Dict[str, Dict[str, Any]]:
    params = {
        "ApiUser": api_user,
        "ApiKey": api_key,
        "UserName": username,
        "ClientIp": client_ip,
        "Command": "namecheap.users.getPricing",
    }
    attempt = 0
    while True:
        attempt += 1
        try:
            r = requests.get(endpoint, params=params, timeout=timeout)
        except requests.RequestException as e:
            if attempt <= retry:
                time.sleep(backoff ** attempt)
                continue
            if debug:
                sys.stderr.write(f"getPricing network error: {e}\n")
            return {}
        if r.status_code != 200:
            if attempt <= retry:
                time.sleep(backoff ** attempt)
                continue
            if debug:
                sys.stderr.write(f"getPricing HTTP {r.status_code}: {r.text[:300]}\n")
            return {}
        return parse_users_get_pricing(r.text, debug=debug)

def run_check_to_csv(
    api_user: str, username: str, api_key: str, client_ip: str,
    input_path: Path, output_csv: Path, output_json: Path = None,
    use_sandbox: bool = False, timeout: int = 20, batch_size: int = MAX_PER_CALL,
    debug: bool = False
) -> Path:
    endpoint = API_SANDBOX if use_sandbox else API_PROD
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    domains: List[str] = []
    for line in input_path.read_text(encoding="utf-8").splitlines():
        d = line.strip().lower()
        if d and not d.startswith("#"):
            if d.startswith("www."):
                d = d[4:]
            domains.append(d)
    if not domains:
        raise ValueError("No domains in input file")

    if batch_size <= 0 or batch_size > MAX_PER_CALL:
        batch_size = MAX_PER_CALL

    all_results: List[Dict[str, Any]] = []
    global_errors: List[str] = []

    for batch in chunked(domains, batch_size):
        resp = call_domains_check(
            endpoint=endpoint,
            api_user=api_user,
            username=username,
            api_key=api_key,
            client_ip=client_ip,
            domains=batch,
            timeout=timeout,
            debug=debug
        )
        if resp["status"] == "ERROR" and resp["errors"]:
            global_errors.extend(resp["errors"])
        all_results.extend(resp["results"])
        time.sleep(0.4)

    tlds_needed: Set[str] = set()
    for row in all_results:
        if not row.get("is_premium"):
            tld = extract_tld(row["domain"])
            if tld:
                tlds_needed.add(tld.upper())

    tld_pricing_map: Dict[str, Dict[str, Any]] = {}
    if tlds_needed:
        pricing_all = call_users_get_pricing(
            endpoint=endpoint,
            api_user=api_user,
            username=username,
            api_key=api_key,
            client_ip=client_ip,
            timeout=timeout,
            debug=debug
        )
        for tld_code in tlds_needed:
            if tld_code in pricing_all:
                tld_pricing_map[tld_code] = pricing_all[tld_code]

    for row in all_results:
        if not row.get("is_premium"):
            tld = extract_tld(row["domain"])
            code = tld.upper() if tld else None
            info = tld_pricing_map.get(code) if code else None
            if info:
                row["tld_currency"] = info.get("currency")
                row["tld_register_price"] = info.get("register_price")
                row["tld_renew_price"] = info.get("renew_price")
                row["tld_transfer_price"] = info.get("transfer_price")
            else:
                row["tld_currency"] = row["tld_register_price"] = row["tld_renew_price"] = row["tld_transfer_price"] = None
        else:
            row["tld_currency"] = row["tld_register_price"] = row["tld_renew_price"] = row["tld_transfer_price"] = None

    # Write CSV
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    import csv
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "domain", "available", "is_premium",
            "premium_registration_price", "premium_renewal_price", "premium_transfer_price",
            "icann_fee", "eap_fee",
            "tld_currency", "tld_register_price", "tld_renew_price", "tld_transfer_price",
            "note"
        ])
        for r in all_results:
            w.writerow([
                r.get("domain"),
                "true" if r.get("available") else "false",
                "true" if r.get("is_premium") else "false",
                r.get("premium_registration_price") or "",
                r.get("premium_renewal_price") or "",
                r.get("premium_transfer_price") or "",
                r.get("icann_fee") or "",
                r.get("eap_fee") or "",
                r.get("tld_currency") or "",
                r.get("tld_register_price") or "",
                r.get("tld_renew_price") or "",
                r.get("tld_transfer_price") or "",
                r.get("error") or ""
            ])

    if output_json:
        import json
        with output_json.open("w", encoding="utf-8") as jf:
            json.dump({"results": all_results, "errors": global_errors}, jf, ensure_ascii=False, indent=2)

    return output_csv