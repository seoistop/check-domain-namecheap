#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Namecheap bulk domain checker + pricing.

Features:
- namecheap.domains.check: trạng thái available + giá cho domain premium
- namecheap.users.getPricing: giá TLD (register/renew/transfer) cho domain không premium
- Batch ≤ 50, sandbox/prod, retry nhẹ, debug XML, CSV + JSON

Usage (Production):
  python3 main.py \
    --api-user YOUR_API_USER \
    --username YOUR_USERNAME \
    --api-key YOUR_API_KEY \
    --client-ip YOUR_WHITELISTED_IP \
    --in domains.txt \
    --out results.csv \
    --batch-size 50

Usage (Sandbox + debug):
  python3 main.py \
    --api-user YOUR_SANDBOX_USER \
    --username YOUR_SANDBOX_USER \
    --api-key YOUR_SANDBOX_KEY \
    --client-ip YOUR_WHITELISTED_IP \
    --in domains.txt \
    --out results.csv \
    --batch-size 50 \
    --sandbox \
    --debug
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import requests
import xml.etree.ElementTree as ET

API_PROD = "https://api.namecheap.com/xml.response"
API_SANDBOX = "https://api.sandbox.namecheap.com/xml.response"

# Theo tài liệu Namecheap: tối đa 50 domain / lần gọi check
MAX_PER_CALL = 50


def chunked(seq: List[str], n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def parse_xml_with_ns(xml_text: str, debug: bool = False):
    """
    Parse XML và trả về (root, ns, q) trong đó:
      - root: Element
      - ns: dict namespace nếu có
      - q: callable q(tag) -> pattern ".//nc:{tag}" hoặc ".//{tag}"
    """
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
    """
    Parse response cho namecheap.domains.check
    Return:
      {
        "status": "OK"|"ERROR",
        "results": [
          {
            "domain": "example.com",
            "available": true/false,
            "is_premium": bool,
            "premium_registration_price": "...",
            "premium_renewal_price": "...",
            "premium_transfer_price": "...",
            "icann_fee": "...",
            "eap_fee": "...",
            "error": "..."/None
          }, ...
        ],
        "errors": ["..."]
      }
    """
    out = {"status": "OK", "results": [], "errors": []}
    try:
        root, ns, q = parse_xml_with_ns(xml_text, debug=debug)
    except ET.ParseError as e:
        out["status"] = "ERROR"
        out["errors"].append(f"XML parse error: {e}")
        return out

    # Errors cấp cao
    errors_node = root.find(q("Errors"), ns)
    if errors_node is not None:
        for err in errors_node:
            num = (err.attrib.get("Number") or "").strip()
            txt = (err.text or "").strip()
            msg = f"{num} {txt}".strip() if (num or txt) else "Unknown API error"
            out["errors"].append(msg)

    # Kết quả domain
    for n in root.findall(q("DomainCheckResult"), ns):
        domain = (n.attrib.get("Domain") or "").strip().lower()
        available = (n.attrib.get("Available", "false").lower() == "true")
        is_premium = (n.attrib.get("IsPremiumName", "false").lower() == "true")

        row = {
            "domain": domain,
            "available": available,
            "is_premium": is_premium,
            "premium_registration_price": n.attrib.get("PremiumRegistrationPrice"),
            "premium_renewal_price": n.attrib.get("PremiumRenewalPrice"),
            "premium_transfer_price": n.attrib.get("PremiumTransferPrice"),
            "icann_fee": n.attrib.get("IcannFee"),
            "eap_fee": n.attrib.get("EapFee"),
            "error": n.attrib.get("Description") or None
        }
        out["results"].append(row)

    # Nếu không có kết quả & cũng không có lỗi -> cảnh báo debug
    if not out["results"] and not out["errors"]:
        out["status"] = "ERROR"
        out["errors"].append("No DomainCheckResult found (check namespace/parameters)")
        if debug:
            sys.stderr.write(f"\n===== RAW XML (no results) =====\n{xml_text}\n===============================\n")

    return out


def call_domains_check(
    endpoint: str,
    api_user: str,
    username: str,
    api_key: str,
    client_ip: str,
    domains: List[str],
    timeout: int = 20,
    retry: int = 2,
    backoff: float = 1.5,
    debug: bool = False
) -> Dict[str, Any]:
    """
    Gọi namecheap.domains.check với tối đa 50 domain/lần.
    """
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
        if parsed["status"] == "ERROR" and attempt <= retry:
            # Retry nhẹ nếu do sự cố tạm thời
            time.sleep(backoff ** attempt)
        return parsed


def extract_tld(domain: str) -> Optional[str]:
    """
    Rất đơn giản: lấy phần sau dấu chấm cuối cùng (ví dụ: example.com -> com).
    Lưu ý: Không xử lý multi-level TLD (vd .co.uk).
    Với nhu cầu phổ thông (.com/.net/.org/.xyz/...), cách này đủ dùng.
    """
    if "." not in domain:
        return None
    tld = domain.rsplit(".", 1)[-1].strip().lower()
    if not tld:
        return None
    return tld


def parse_users_get_pricing(xml_text: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Parse response của namecheap.users.getPricing để tạo map:
      {
        "COM": {
          "currency": "USD",
          "register_price": "x.xx",
          "renew_price": "y.yy",
          "transfer_price": "z.zz"
        },
        ...
      }

    Do cấu trúc XML có thể thay đổi, mình parse "rộng":
    - Tìm <Product Name="COM"> ... các node con có attrib Action="REGISTER"/"RENEW"/"TRANSFER"
    - Ưu tiên attrib "Price"; fallback "RegularPrice"
    - Lấy currency từ attrib "Currency" (nếu có) của node giá
    """
    out: Dict[str, Dict[str, Any]] = {}
    try:
        root, ns, q = parse_xml_with_ns(xml_text, debug=debug)
    except ET.ParseError:
        return out

    # Dò tất cả node có attrib Name (sản phẩm TLD)
    # Trên thực tế là <Product Name="COM"> ... </Product>
    for prod in root.findall(".//*[@Name]"):
        name = prod.attrib.get("Name")
        if not name:
            continue
        tld_key = name.strip().upper()

        # Bên trong tìm các node con có Action (REGISTER/RENEW/TRANSFER)
        # Thực tế có thể là <Price Action="REGISTER" Price="..." Currency="USD" ... />
        prices = {"register_price": None, "renew_price": None, "transfer_price": None, "currency": None}

        for node in list(prod.iter()):
            action = node.attrib.get("Action", "").strip().upper() if hasattr(node, "attrib") else ""
            if action in {"REGISTER", "RENEW", "TRANSFER"}:
                price = node.attrib.get("Price") or node.attrib.get("RetailPrice") or node.attrib.get("RegularPrice")
                currency = node.attrib.get("Currency")
                key = {
                    "REGISTER": "register_price",
                    "RENEW": "renew_price",
                    "TRANSFER": "transfer_price"
                }.get(action)

                if key and price:
                    # Ghi nếu chưa có; ưu tiên ghi lần đầu
                    if prices[key] is None:
                        prices[key] = price
                    # Currency: lấy cái đầu tiên gặp
                    if not prices["currency"] and currency:
                        prices["currency"] = currency

        # Chỉ thêm khi có ít nhất một mức giá
        if any([prices["register_price"], prices["renew_price"], prices["transfer_price"]]):
            out[tld_key] = prices

    return out


def call_users_get_pricing(
    endpoint: str,
    api_user: str,
    username: str,
    api_key: str,
    client_ip: str,
    timeout: int = 20,
    retry: int = 1,
    backoff: float = 1.5,
    debug: bool = False
) -> Dict[str, Dict[str, Any]]:
    """
    Gọi namecheap.users.getPricing để lấy bảng giá TLD.
    Không filter quá chặt để tránh "trượt" schema; parse rộng để lôi được các giá quan trọng.
    """
    params = {
        "ApiUser": api_user,
        "ApiKey": api_key,
        "UserName": username,
        "ClientIp": client_ip,
        "Command": "namecheap.users.getPricing",
        # Để trống filter => trả rộng; sau đó tự lọc cần thiết trong parser
        # Nếu muốn, có thể thử thêm:
        # "ProductType": "DOMAIN"
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

        pricing = parse_users_get_pricing(r.text, debug=debug)
        return pricing


def main():
    ap = argparse.ArgumentParser(description="Namecheap bulk domain checker + pricing")
    ap.add_argument("--api-user", required=True, help="Namecheap APIUser (thường giống UserName)")
    ap.add_argument("--username", required=True, help="Namecheap UserName (username đăng nhập)")
    ap.add_argument("--api-key", required=True, help="Namecheap ApiKey")
    ap.add_argument("--client-ip", required=True, help="Whitelisted ClientIp (IP cố định của bạn)")
    ap.add_argument("--in", dest="infile", required=True, help="Input file: mỗi dòng 1 domain (không www.)")
    ap.add_argument("--out", dest="outfile", required=True, help="Output CSV file")
    ap.add_argument("--json", dest="jsonfile", help="Optional JSON output file")
    ap.add_argument("--sandbox", action="store_true", help="Dùng sandbox endpoint")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout (seconds)")
    ap.add_argument("--batch-size", type=int, default=MAX_PER_CALL, help="Domains per API call (<=50)")
    ap.add_argument("--debug", action="store_true", help="In RAW XML khi không có kết quả / lỗi")
    args = ap.parse_args()

    endpoint = API_SANDBOX if args.sandbox else API_PROD

    # Đọc domains
    src = Path(args.infile)
    if not src.exists():
        print(f"⛔ Không tìm thấy file input: {src}", file=sys.stderr)
        sys.exit(2)

    domains: List[str] = []
    for line in src.read_text(encoding="utf-8").splitlines():
        d = line.strip().lower()
        if d and not d.startswith("#"):
            if d.startswith("www."):
                d = d[4:]
            domains.append(d)

    if not domains:
        print("⚠️ Không có domain nào trong input.", file=sys.stderr)
        sys.exit(2)

    # Validate batch size
    if args.batch_size > MAX_PER_CALL or args.batch_size <= 0:
        print(f"⚠️ batch-size không hợp lệ, dùng {MAX_PER_CALL}.", file=sys.stderr)
        args.batch_size = MAX_PER_CALL

    all_results: List[Dict[str, Any]] = []
    global_errors: List[str] = []

    print(f"→ Endpoint : {endpoint}")
    print(f"→ Tổng domain : {len(domains)} | Batch: {args.batch_size}")

    # 1) Gọi check theo batch
    for batch in chunked(domains, args.batch_size):
        resp = call_domains_check(
            endpoint=endpoint,
            api_user=args.api_user,
            username=args.username,
            api_key=args.api_key,
            client_ip=args.client_ip,
            domains=batch,
            timeout=args.timeout,
            debug=args.debug
        )
        if resp["status"] == "ERROR" and resp["errors"]:
            print("⛔ API error:", "; ".join(resp["errors"]), file=sys.stderr)
            global_errors.extend(resp["errors"])
        all_results.extend(resp["results"])
        # Nghỉ nhẹ để tránh rate-limit
        time.sleep(0.4)

    # 2) Chuẩn bị danh sách TLD cần tra giá TLD (chỉ cho domain không premium)
    tlds_needed: Set[str] = set()
    for row in all_results:
        if not row.get("is_premium"):
            tld = extract_tld(row["domain"])
            if tld:
                tlds_needed.add(tld.upper())

    # 3) Gọi users.getPricing 1 lần và parse
    tld_pricing_map: Dict[str, Dict[str, Any]] = {}
    if tlds_needed:
        pricing_all = call_users_get_pricing(
            endpoint=endpoint,
            api_user=args.api_user,
            username=args.username,
            api_key=args.api_key,
            client_ip=args.client_ip,
            timeout=args.timeout,
            debug=args.debug
        )
        # Lọc lại chỉ giữ những TLD thực sự cần
        for tld_code in tlds_needed:
            if tld_code in pricing_all:
                tld_pricing_map[tld_code] = pricing_all[tld_code]

    # 4) Gắn giá TLD vào những domain không premium (nếu lấy được)
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
                row["tld_currency"] = None
                row["tld_register_price"] = None
                row["tld_renew_price"] = None
                row["tld_transfer_price"] = None
        else:
            # Premium: giá cụ thể đã có ở các field premium_*
            row["tld_currency"] = None
            row["tld_register_price"] = None
            row["tld_renew_price"] = None
            row["tld_transfer_price"] = None

    # 5) Ghi CSV
    out_csv = Path(args.outfile)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "domain",
            "available",
            "is_premium",
            "premium_registration_price",
            "premium_renewal_price",
            "premium_transfer_price",
            "icann_fee",
            "eap_fee",
            "tld_currency",
            "tld_register_price",
            "tld_renew_price",
            "tld_transfer_price",
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

    # 6) Ghi JSON (nếu cần)
    if args.jsonfile:
        out_json = Path(args.jsonfile)
        with out_json.open("w", encoding="utf-8") as jf:
            json.dump({"results": all_results, "errors": global_errors}, jf, ensure_ascii=False, indent=2)

    print(f"✅ Done. Đã ghi CSV: {out_csv}")
    if args.jsonfile:
        print(f"🧾 JSON: {args.jsonfile}")
    if global_errors:
        print("⚠️ Một số lỗi:", "; ".join(global_errors))


if __name__ == "__main__":
    main()