#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
from typing import Any, Dict, List, Optional


PC_PATTERNS = [
    re.compile(r"\bPC:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b"),
    re.compile(r"\bpc=\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b", re.IGNORECASE),
]


def parse_address_token(token: str, prefer_hex: bool = False) -> Optional[int]:
    token = token.strip()
    if not token:
        return None
    try:
        if token.lower().startswith("0x"):
            return int(token, 16)
        if prefer_hex:
            return int(token, 16)
        if re.search(r"[a-fA-F]", token):
            return int(token, 16)
        return int(token, 10)
    except ValueError:
        return None


def parse_taint_pcs(log_path: str, tainted_only: bool = True) -> List[int]:
    addresses: List[int] = []
    seen = set()

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if tainted_only and "TAINTED" not in line and "TAINTTAG" not in line:
                continue

            hit = None
            for pattern in PC_PATTERNS:
                matched = pattern.search(line)
                if matched:
                    hit = matched.group(1)
                    break

            if hit is None:
                continue

            addr = parse_address_token(hit, prefer_hex=True)
            if addr is None or addr in seen:
                continue

            seen.add(addr)
            addresses.append(addr)

    return addresses


def load_reachable_testcases(result_json_path: str, taint_tag: Optional[str] = None) -> List[Dict[str, Any]]:
    with open(result_json_path, "r", encoding="utf-8", errors="ignore") as file:
        data = json.load(file)

    if not isinstance(data, list):
        return []

    testcases: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        testcase = {
            "api_url": item.get("api_url"),
            "method": item.get("method"),
            "post_payload": item.get("post_payload"),
        }

        payload = testcase.get("post_payload")
        if taint_tag is not None:
            if not isinstance(payload, dict):
                continue
            if taint_tag not in [str(value) for value in payload.values()]:
                continue

        if testcase["api_url"] is None:
            continue

        testcases.append(testcase)

    return testcases


def to_hex_addresses(addresses: List[int]) -> List[str]:
    return [hex(addr) for addr in addresses]


def build_source_entries(
    addresses: List[int],
    testcases: Optional[List[Dict[str, Any]]] = None,
    testcase_strategy: str = "first",
) -> Dict[str, List[Dict[str, Any]]]:
    sources: List[Dict[str, Any]] = []
    testcases = testcases or []

    for idx, addr in enumerate(addresses):
        entry: Dict[str, Any] = {"address": hex(addr)}

        if testcases:
            if testcase_strategy == "first":
                entry["reachable_testcase"] = testcases[0]
            elif testcase_strategy == "round-robin":
                entry["reachable_testcase"] = testcases[idx % len(testcases)]

        sources.append(entry)

    return {"sources": sources}


def write_json(output_path: str, content: Any) -> None:
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(content, file, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert afl-qemu taint log into Source.json for LLMATaint.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--qemu-log", required=True, help="Path to qemu taint/debug log file")
    parser.add_argument(
        "--format",
        choices=["address-list", "sources"],
        default="sources",
        help="Output format: plain address list or {'sources': [...]} format",
    )
    parser.add_argument(
        "--result-json",
        default=None,
        help="Optional result.json from Fuzzer.py for attaching reachable testcase",
    )
    parser.add_argument(
        "--testcase-strategy",
        choices=["first", "round-robin"],
        default="first",
        help="How to attach testcase when --result-json is provided",
    )
    parser.add_argument(
        "--taint-tag",
        default=None,
        help="Optional taint tag filter for testcase payload values, e.g. TAINTTAG",
    )
    parser.add_argument(
        "--include-non-tainted-lines",
        action="store_true",
        help="Also parse lines without TAINTED/TAINTTAG markers",
    )
    parser.add_argument("--output", default="Source.json", help="Output json path")
    args = parser.parse_args()

    addresses = parse_taint_pcs(args.qemu_log, tainted_only=not args.include_non_tainted_lines)

    if args.format == "address-list":
        output_obj: Any = to_hex_addresses(addresses)
    else:
        testcases = []
        if args.result_json:
            testcases = load_reachable_testcases(args.result_json, taint_tag=args.taint_tag)
        output_obj = build_source_entries(addresses, testcases, testcase_strategy=args.testcase_strategy)

    write_json(args.output, output_obj)
    print(f"[+] Parsed taint PCs: {len(addresses)}")
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
