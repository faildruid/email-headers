#!/usr/bin/env python3
"""
header_report.py
Reads a mail header from 'header.txt' and prints a condensed timeline & routing report.
Usage:
    python header_report.py               # reads ./header.txt
    python header_report.py /path/to/header.txt
"""
import sys
import re
import json
from datetime import datetime
from typing import List, Dict, Optional

DT_PATTERNS = [
    # RFC2822-like dates ending the Received header after a semicolon
    r";\s*(?P<date>[A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+\+\d{4})",
    r";\s*(?P<date>\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+\+\d{4})",
    r";\s*(?P<date>[A-Za-z]{3},\s+[A-Za-z]{3}\s+\d{1,2},\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]{3})",
]

RECEIVED_FROM_PAT = re.compile(
    r"Received:\s*from\s+(?P<from_host>[^\s(]+)(?:\s*\((?P<from_info>[^)]*)\))?",
    re.IGNORECASE | re.DOTALL,
)
RECEIVED_BY_PAT = re.compile(
    r"\)\s*by\s+(?P<by_host>[^\s(]+)",
    re.IGNORECASE | re.DOTALL,
)
RECEIVED_FOR_PAT = re.compile(
    r"\bfor\s+<?(?P<for_rcpt>[^>;]+)>?;",
    re.IGNORECASE | re.DOTALL,
)
IP_PAT = re.compile(r"\[([0-9a-fA-F\.:]+)\]")

AUTH_RES_LINE = re.compile(r"^Authentication-Results:", re.IGNORECASE)
SPF_LINE = re.compile(r"^Received-SPF:", re.IGNORECASE)
DKIM_SIG_LINE = re.compile(r"^DKIM-Signature:", re.IGNORECASE)
ARC_AR_LINE = re.compile(r"^ARC-Authentication-Results:", re.IGNORECASE)
ARC_SEAL_LINE = re.compile(r"^ARC-Seal:", re.IGNORECASE)
ARC_MSGSIG_LINE = re.compile(r"^ARC-Message-Signature:", re.IGNORECASE)
SIEVE_REDIRECT_LINE = re.compile(r"^X-Sieve-Redirected-From:", re.IGNORECASE)
RETURN_PATH_LINE = re.compile(r"^Return-Path:\s*<([^>]+)>", re.IGNORECASE)
FROM_LINE = re.compile(r"^From:\s*(.*)$", re.IGNORECASE)
TO_LINE = re.compile(r"^To:\s*(.*)$", re.IGNORECASE)
SUBJECT_LINE = re.compile(r"^Subject:\s*(.*)$", re.IGNORECASE)
DATE_LINE = re.compile(r"^Date:\s*(.*)$", re.IGNORECASE)


def parse_header_text(text: str) -> Dict:
    """
    Parse the raw email header text into structured fields.
    Unfolds multiline headers and collects multi-valued and single-valued headers.

    Args:
        text (str): The raw header text.

    Returns:
        Dict: Dictionary with 'multi' and 'single' header fields.
    """
    # Unfold headers: join continuation lines
    lines = []
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += " " + line.strip()
        else:
            lines.append(line.rstrip("\r\n"))
    # Collect multi-valued headers in order
    data: Dict[str, List[str]] = {
        "received": [],
        "authentication_results": [],
        "received_spf": [],
        "dkim_signature": [],
        "arc_auth_results": [],
        "arc_seal": [],
        "arc_msgsig": [],
    }
    single: Dict[str, Optional[str]] = {
        "return_path": None,
        "from": None,
        "to": None,
        "subject": None,
        "date": None,
        "sieve_redirected_from": None,
    }
    for ln in lines:
        if ln.lower().startswith("received:"):
            data["received"].append(ln)
        elif AUTH_RES_LINE.match(ln):
            data["authentication_results"].append(ln)
        elif SPF_LINE.match(ln):
            data["received_spf"].append(ln)
        elif DKIM_SIG_LINE.match(ln):
            data["dkim_signature"].append(ln)
        elif ARC_AR_LINE.match(ln):
            data["arc_auth_results"].append(ln)
        elif ARC_SEAL_LINE.match(ln):
            data["arc_seal"].append(ln)
        elif ARC_MSGSIG_LINE.match(ln):
            data["arc_msgsig"].append(ln)
        else:
            m = RETURN_PATH_LINE.match(ln)
            if m:
                single["return_path"] = m.group(1)
                continue
            m = SIEVE_REDIRECT_LINE.match(ln)
            if m:
                single["sieve_redirected_from"] = ln.split(":", 1)[1].strip()
                continue
            m = FROM_LINE.match(ln)
            if m:
                single["from"] = m.group(1).strip()
                continue
            m = TO_LINE.match(ln)
            if m:
                single["to"] = m.group(1).strip()
                continue
            m = SUBJECT_LINE.match(ln)
            if m:
                single["subject"] = m.group(1).strip()
                continue
            m = DATE_LINE.match(ln)
            if m:
                single["date"] = m.group(1).strip()
                continue
    return {"multi": data, "single": single}


def parse_received(rec_line: str) -> Dict:
    """
    Parse a single 'Received' header line into its components.

    Args:
        rec_line (str): The raw 'Received' header line.

    Returns:
        Dict: Parsed components including from_host, by_host, for, date, and IP.
    """
    hop = {
        "raw": rec_line,
        "from_host": None,
        "from_ip": None,
        "by_host": None,
        "for": None,
        "date": None,
    }
    m = RECEIVED_FROM_PAT.search(rec_line)
    if m:
        hop["from_host"] = m.group("from_host")
        info = m.group("from_info") or ""
        ipm = IP_PAT.search(info)
        if ipm:
            hop["from_ip"] = ipm.group(1)
    m = RECEIVED_BY_PAT.search(rec_line)
    if m:
        hop["by_host"] = m.group("by_host")
    m = RECEIVED_FOR_PAT.search(rec_line)
    if m:
        hop["for"] = m.group("for_rcpt").strip()
    for pat in DT_PATTERNS:
        dm = re.search(pat, rec_line)
        if dm:
            hop["date"] = dm.group("date")
            break
    return hop


def summarize_auth(multi: Dict) -> Dict[str, List[str]]:
    """
    Summarize authentication results from parsed header fields.

    Args:
        multi (Dict): Multi-valued header fields.

    Returns:
        Dict[str, List[str]]: SPF, DKIM, DMARC, and ARC authentication results.
    """
    out = {"spf": [], "dkim": [], "dmarc": [], "arc": []}
    # SPF
    for ln in multi["received_spf"]:
        out["spf"].append(ln)
    # DKIM
    for ln in multi["dkim_signature"]:
        out["dkim"].append(ln)
    # DMARC + DKIM in Authentication-Results
    for ln in multi["authentication_results"]:
        if "dmarc=" in ln.lower():
            out["dmarc"].append(ln)
        if "dkim=" in ln.lower():
            out["dkim"].append(ln)
    # ARC
    out["arc"].extend(
        multi["arc_auth_results"] + multi["arc_seal"] + multi["arc_msgsig"]
    )
    return out


def parse_dt(s: str) -> Optional[datetime]:
    # Try a couple of common formats; if fail, return None
    """
    Parse a date string into a datetime object using common formats.

    Args:
        s (str): The date string.

    Returns:
        Optional[datetime]: The parsed datetime object, or None if parsing fails.
    """
    fmts = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%a, %b %d, %Y %H:%M:%S %Z",
    ]
    for f in fmts:
        try:
            return datetime.strptime(s, f)
        except Exception:
            pass
    return None


def main(path: str):
    """
    Main function to parse the email header and print a routing and authentication report.

    Args:
        path (str): Path to the header file.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    parsed = parse_header_text(text)
    multi = parsed["multi"]
    single = parsed["single"]
    received_hops = [parse_received(r) for r in multi["received"]]

    # Maintain natural order as seen in header (top-most first)
    # Build a simple timeline sorted by parsed date if possible
    def dt_key(h):
        dt = parse_dt(h.get("date") or "")
        # put None at end with original index fallback
        return (0, dt) if dt else (1, None)

    received_sorted = sorted(enumerate(received_hops), key=lambda t: dt_key(t[1]))
    # Print report
    print("=== Mail Header Routing Report ===\n")
    if single.get("subject"):
        print(f"Subject: {single['subject']}")
    if single.get("from"):
        print(f"From:    {single['from']}")
    if single.get("to"):
        print(f"To:      {single['to']}")
    if single.get("date"):
        print(f"Date:    {single['date']}")
    if single.get("return_path"):
        print(f"Return-Path at delivery: <{single['return_path']}>")
    if single.get("sieve_redirected_from"):
        print(
            f"Redirected by (X-Sieve-Redirected-From): {single['sieve_redirected_from']}"
        )
    print("\n-- Timeline (earliest to latest by timestamp when available) --")
    for idx, hop in received_sorted:
        ts = hop.get("date") or "unknown-date"
        frm = hop.get("from_host") or "unknown-from"
        ip = f" [{hop['from_ip']}]" if hop.get("from_ip") else ""
        by = hop.get("by_host") or "unknown-by"
        rcpt = f" for {hop['for']}" if hop.get("for") else ""
        print(f"* {ts}: from {frm}{ip} by {by}{rcpt}")
    # Routing chain inference
    print("\n-- Routing chain (inferred) --")
    chain = []
    # Try to capture salient points
    # First hop likely external source -> Titan
    if received_hops:
        first = received_hops[
            -1
        ]  # Many systems append; but we sorted separately. Use original order heuristic
        # Improve: choose hop whose 'from' is not titan and 'by' is titan
        for h in received_hops:
            if (
                h.get("from_host")
                and "paypal" in h["from_host"]
                and h.get("by_host")
                and "titan" in h["by_host"]
            ):
                first = h
                break
        chain.append(f"{first.get('from_host','?')} → {first.get('by_host','?')}")
    # Any redirect indicator
    if single.get("sieve_redirected_from"):
        chain.append(
            f"Redirected by {single['sieve_redirected_from']} (envelope may change)"
        )
    # Outbound titan to inbound titan
    for h in received_hops:
        if h.get("from_host", "").startswith("mail") and ".out.titan.email" in h.get(
            "from_host", ""
        ):
            chain.append(f"{h['from_host']} → {h.get('by_host','?')}")
    # Final accept
    if received_hops:
        last = received_hops[0]
        for h in received_hops:
            if h.get("by_host") and "prod-euc1-smtp-in" in h["by_host"]:
                last = h
        chain.append(f"Final acceptance at {last.get('by_host','?')}")
    print(" → ".join(chain))
    # Authentication summary
    print("\n-- Authentication summary --")
    auth = summarize_auth(multi)

    def short_list(tag, items):
        """
        Print a short summary of authentication results.

        Args:
            tag (str): The authentication type (SPF, DKIM, DMARC).
            items (list): List of authentication result lines.
        """
        if not items:
            print(f"{tag}: (none found)")
            return
        # Try to extract concise status bits
        statuses = []
        for ln in items:
            m = re.search(r"\b(spf|dkim|dmarc)=([a-z]+)", ln, re.IGNORECASE)
            if m:
                statuses.append(f"{m.group(1).upper()} {m.group(2).lower()}")
        if statuses:
            print(f"{tag}: " + ", ".join(dict.fromkeys(statuses)))
        else:
            print(f"{tag}: {len(items)} record(s) found")

    short_list("SPF", auth["spf"])
    short_list("DKIM", auth["dkim"])
    short_list("DMARC", auth["dmarc"])
    if auth["arc"]:
        print("ARC: present")
    else:
        print("ARC: (none found)")
    print("\nReport complete.")
    # Save JSON report
    json_report = {
        "subject": single.get("subject"),
        "from": single.get("from"),
        "to": single.get("to"),
        "date": single.get("date"),
        "return_path": single.get("return_path"),
        "sieve_redirected_from": single.get("sieve_redirected_from"),
        "timeline": received_sorted,
        "routing_chain": chain,
        "authentication": auth,
    }
    with open("report.json", "w", encoding="utf-8") as jf:
        json.dump(json_report, jf, indent=2, ensure_ascii=False, default=str)
    print("\nJSON report saved to report.json")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "header.txt"
    main(path)
