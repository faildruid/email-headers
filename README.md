# Mail Header Routing Report Tool

## Overview
This tool (`header_report.py`) parses a raw email header (from a file such as `header.txt`) and generates both:

1. A **human-readable report** (printed to the console) summarizing:
   - Message metadata (From, To, Subject, Date, Return-Path)
   - Any **redirects** (`X-Sieve-Redirected-From`)
   - A **timeline of hops** extracted from `Received:` headers
   - An **inferred routing chain**
   - **Authentication results** (SPF, DKIM, DMARC, ARC)

2. A **structured JSON output** (`report.json`) that contains the same parsed data in machine-friendly format for further analysis.

## Usage

### Input
- Save the raw mail header text into a file, for example: `header.txt`

### Run
```bash
python header_report.py            # Reads ./header.txt
python header_report.py myheader.txt   # Reads a custom header file
```

### Output
- Console: Human-readable summary of timeline and routing
- File: `report.json` containing the structured report

## Example Output (console)

```
=== Mail Header Routing Report ===

Subject: Example Subject
From:    Example Sender <sender@example.com>
To:      Example Recipient <recipient@example.com>
Date:    Sat, 16 Aug 2025 03:49:08 -0700
Return-Path at delivery: <redirect@example.com>
Redirected by (X-Sieve-Redirected-From): redirect@example.com

-- Timeline (earliest to latest by timestamp when available) --
* Sat, 16 Aug 2025 10:49:10 +0000: from mx1.example.com [192.0.2.1] by mx2.example.com for recipient@example.com
* Sat, 16 Aug 2025 10:49:12 +0000: from webmail.example.com [198.51.100.2] by smtp.example.com for recipient@example.com
* Sat, 16 Aug 2025 10:49:12 +0000: from mailout.example.com [203.0.113.3] by mx2.example.com for recipient@example.com
* Sat, 16 Aug 2025 10:49:13 +0000: from mx2.example.com by smtp-in.example.com

-- Routing chain (inferred) --
mx1.example.com → mx2.example.com → Redirected by redirect@example.com (envelope may change) → mailout.example.com → mx2.example.com → Final acceptance at smtp-in.example.com

-- Authentication summary --
SPF: SPF pass
DKIM: DKIM pass
DMARC: DMARC pass
ARC: present

Report complete.

JSON report saved to report.json
```

## JSON Output
`report.json` will contain structured data like:

```json
{
  "subject": "Example Subject",
  "from": "Example Sender <sender@example.com>",
  "to": "Example Recipient <recipient@example.com>",
  "date": "Sat, 16 Aug 2025 03:49:08 -0700",
  "return_path": "redirect@example.com",
  "sieve_redirected_from": "redirect@example.com",
  "timeline": [...],
  "routing_chain": [...],
  "authentication": {
    "spf": [...],
    "dkim": [...],
    "dmarc": [...],
    "arc": [...]
  }
}
```

## Requirements
- Python 3.11+
- No external dependencies (standard library only)

## Notes
- I created this for a support ticket I have with my provider, so that i could provide a **forensic analysis** of email headers to trace message flow.
- Works best with headers including `Received`, `Authentication-Results`, `SPF`, `DKIM`, and `DMARC` fields.
