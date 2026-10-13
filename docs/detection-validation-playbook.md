# Endpoint Detection Lab — Reproducible Validation Playbook

This document describes **proposed validation exercises**, not verified detection results. Perform them only on systems you own or are explicitly authorized to administer. The existing README describes a Splunk/Sysmon/Windows lab; this playbook makes the evidence and limitations clearer.

## Prerequisites

- Isolated Windows virtual machine with Sysmon configured to log process creation (Event ID 1).
- Splunk with the appropriate Windows Security and Sysmon event ingestion configured.
- A lab account and permission to view Windows Event Logs.
- Document actual index names, sourcetypes, host, time zone, and ingestion delays; do not assume `wineventlog` is the configured index.

## Confirm telemetry before detections

In Splunk, first establish that data exists for the lab host:

```spl
index=* host="<LAB_HOST>" (EventCode=4624 OR EventCode=4625 OR EventCode=1)
| stats count by index sourcetype EventCode
```

Replace `<LAB_HOST>` with your own host. Searching all indexes can be expensive; after discovery, restrict subsequent searches to your configured index.

## Detection 1: Repeated failed logins

Windows Security event 4625 records failed logon attempts. It is a **signal for investigation**, not proof of brute force.

```spl
index="<SECURITY_INDEX>" host="<LAB_HOST>" EventCode=4625
| bin _time span=5m
| stats count as failures values(Account_Name) as accounts by _time host src_ip
| where failures >= 5
| sort - failures
```

Field names vary by Windows TA / ingestion pipeline; `src_ip` and `Account_Name` may be absent. Inspect a raw 4625 event and adapt fields before interpreting results.

**Safe validation:** In an isolated lab, intentionally enter an incorrect password a few times on your own test account, then check whether 4625 events arrive. Avoid account lockouts. Record whether the threshold was reached; do not claim detection success solely from a screenshot.

## Detection 2: Successful logons

```spl
index="<SECURITY_INDEX>" host="<LAB_HOST>" EventCode=4624
| stats count by Logon_Type Account_Name host
```

Review logon type and account context. A 4624 event alone is not evidence of compromise.

## Detection 3: Sysmon process creation

```spl
index="<SYSMON_INDEX>" host="<LAB_HOST>" EventCode=1
| table _time host Image ParentImage CommandLine User
| sort - _time
```

**Safe validation:** Launch a benign program such as Notepad on your own VM and confirm its process-creation event appears. Event ID 1 requires Sysmon process-create logging to be enabled. Do not equate ordinary PowerShell use with malicious behavior.

## Evidence checklist

For each exercise, capture:
1. Lab topology and anonymized VM configuration.
2. Sysmon and Splunk ingestion configuration (with secrets removed).
3. Search query, exact time window, and expected result.
4. Anonymized event sample showing relevant fields.
5. Actual result, including **not detected** outcomes.
6. False-positive considerations, detection gaps, and next steps.

Do not publish passwords, tokens, real patient information, IP addresses of private third parties, or confidential logs.

## Limitations

These searches are **investigation starters**, not production-ready detections. Actual behavior depends on audit policy, Sysmon configuration, event forwarding, index mappings, and test data. No claim of live alerting, brute-force detection efficacy, or incident-response completion is made without reproducible evidence.
