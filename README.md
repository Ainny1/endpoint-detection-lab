# Endpoint Threat Detection & Response Lab

A Windows endpoint monitoring portfolio lab using **Sysmon**, **Windows Security events**, and **Splunk Enterprise**. The examples below are hunting queries for a controlled lab; they are not production-ready correlation searches.

## Architecture

Windows test VM → Windows event collection / Splunk forwarder → Splunk index → SPL hunting queries → analyst triage.

**Prerequisites:** A Windows VM you own or are authorized to administer, Sysmon with a reviewed configuration, Splunk with an appropriate event ingestion path, and permission to collect security logs. Confirm your index and sourcetype names; the examples use `index=wineventlog` as a placeholder.

## Hunting queries

### Repeated failed Windows logons (Security Event ID 4625)

```spl
index=wineventlog EventCode=4625 earliest=-24h
| eval principal=coalesce(TargetUserName, Account_Name, user)
| bin _time span=15m
| stats count as failed_logons by _time host principal
| where failed_logons >= 5
| sort - failed_logons
```

**Analyst check:** Confirm the host, account, logon type, source workstation/IP when available, and whether failures correspond to a known password change or service account.

### Successful Windows logons (Security Event ID 4624)

```spl
index=wineventlog EventCode=4624 earliest=-24h
| eval principal=coalesce(TargetUserName, Account_Name, user)
| stats count as successful_logons by host principal Logon_Type
| sort - successful_logons
```

### PowerShell process creation (Sysmon Event ID 1)

```spl
index=wineventlog EventCode=1 earliest=-24h
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid
| sort - _time
```

Sysmon Event ID 1 provides process creation telemetry **only when Sysmon is installed, configured, and collected**. The query identifies PowerShell execution, which is often legitimate; it does not by itself indicate malicious behavior. Adapt field names to your Splunk add-ons and event extraction.

## SOC triage runbook

1. **Validate the event:** Verify timestamps, data source, event ID, host, and account. Confirm the relevant data is ingested.
2. **Establish context:** Review nearby logons, parent/child processes, process command lines, and approved administration activity.
3. **Scope:** Search for the same account, host, process, or indicators elsewhere in the lab.
4. **Classify:** Record evidence for benign, suspicious, or unresolved findings. Do not equate a detection match with compromise.
5. **Respond with authorization:** Follow the environment's approved incident-response process before containment or remediation.
6. **Document:** Save query, timeframe, observations, false positives, and follow-up actions. Avoid publishing personal data or secrets.

## Testing checklist

- [ ] Confirm Windows Security event collection includes 4624 and 4625.
- [ ] Confirm Sysmon Event ID 1 appears in Splunk.
- [ ] Replace the placeholder index with the actual configured index.
- [ ] Generate benign test logons and approved PowerShell activity on your own lab VM.
- [ ] Compare returned events with Event Viewer and review extraction fields.
- [ ] Record false positives and tune thresholds.

## Existing lab screenshots

### Failed login detection
<img width="800" height="450" alt="Failed login detection lab screenshot" src="https://github.com/user-attachments/assets/e733ef70-f861-43ba-9277-be22d077f05a" />

### PowerShell activity monitoring
<img width="800" height="450" alt="PowerShell activity monitoring lab screenshot" src="https://github.com/user-attachments/assets/84dd66eb-be5f-4566-beb6-9c599ec2b752" />

## Skills demonstrated

Splunk SPL, Windows Security auditing, Sysmon telemetry, endpoint investigation, alert triage, and security documentation.

> This repository demonstrates lab exercises and example detection logic. No claim is made that these queries have been tested in a production environment or integrated with CrowdStrike Falcon.
