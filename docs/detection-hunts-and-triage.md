# Endpoint Detection: Hunting Queries and Triage

These examples are for an authorized Windows/Splunk lab, not validated production detections. Replace the placeholder `index=wineventlog` and check actual field extraction.

## Failed Windows logons (4625)

```spl
index=wineventlog EventCode=4625 earliest=-24h
| eval principal=coalesce(TargetUserName, Account_Name, user)
| bin _time span=15m
| stats count as failed_logons by _time host principal
| where failed_logons >= 5
| sort - failed_logons
```

Investigate the source address, logon type, host, and whether the failures were expected.

## Successful Windows logons (4624)

```spl
index=wineventlog EventCode=4624 earliest=-24h
| eval principal=coalesce(TargetUserName, Account_Name, user)
| stats count as successful_logons by host principal Logon_Type
| sort - successful_logons
```

## PowerShell process creation (Sysmon Event ID 1)

```spl
index=wineventlog EventCode=1 earliest=-24h
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid
| sort - _time
```

This requires Sysmon Event ID 1 ingestion; adjust the index/sourcetype and fields to match your environment. PowerShell use alone is not evidence of compromise.

## SOC triage workflow

1. Validate the event's source, timestamp, and field mappings.
2. Correlate authentication events and process activity on the affected host.
3. Investigate account, parent process, and known administrative activity.
4. Scope the activity across other authorized endpoints.
5. Record evidence and classify benign, suspicious, or unresolved.
6. Follow an approved incident response process before containment.

## Lab validation checklist

- [ ] Confirm 4624 and 4625 Windows Security events are collected.
- [ ] Confirm Sysmon Event ID 1 is collected.
- [ ] Replace the sample index name with your actual Splunk index.
- [ ] Generate benign test activity on a VM you own or are authorized to test.
- [ ] Verify field names and expected results in Splunk.
- [ ] Record false positives, tuning, and screenshots without secrets.

> This documentation does not assert live validation or a CrowdStrike Falcon integration.
