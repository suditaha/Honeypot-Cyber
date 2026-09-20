# Cyber Defense Final Report

This document contains two reports:

1. [Incident Report - IR-2026-0902](#incident-report---ir-2026-0902)
2. [Host DFIR Report - CORP-FIN-03](#host-dfir-report---corp-fin-03)

---

# Incident Report - IR-2026-0902

| Field | Value |
|---|---|
| Host | `corp-fin-03` |
| Analyst | Sid Taha |
| Report date | September 19, 2026 |
| Status | Closed |

> **Time convention:** All times are rendered as shown in the `TimeGenerated` column of the supplied exports (UTC-5). The MySQL `RawData` field carries the same events in UTC (+5-hour offset). Verify the workspace timezone before publishing externally.

## 1. Executive Summary

An internet-reachable MySQL 8.0 instance on the Windows host `corp-fin-03` was compromised on September 2, 2026 at 22:06 by an automated extortion bot that authenticated as `root` from `64.89.163.164`.

Within roughly 50 seconds, the actor read every table in the `cr_corp_01` business database, including a table named `credentials`, dropped four databases, and replaced them with a database named `RECOVER_YOUR_DATA` containing a Bitcoin ransom demand for 0.0109 BTC. The attacker then cleared the MySQL binary logs with `RESET MASTER` and `PURGE BINARY LOGS` to frustrate recovery and forensic replay, and issued a `SHUTDOWN`.

The instance remained exposed after the initial event and was repeatedly re-compromised by additional source IP addresses through September 7, indicating that no effective containment occurred during that window.

## 2. Incident Details

| Field | Value |
|---|---|
| Incident ID | `IR-2026-0902` |
| First malicious activity | Sep 2, 2026 22:06:31 - MySQL authentication failure from `64.89.163.164` |
| Impact action | Sep 2, 2026 22:07:16-22:07:22 |
| Detection date/time | Not determined. No alert, ticket, or detection record was provided. Earliest host-side indication of human review: `mike_admin` opened `mysql_general.log` at Sep 2, 22:43. |
| Reported by | Not determined from available logs |
| Classification | Database extortion / destructive data attack (`T1485` Data Destruction, `T1486`-adjacent extortion, `T1110` Brute Force, `T1070` Indicator Removal) |
| Severity | **High** - confirmed production-data destruction, credential-table access, ransom demand, and repeat compromise over five days |
| Affected asset | `corp-fin-03` - Windows Server Azure VM, MySQL Server 8.0, data directory `C:\ProgramData\MySQL\MySQL Server 8.0\Data` |
| Affected databases | `cr_corp_01`, `sakila`, `world`, `recover_your_data` |
| Accounts involved | MySQL `root` (`root@%`); Windows `administrator`; `mike_admin` (console user, no malicious activity observed) |

### Confirm event coverage

```kusto
union
  (DeviceLogonEvents | extend SourceTable = "DeviceLogonEvents"),
  (DeviceProcessEvents | extend SourceTable = "DeviceProcessEvents"),
  (DeviceFileEvents | extend SourceTable = "DeviceFileEvents"),
  (DeviceRegistryEvents | extend SourceTable = "DeviceRegistryEvents")
| where Timestamp between (datetime(2026-09-02) .. datetime(2026-09-08))
| where DeviceName == "corp-fin-03"
| summarize Events = count() by DeviceName, SourceTable
| order by Events desc
```

> Screenshot in source PDF: asset scope query results.
<img width="649" height="561" alt="Screenshot 2026-09-20 at 4 53 02 PM" src="https://github.com/user-attachments/assets/1018df45-afff-4bc5-9657-4e4e7fd397ad" />


## 3. Impact Assessment

### Confidentiality

**Confirmed access; exfiltration assessed as confirmed.** The actor executed `SELECT * FROM` against every table in `cr_corp_01` (`credentials`, `customers`, `orders`, and `payments`) and the `sakila` and `world` schemas. This was preceded by `SELECT COLUMN_NAME, DATA_TYPE` schema reads and a `SUM(data_length + index_length)` size calculation, a standard mass-copy staging pattern.

`DeviceNetworkEvents` confirms that `mysqld.exe` established an outbound connection to `64.89.163.164` on port `37752` during the compromise window. MySQL returns query results over the client's inbound session, so the queried result sets were transmitted to the attacker. Treat all data in `cr_corp_01` as disclosed.

### Integrity and availability

**Confirmed destruction.** Four databases were dropped. `RESET MASTER` and `PURGE BINARY LOGS TO 'josh-mde-lab-bin.000001'` destroyed the binary logs, removing point-in-time recovery for the affected window. A `SHUTDOWN` command was issued against the instance.

### Business impact

Not determined from available logs. No backup inventory, RTO/RPO, or application dependency map was supplied. The hostname and table names suggest finance-adjacent customer and payment data.

### Enumerate data access and destruction

```kusto
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-03 03:06:00Z) .. datetime(2026-09-03 03:08:00Z))
| where RawData has_any ("SELECT *", "DROP DATABASE", "information_schema.tables")
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

> Screenshot in source PDF: table access and `DROP` sequence.

<img width="779" height="461" alt="Screenshot 2026-09-20 at 4 55 17 PM" src="https://github.com/user-attachments/assets/90c22141-3ff1-418e-b51f-2aa429e2e6d2" />


## 4. Indicators of Compromise

The following values are present in the supplied logs. The tasking IOCs `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99`, `ak+28t2@onionmail.org`, `2no[.]co/2mysql`, and `DATAID 28T2` do **not** appear in this dataset. They are per-victim variants from a different case and should not be published against this incident.

| Type | Indicator | Source |
|---|---|---|
| BTC address | `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` | `MySQLAudit_CL` Queries |
| Contact email | `ak+2nnq3@onionmail.org` | `MySQLAudit_CL` Queries |
| Reference URL | `hxxp://spoo[.]me/mysql` | `MySQLAudit_CL` Queries |
| DATAID | `2NNQ3` | `MySQLAudit_CL` Queries |
| Ransom amount | `0.0109 BTC` | `MySQLAudit_CL` Queries |
| Database artifact | `RECOVER_YOUR_DATA` | `MySQLAudit_CL` Queries |
| Initial DB compromise | `64.89.163.164` | `MySQLAudit_CL` Auth |
| Subsequent successful DB logons | `64.89.163.141`, `64.89.163.158`, `64.89.163.168`, `64.89.163.170`, `64.89.163.179`, `64.89.163.180`, `213.209.159.115`, `136.144.19.189` | `MySQLAudit_CL` Auth |
| DB brute force failures | `213.209.159.115`, `77.90.185.21`, `97.99.88.77`, `34.78.114.97`, `35.240.58.40`, `35.241.246.219`, `34.156.149.204` | `MySQLAudit_CL` Auth |
| Windows administrator logon success | `103.105.213.193`, `39.152.28.80`, `51.89.111.170`, `80.66.83.80`, `36.129.21.114`, `103.105.213.198` | `DeviceLogonEvents` |
| High-volume Windows brute force | `51.89.111.170` (40), `39.152.28.80` (25), `36.129.21.114` (15), `80.94.95.83` (10) | `DeviceLogonEvents` |
| Behavioral | `GRANT CREATE, DROP ON *.* TO root@%`, followed by `REVOKE ALL PRIVILEGES ... FROM root@%` | `MySQLAudit_CL` Queries |
| Behavioral | `RESET MASTER; PURGE BINARY LOGS TO 'josh-mde-lab-bin.000001'` | `MySQLAudit_CL` Queries |
| Behavioral | Oversized `JSON_SCHEMA_VALID` string probe | `MySQLAudit_CL` Queries |
| Network | `mysqld.exe` to `64.89.163.164:37752` | `DeviceNetworkEvents` |

`70.119.84.132` and `10.0.8.5` appear as successful administrator RemoteInteractive logons on Sep 7 at 21:00-21:01 and as failed MySQL root attempts earlier that evening. This pattern is consistent with administrative or investigative access. Confirm against the responder roster before adding either address to a blocklist.

### IOC sweep

```kusto
let ioc_ips = dynamic([
  "64.89.163.164", "64.89.163.141", "64.89.163.158", "64.89.163.168",
  "64.89.163.170", "64.89.163.179", "64.89.163.180", "213.209.159.115",
  "136.144.19.189", "103.105.213.193", "39.152.28.80", "51.89.111.170",
  "80.66.83.80", "36.129.21.114", "103.105.213.198"
]);
DeviceLogonEvents
| where TimeGenerated > ago(30d)
| where RemoteIP in (ioc_ips)
| summarize Attempts = count(),
            Successes = countif(ActionType == "LogonSuccess"),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by RemoteIP, DeviceName, AccountName
| order by Successes desc
```

> Screenshot in source PDF: IOC sweep results.
<img width="833" height="548" alt="Screenshot 2026-09-20 at 4 59 56 PM" src="https://github.com/user-attachments/assets/6bda760c-bd02-47a7-861a-154b2935546e" />

## 5. Timeline

| # | Time (UTC-5) | Event | Source |
|---:|---|---|---|
| 1 | Sep 2, 19:38:29 | First MySQL root authentication failures from `97.99.88.77`; instance confirmed internet-reachable | `MySQLAudit_CL` Auth |
| 2 | Sep 2, 19:40:00-19:40:07 | Windows administrator brute force from `103.105.213.193`; two failures followed by success | `DeviceLogonEvents` |
| 3 | Sep 2, 21:07:18-21:07:25 | Second Windows administrator success from `103.105.213.193` | `DeviceLogonEvents` |
| 4 | Sep 2, 22:06:31 / 22:06:39 | MySQL root failures from `64.89.163.164` using no password | `MySQLAudit_CL` Auth |
| 5 | Sep 2, 22:06:40 | MySQL root success from `64.89.163.164` over TCP/IP | `MySQLAudit_CL` Auth |
| 6 | Sep 2, 22:06:40-22:06:41 | `RECOVER_YOUR_DATA` created; ransom-note rows inserted | `MySQLAudit_CL` Queries |
| 7 | Sep 2, 22:06:42 | `GRANT CREATE, DROP ON *.* TO root@%` | `MySQLAudit_CL` Queries |
| 8 | Sep 2, 22:06:42-22:06:46 | Size calculation and reads of `credentials`, `customers`, `orders`, and `payments` | `MySQLAudit_CL` Queries |
| 9 | Sep 2, 22:06:49-22:07:16 | Full enumeration and read of `sakila` and `world` | `MySQLAudit_CL` Queries |
| 10 | Sep 2, 22:07:16-22:07:17 | Four databases dropped | `MySQLAudit_CL` Queries |
| 11 | Sep 2, 22:07:18-22:07:19 | Ransom database recreated; `RESET MASTER` | `MySQLAudit_CL` Queries |
| 12 | Sep 2, 22:07:20 | Privileges revoked; binary logs purged | `MySQLAudit_CL` Queries |
| 13 | Sep 2, 22:07:21 | `SHUTDOWN` issued | `MySQLAudit_CL` Queries |
| 14 | Sep 2, 22:07:22 | Oversized-string probe issued | `MySQLAudit_CL` Queries |
| 15 | Sep 2, 22:43:15 | `mike_admin` opens `mysql_general.log`; earliest observed human review | `DeviceFileEvents` |
| 16 | Sep 2, 23:15:50-Sep 7, 19:45 | Repeated successful root logons from eight additional IPs; ransom database recreated | Auth and queries |
| 17 | Sep 3-Sep 7 | Continuous Windows administrator brute force from 100+ IPs; further successful logons | `DeviceLogonEvents` |
| 18 | Sep 7, 21:00:44-21:01:46 | RDP sessions from `70.119.84.132` and `10.0.8.5`; assessed as responder access | Logon and process events |

### Timeline queries

```kusto
// Database activity
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-03 00:30:00Z) .. datetime(2026-09-08 02:00:00Z))
| where RawData has_any (
    "LogonSuccess", "DROP DATABASE", "RECOVER_YOUR_DATA",
    "RESET MASTER", "PURGE BINARY", "SHUTDOWN", "GRANT", "REVOKE")
| project TimeGenerated, RawData
| order by TimeGenerated asc

// Host activity
DeviceLogonEvents
| where DeviceName == "corp-fin-03"
| where TimeGenerated between (datetime(2026-09-03 00:00:00Z) .. datetime(2026-09-08 02:00:00Z))
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

## 6. Root Cause and Attack Vector

**Established:** MySQL 8.0 accepted root logins directly from arbitrary internet source addresses over TCP/IP. The account `root@%` existed with privileges the actor could extend. Failed attempts from `64.89.163.164` used no password and the successful connection followed seconds later, indicating a blank or trivially guessable credential.

The fixed sequence of ransom note, database read, database destruction, note recreation, and log purging indicates a commodity mass-scanning extortion bot rather than a targeted intrusion.

### Not determined from available logs

- The exact credential used or whether it was default, reused, blank, or guessed.
- Whether the Windows administrator compromise and MySQL compromise involved the same actor. No source IP overlaps the success sets and no administrator process execution was observed in the relevant window.
- Whether ports `3306` and `3389` were deliberately exposed in the firewall or NSG.
- Any persistence. Registry events showed no actor-created Run key, service, or scheduled task.

### Lateral movement and persistence checks

```kusto
DeviceProcessEvents
| where DeviceName == "corp-fin-03"
| where AccountName == "administrator"
| where TimeGenerated between (datetime(2026-09-03 00:00:00Z) .. datetime(2026-09-08 02:00:00Z))
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

DeviceRegistryEvents
| where DeviceName == "corp-fin-03"
| where RegistryKey has_any (@"CurrentVersion\Run", @"CurrentVersion\RunOnce", @"Services\", "Winlogon")
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessCommandLine,
          RegistryKey, RegistryValueData
```

## 7. Response Actions

**Actions taken:** Not determined from available logs. The instance remained reachable and was re-compromised through September 7. The only confirmed responder activity is the RDP sessions on September 7 at 21:00.

### Containment - immediate

1. Remove `3306/TCP` and `3389/TCP` from internet-facing NSG and Windows Firewall rules. Restrict access to a management subnet or bastion.
2. Isolate `corp-fin-03` in Defender for Endpoint.
3. Disable `root@%`; rotate all MySQL credentials and every credential stored in `cr_corp_01.credentials`.
4. Disable or rename the local Windows administrator account and rotate its password.

### Eradication

5. Rebuild the host rather than attempting in-place cleanup.
6. Preserve the ransom note as evidence, then remove `RECOVER_YOUR_DATA`.

### Recovery

7. Restore `cr_corp_01` from the latest backup preceding Sep 2 at 22:06. Point-in-time recovery is unavailable because the binary logs were purged.
8. Do not pay the ransom.
9. Validate backup integrity and the RPO gap before returning the service to production.

## 8. Evidence

| Artifact | Location / details |
|---|---|
| MySQL auth audit | `MySQLAudit_CL_-_Auth_Logs.csv` - 148 events, Sep 2 19:38 through Sep 7 20:19 |
| MySQL query audit | `MySQLAudit_CL_-_Queries.csv` - 367 events, Sep 2 22:06 through Sep 7 20:19 |
| Windows logons | `DeviceLogonEvents.csv` - 262 events |
| Process execution | `DeviceProcessEvents.csv` - 7,696 events |
| Registry | `DeviceRegistryEvents.csv` - 5,140 events; no adversary artifacts identified |
| File events | `DeviceFileEvents.csv` - 6,184 events; no adversary artifacts identified |
| Ransom note | Two rows reconstructed from audit-log `INSERT` statements |
| MySQL general log | `C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log` |
| Network | `DeviceNetworkEvents` confirms `mysqld.exe` to `64.89.163.164:37752` |
| Missing evidence | `NTANetAnalytics`, NSG flow logs, `my.ini`, backup catalog, Defender incident record |

### Evidence-preservation queries

```kusto
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-03 03:00:00Z) .. datetime(2026-09-03 03:10:00Z))
| project TimeGenerated, DeviceName, ActionType, Username, IpAddress, Query, RawData

DeviceNetworkEvents
| where DeviceName == "corp-fin-03"
| where TimeGenerated between (datetime(2026-09-03 03:06:00Z) .. datetime(2026-09-03 03:15:00Z))
| where RemoteIP !startswith "10."
| summarize Connections = count(),
            Bytes = sum(todouble(column_ifexists("BytesSent", 0)))
  by RemoteIP, RemotePort, InitiatingProcessFileName
| order by Bytes desc
```

## 9. Lessons Learned and Recommendations

| Priority | Recommendation | Rationale |
|---|---|---|
| P1 | Remove database and RDP ports from direct internet exposure; enforce with Azure Policy | Internet exposure made rapid database loss and parallel brute force possible |
| P1 | Eliminate `root@%`; use least-privilege, host-scoped accounts and managed secrets | Actor remotely authenticated as root and self-granted destructive privileges |
| P1 | Alert on destructive database DDL | The instance was repeatedly re-owned before containment |
| P1 | Alert on new external-IP database success and fail-then-success patterns | Would have detected the compromise before the first `DROP` |
| P2 | Ship binary logs off-host and maintain immutable, tested backups | Local recovery logs were destroyed seconds after the database drop |
| P2 | Onboard network telemetry for data-bearing hosts | Network visibility is necessary to scope disclosure confidently |
| P3 | Lock down Windows administration with MFA-gated bastion or JIT access | Multiple successful remote administrator logons remain unexplained |

### Open items

- Confirm `70.119.84.132` and `10.0.8.5` as responder infrastructure.
- Recover `my.ini` and document `bind-address` and exposure configuration.
- Determine who detected the incident and when.

---

# Host DFIR Report - CORP-FIN-03

**Analysis type:** Differential review of two Microsoft Defender for Endpoint live-response investigation packages  
**Host:** `CORP-FIN-03`  
**Operating system:** Windows 11 Pro, 10.0.26200 Build 26200  
**Environment:** Azure Hyper-V VM, WORKGROUP, UTC  
**Machine SID:** `S-1-5-21-3106873643-3680112584-2551108624`  
**Report date:** September 20, 2026

## Executive Summary

| Field | Finding |
|---|---|
| Compromise indicators | **Yes** |
| Confidence | **High** |
| Probable incident type | Opportunistic internet-exposed-host compromise via SMB credential brute force; post-exploitation at discovery stage |
| Attacker present at collection | Yes - external SMB session established and reconnaissance script actively running |
| Earliest confirmed attack activity | 2026-09-06 19:10 UTC, bounded by log retention |

A sustained distributed password-guessing campaign against SMB successfully authenticated as the local `administrator` account from three external IP addresses. At collection time, an external SMB session remained established, the host firewall was disabled on all three profiles, an unexplained local account named `hi` existed with no logon history, and a SYSTEM-level PowerShell port-scanning script was actively executing from `C:\ProgramData`.

## 1. Baseline Determination

| Field | Baseline | Comparison |
|---|---|---|
| Archive | `Pre-Breach_Investigation_Package.zip` | `Post-breach_Investigation_Package.zip` |
| Collection time | `2026-08-25T04:01:49Z` | `2026-09-08T00:45:39Z` |
| MDE collection GUID | `b47cb240-6513-4d5b-b4fe-af9006992bb1` | `ce1427a6-6d20-433d-96b9-cd729aaa3bd7` |
| System boot | `2026-08-24 22:26:18` | `2026-09-07 22:02:33` |

The ordering is based on internal metadata, not filenames. Collection timestamps, distinct GUIDs, identical host identity, and forward-only Defender, Edge, and OneDrive version drift establish that the first package is the baseline.

## 2. Summary Verdict

> **Compromise indicators found: YES. Confidence: HIGH.**

Successful external brute-force authentication as `administrator`, a live attacker SMB session, disabled firewall profiles, an unexplained dormant local account, and an active SYSTEM-level reconnaissance script were all absent from the baseline.

## 3. Notable Deltas

| Category | Change | Assessment | Evidence |
|---|---|---|---|
| Event logs | EID 4625: 0 to 14,468 failed logons | Suspicious | `Security.evtx`, Sep 6 19:10-Sep 8 00:45 |
| Event logs | EID 4740: 0 to 73 lockouts, all targeting `administrator` | Suspicious | `Security.evtx` |
| Event logs | EID 4624 Type 3 success as `administrator` from three external IPs | Critical | Sep 6 21:07, Sep 7 02:08, Sep 8 00:33 |
| Event logs | Five external ANONYMOUS LOGON successes | Suspicious | `Security.evtx` |
| Network | `10.0.0.11:445 <- 103.105.213.198:54912`, ESTABLISHED, PID 4 | Active compromise | `ActiveNetConnections.txt` |
| Network | Three short-lived sessions to `10.0.0.11:3306` from `64.89.163.179` | Suspicious | `ActiveNetConnections.txt` |
| Firewall | `EnableFirewall` changed from `0x1` to `0x0` on all profiles | Suspicious | `Autoruns.txt` |
| Users | Local account `hi`, SID ending `-1001`, added to Users | Suspicious | `LocalGroups.txt` |
| Processes | `portscan.ps1` running as SYSTEM with execution-policy bypass | Suspicious | `Processes.csv` |
| Processes | `script89.ps1` launched by `RunCommandExtension.exe` | Suspicious | `Processes.csv` |
| DNS | `raw.githubusercontent.com` cached | Suspicious | `DnsCache.txt` |
| Administrators | Membership unchanged | Benign | Both `LocalGroups.txt` files |
| Scheduled tasks | Count unchanged; only Microsoft version-path updates | Benign | `ScheduledTasks.csv` |
| Services | 22 per-session service instances removed | Benign | `Services.csv` |
| Processes | User-interactive processes absent after logout | Benign | `QueryUser.txt`, `Processes.csv` |
| Autoruns | User Run values absent because hive was not loaded | Benign | `Autoruns.txt` |
| Event logs | No EID 1102 log-clearing event | No deliberate clearing | Parsed EVTX |

## 4. Prioritized Compromise Indicators and ATT&CK Mapping

### 4.1 Successful brute-force authentication

**ATT&CK:** `T1110.001` - Brute Force: Password Guessing

The post package contains 14,468 EID 4625 network/SMB failures compared with zero in the baseline.

| Source IP | Failed attempts |
|---|---:|
| `175.139.147.237` | 6,630 |
| `103.168.190.59` | 3,344 |
| `36.129.21.114` | 568 |
| `39.152.28.80` | 474 |
| `135.171.80.73` | 144 |
| `104.243.39.112` | 108 |
| `118.193.43.72` | 101 |
| About 100 additional IPs | Remainder |

Three successful Type 3 logons occurred as `administrator`:

| Timestamp (UTC) | Source IP |
|---|---|
| 2026-09-06 21:07:18 | `36.129.21.114` |
| 2026-09-07 02:08:43 | `36.129.21.114` |
| 2026-09-08 00:33:10 | `103.105.213.198` |

### 4.2 Live attacker SMB session

**ATT&CK:** `T1078.003` - Valid Accounts: Local Accounts; `T1021.002` - SMB/Windows Admin Shares

```text
TCP 10.0.0.11:445 <- 103.105.213.198:54912 ESTABLISHED PID 4 (System)
```

The source first produced an ANONYMOUS LOGON success at 00:33:02, followed by a credentialed administrator success eight seconds later. The session remained open at collection time.

### 4.3 Host firewall disabled

**ATT&CK:** `T1562.004` - Impair Defenses: Disable or Modify System Firewall

| Profile | Baseline | Post |
|---|---:|---:|
| Domain | `0x1` | `0x0` |
| Public | `0x1` | `0x0` |
| Standard / Private | `0x1` | `0x0` |

Defaults remained enabled in both packages, while active policy values were disabled. This indicates a runtime policy change rather than an image default.

### 4.4 Unexplained local account `hi`

**ATT&CK:** `T1136.001` - Create Account: Local Account

- SID: `S-1-5-21-3106873643-3680112584-2551108624-1001`
- Absent from baseline; member of Users only
- No profile directory or user hive
- First observed at 2026-09-06 19:21:01 during group enumeration
- Creation event was outside retained Security-log history

The account was created but had not been interactively used, consistent with a dormant re-entry account.

### 4.5 SYSTEM-level reconnaissance

**ATT&CK:** `T1046`, `T1059.001`, `T1562.001`

```text
RunCommandExtension.exe "enable" (PID 7952)
└─ cmd /C powershell -ExecutionPolicy Unrestricted -File script89.ps1 (PID 1392)
   └─ powershell -ExecutionPolicy Unrestricted -File script89.ps1 (PID 4812)
      └─ cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1 (PID 6196)
         └─ powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1 (PID 4380)
```

All processes ran as SYSTEM in session 0 and remained active at collection.

### 4.6 Tool-staging domain

**ATT&CK:** `T1105` - Ingress Tool Transfer

`raw.githubusercontent.com` resolved to `185.199.108.133` through `185.199.111.133` shortly before collection and was absent from the baseline DNS cache.

### 4.7 External MySQL access

**ATT&CK:** `T1046`; possible `T1005`

```text
TCP 10.0.0.11:3306 <- 64.89.163.179:32984 TIME_WAIT
TCP 10.0.0.11:3306 <- 64.89.163.179:33004 TIME_WAIT
TCP 10.0.0.11:3306 <- 64.89.163.179:57880 TIME_WAIT
```

The baseline showed MySQL listening locally with no external peers.

## 5. Probable Incident Type

**Opportunistic internet-exposed-host compromise via SMB credential brute force, captured during post-exploitation discovery.**

The attack was consistent with mass scanning: hundreds of source IPs, generic administrator usernames, and no phishing or user-execution artifacts. Observed post-access activity focused on foothold-building and reconnaissance rather than objective completion.

No host-DFIR evidence showed ransomware deployment, mass encryption, shadow-copy deletion, large outbound transfers, or confirmed data theft. The pattern commonly precedes ransomware, cryptomining, or botnet enrollment, but the final objective cannot be determined from the collected artifacts.

### Unresolved Azure control-plane ambiguity

`script89.ps1` was delivered through the legitimate, Microsoft-signed Azure VM Run Command agent. Two explanations remain possible:

1. An attacker with stolen Azure control-plane credentials pushed commands to the VM.
2. Legitimate administration or tooling coincidentally ran during the compromise.

The bypassed PowerShell chain and ProgramData staging favor the first explanation, but Azure Activity Logs and Run Command invocation records are required to resolve it. This is the highest-priority escalation item.

## 6. IOC List and Hunt Results

| IOC | Type | Context | Baseline | Post |
|---|---|---|---:|---|
| `103.105.213.198` | IPv4 | Live SMB session and administrator success | 0 | Present |
| `36.129.21.114` | IPv4 | Two administrator successes; 568 failures | 0 | EVTX |
| `39.152.28.80` | IPv4 | Anonymous success; 474 failures | 0 | EVTX |
| `175.139.147.237` | IPv4 | 6,630 failures | 0 | EVTX |
| `103.168.190.59` | IPv4 | 3,344 failures | 0 | EVTX |
| `64.89.163.179` | IPv4 | MySQL access | 0 | Present x3 |
| `raw.githubusercontent.com` | Domain | Tool staging | 0 | Present x5 |
| `185.199.108.133`-`185.199.111.133` | IPv4 | Domain resolutions | 0 | Present |
| `C:\programdata\portscan.ps1` | File | SYSTEM recon script | 0 | Present x2 |
| `script89.ps1` | File | Run Command payload | 0 | Present x2 |
| `hi` | Account | Suspected dormant account | 0 | Present |
| SID ending `-1001` | SID | `hi` account | 0 | Present |

Every indicator was absent from the baseline. Brute-force IPs appeared only in UTF-16-encoded `Security.evtx` and were recovered through direct EVTX parsing.

## 7. Gaps and Limitations

1. `Security.txt` was empty in both packages; Security events were parsed directly from `Security.evtx`.
2. The fixed 21 MB Security log wrapped under attack volume. Post-package retention begins at 2026-09-06 19:10, so earlier activity and key creation/change events were lost.
3. No EID 1102 was present; log loss was caused by wrapping, not confirmed deliberate clearing.
4. Command-line auditing was effectively disabled. The live process snapshot was the primary source for execution-chain reconstruction.
5. System and Application event logs were unavailable.
6. The contents of `portscan.ps1` and `script89.ps1` were not collected.
7. The packages contained no file hashes.
8. `pfirewall.log` was unavailable.
9. Browser and credential artifacts were unavailable.
10. `MPSupportFiles.cab` was not expanded and may contain additional Defender history.
11. Null-session enumeration succeeded, but the enumerated data cannot be determined.

## 8. Recommended Immediate Actions

| # | Action | Priority |
|---:|---|---|
| 1 | Isolate the host; an attacker SMB session was live | Immediate |
| 2 | Rotate `administrator`, `mike_admin`, and all host-resident credentials | Immediate |
| 3 | Pull Azure Activity Logs for VM Run Command invocations | Immediate |
| 4 | Disable but preserve the `hi` account | Immediate |
| 5 | Retrieve `portscan.ps1` and `script89.ps1` | High |
| 6 | Re-enable the firewall and remove ports 445, 3389, and 3306 from internet exposure | High |
| 7 | Acquire full disk and memory images before remediation | High |
| 8 | Hunt all Section 6 IOCs across the estate | High |
| 9 | Expand Security logs and enable EID 4688 command lines and PowerShell script-block logging | Medium |
| 10 | Determine whether MySQL holds financial data | Medium |

## Appendix A - Attack Timeline (UTC)

| Time | Event |
|---|---|
| 2026-08-25 04:01:49 | Baseline collection; no inbound connections, firewall enabled, no failed logons |
| 14-day gap | Activity before Sep 6 19:10 not retained |
| 2026-09-06 19:10:59 | Retained Security-log window begins; brute force already underway |
| 2026-09-06 19:18:19 | First administrator account lockout |
| 2026-09-06 19:21:01 | Account `hi` first observed; already existed |
| 2026-09-06 20:56:03 | Anonymous success from `36.129.21.114` |
| 2026-09-06 21:07:18 | First administrator success from `36.129.21.114` |
| 2026-09-06 23:45:04 | Anonymous success from `39.152.28.80` |
| 2026-09-07 02:08:43 | Second administrator success from `36.129.21.114` |
| 2026-09-07 22:02:33 | System reboot |
| 2026-09-08 00:02:40 | Final administrator lockout |
| 2026-09-08 00:33:02 | Anonymous success from `103.105.213.198` |
| 2026-09-08 00:33:10 | Administrator success from `103.105.213.198` |
| 2026-09-08 00:36:47 | Run Command execution chain begins |
| 2026-09-08 00:36:51 | `portscan.ps1` launched as SYSTEM |
| 2026-09-08 00:45:22 | Last failed logon; brute force ongoing |
| 2026-09-08 00:45:39 | Post-breach collection; attacker session and recon script active |

## Appendix B - ATT&CK Technique Summary

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | `T1110.001` | 14,468 EID 4625 Type 3 failures |
| Initial Access | Valid Accounts: Local Accounts | `T1078.003` | Three external administrator successes |
| Lateral Movement | SMB/Admin Shares | `T1021.002` | Established inbound TCP 445 session |
| Defense Evasion | Disable or Modify System Firewall | `T1562.004` | All active firewall profiles disabled |
| Defense Evasion | Disable or Modify Tools | `T1562.001` | PowerShell execution-policy bypass |
| Persistence | Create Account: Local Account | `T1136.001` | Account `hi`, no logon history |
| Execution | PowerShell | `T1059.001` | `script89.ps1` and `portscan.ps1` |
| Discovery | Network Service Discovery | `T1046` | Active `portscan.ps1` process |
| Command and Control | Ingress Tool Transfer | `T1105` | `raw.githubusercontent.com` in DNS cache |

---

*This report was generated from the supplied MySQL, MDE, and live-response artifacts. Conclusions are bounded by the documented evidence gaps, particularly Security-log wrapping and incomplete network telemetry.*
