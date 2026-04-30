# Splunk Sourcetype Library

> Generic reference describing the **shape, fields, CIM mappings, and gotchas** of common Splunk sourcetypes — including ones that may not exist in any given environment. Use this as a vendor-agnostic catalogue of what each sourcetype looks like and what to expect from it.
>
> For environment-specific state — which indexes hold what, which CIM data models are populating, which TAs are installed, what's broken or stale — consult the companion `splunk-environment-context.md`, which is generated per deployment.
>
> Caution: CIM mappings documented here describe the **intent** of the source TA. Actual data-model population in any given environment depends on tagging, eventtype chains, field aliasing, and accelerated DM configuration — any of which may or may not be configured correctly. Always validate with `tstats from datamodel=...` rather than assuming the mapping is live.
>
> Organised by source TA / app for ease of extension.

## Contents

- [How CIM works in practice](#how-cim-works-in-practice)
- [Microsoft Windows](#microsoft-windows--splunk_ta_windows)
- [Microsoft Active Directory](#microsoft-active-directory--splunk_ta_microsoft-ad--sa-ldapsearch)
- [Microsoft Sysmon](#microsoft-sysmon--splunk_ta_microsoft_sysmon)
- [Microsoft IIS](#microsoft-iis--splunk_ta_microsoft-iis-splunkbase-3185)
- [Linux / Unix](#linux--unix--splunk_ta_nix)
- [Microsoft Cloud (Azure / Entra ID)](#microsoft-cloud--splunk_ta_microsoft-cloudservices)
- [Microsoft Office 365](#microsoft-office-365--splunk_ta_o365-splunkbase-4055)
- [Microsoft Defender / MS Security stack](#microsoft-defender--ms-security-stack)
- [Amazon Web Services](#amazon-web-services--splunk_ta_aws-splunkbase-1876)
- [Palo Alto Networks](#palo-alto-networks--splunk_ta_paloalto-splunkbase-7523)
- [Cisco ASA / FTD](#cisco-asa--ftd--splunk_ta_cisco-asa-splunkbase-1620)
- [F5 BIG-IP](#f5-big-ip--splunk_ta_f5-big-ip-splunkbase-2680)
- [Lansweeper](#lansweeper--ta-lansweeper-add-on-for-splunk-splunkbase-5418)
- [Check Point](#check-point--splunk_ta_checkpoint_log_exporter-splunkbase-5478)
- [CrowdStrike](#crowdstrike--splunk_ta_crowdstrike)
- [SentinelOne](#sentinelone--sentinelone_app_for_splunk-splunkbase-5433-and-family)
- [Mimecast Email Security](#mimecast-email-security--mimecast_for_splunk--ta-mimecast-for-splunk-splunkbase-4075)
- [Splunk Stream](#splunk-stream--splunk_ta_stream)
- [Zeek (Bro)](#zeek-bro--ta-zeek-af_packet--ta-zeek_kafka--similar)
- [UniFi](#unifi-custom-syslog-ta--ta-unifi_syslog)
- [Splunk Internal](#splunk-internal)

---

## How CIM works in practice

The Common Information Model (CIM) is a set of normalised data models — `Authentication`, `Endpoint`, `Network_Traffic`, `Web`, `Email`, `Change`, `Malware`, etc. — each with a fixed schema of canonical field names. Detections and dashboards written against a CIM data model are portable across vendors: the same SPL works whether the underlying data came from Windows Security, Sysmon, Linux auditd, or CrowdStrike, because each TA aliases its raw fields into the canonical CIM names.

For any sourcetype to actually populate a CIM data model, **a chain of conditions must all hold**. If any link is missing, the data is in Splunk but invisible to CIM-backed searches.

### The tag chain

```
raw events
  → eventtype matches (eventtypes.conf)
    → tags applied (tags.conf)
      → datamodel constraint matches (the DM's root search)
        → CIM-aliased fields available (FIELDALIAS-/EVAL- in props.conf)
```

Each link can break independently:

- **Eventtype not matching** — the TA's `eventtypes.conf` defines a search like `sourcetype=XmlWinEventLog EventCode=4624`; if the sourcetype name on disk doesn't match, the eventtype never fires.
- **Tag missing** — `tags.conf` applies tags (e.g. `authentication`, `success`) to the eventtype; if the eventtype-to-tag mapping is missing, the DM constraint won't match.
- **Constraint mismatch** — the DM's root search typically requires a specific tag combination (e.g. `tag=authentication`); without that tag, the event isn't in scope.
- **Field alias missing** — the event matches the DM but raw field names (`TargetUserName`, `IpAddress`) need to be aliased to canonical CIM names (`user`, `src`); without `FIELDALIAS-`, the DM column is null.

### `cim_<dm>_indexes` macros

Every CIM data model includes a scope macro — `cim_Authentication_indexes`, `cim_Network_Traffic_indexes`, etc. — defined in `Splunk_SA_CIM/macros.conf`. The DM's root search expands the macro to limit which indexes it scans.

A sourcetype that's correctly tagged but lives in an index **not listed in the relevant macro** will not populate the DM. Conversely, a macro that includes too many indexes drags acceleration cost up unnecessarily. Override the macro in a local app, never edit the SA app directly.

### Field aliasing

TAs ship `FIELDALIAS-` definitions in `props.conf` that map raw field names to the canonical CIM names. For example, `Splunk_TA_windows` aliases `TargetUserName` to `user` and `dest_user`, `IpAddress` to `src` and `src_ip`. The library's per-sourcetype "Common fields" tables include a CIM-alias column showing the names a detection would write against.

Aliases are TA-version-dependent. Where a field is canonically aliased by the standard CIM Add-on or the TA documentation, the column shows the alias name. Where the alias is plausible but not universally guaranteed, it is marked `(TA-dependent)`. Where the field has no canonical alias for the relevant data model, the column shows `—`.

### `summariesonly` trade-off

For accelerated data models, `tstats summariesonly=true` reads only the pre-built acceleration summaries — fast, but only covers the buckets that have been summarised (typically recent events within the acceleration backfill window). `summariesonly=false` falls back to raw events for buckets without summaries — slower, but complete.

When validating whether a sourcetype is populating a DM, **always use `summariesonly=false`**: a result of zero with `summariesonly=true` could just mean acceleration hasn't run yet, while zero with `summariesonly=false` means the tag chain or scope macro is genuinely broken.

### Verification one-liner

The canonical "is this sourcetype actually populating the DM" check:

```
| tstats summariesonly=false count from datamodel=<DM> by index, sourcetype
```

If it returns nothing, work back up the chain:

1. Is the index in the `cim_<dm>_indexes` macro?
2. Are events being tagged? `index=<idx> sourcetype=<st> | head 1 | eval tags=tag` — does the expected tag appear?
3. Is the eventtype matching? Search for the TA's eventtype name directly: `eventtype=<expected_eventtype> | head 1`.
4. Are field aliases present? `index=<idx> sourcetype=<st> | head 1 | table user, src, dest, signature` — null where you expected values means the alias is missing.

The CIM mappings documented per-sourcetype in this library are the **intent** of the source TA, not a guarantee. Actual population in any specific environment depends on the tag chain being intact, which is what the companion `splunk-environment-context.md` confirms per deployment.

---

## Microsoft Windows — `Splunk_TA_windows`

### `XmlWinEventLog`
**Format:** XML-formatted Windows Event Log records (modern XML ingestion mode)
**Replaces:** `WinEventLog:*` legacy classic format

**What it covers:**
Anything written to Windows Event Channels — Security, System, Application, PowerShell Operational, Task Scheduler Operational, Windows Defender Operational, Directory Service, DFS Replication, DNS Server, etc. The channel is encoded in the `source` field as `XmlWinEventLog:<ChannelName>`.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `EventCode` | Numeric Windows event ID (e.g. `4624` logon, `4625` failed logon, `4740` lockout, `4688` process create) | `signature_id` |
| `EventID` | Same as EventCode in some pipelines — both are typically present | `signature_id` |
| `Channel` | Source channel (e.g. `Security`, `Microsoft-Windows-PowerShell/Operational`) | — |
| `Computer` | Host where the event was generated | `dest`, `dest_nt_host`, `host` |
| `TargetUserName` | User account affected by the event | `user`, `dest_user` |
| `SubjectUserName` | User account that initiated the event | `src_user` |
| `TargetDomainName` | Domain of the affected user | `user_domain`, `dest_nt_domain` |
| `SubjectDomainName` | Domain of the initiating user | `src_user_domain`, `src_nt_domain` |
| `LogonType` | Numeric logon type (2 = interactive, 3 = network, 10 = remote interactive) | `Authentication_Method` (computed via EVAL-) |
| `IpAddress` | Source IP for network logons; blank for local | `src`, `src_ip` |
| `WorkstationName` | Source hostname for network logons | `src_nt_host` |
| `ProcessName` | Process identifying the event source | `process`, `process_name` |
| `ProcessId` | Process ID | `process_id` |
| `CallerComputerName` | Host initiating the event (often relevant for service / scheduled task events) | `src` (TA-dependent) |

**CIM mapping:**
- `Authentication` (logon channels — 4624/4625/4634/4647/4648/4768/4769/4771/4776)
- `Change` (account/group/policy changes — 4720/4722/4724/4725/4726/4738)
- `Endpoint` (process create 4688, Sysmon-style activity — depends on tagging)
- `Updates` (System channel update events)
- `Malware` (Defender Operational channel — depends on tagging)

**Use cases:**
- Failed logon investigation, password spray, lockouts
- Privilege escalation (group membership changes, special privileges assigned)
- PowerShell command-line auditing
- Scheduled task creation/modification
- Defender detection events

**Gotchas:**
- Field naming differs from the classic `WinEventLog:*` sourcetype — older content may need updating
- PowerShell Operational events are far higher volume than Security — filter aggressively by `source=` or `EventCode=`
- Defender Operational events are in this sourcetype but require correct eventtype/tag chain to populate the `Malware` data model
- XML and JSON variants both use this sourcetype name despite different field-extraction behaviour — environment-dependent

---

### `WindowsFirewallLog`
**Format:** W3C-style text log (`pfirewall.log`)
**Source:** `C:\WINDOWS\System32\LogFiles\Firewall\pfirewall.log`

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `action` | ALLOW / DROP | `action` |
| `protocol` | IP protocol | `transport`, `protocol` |
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` | Source port | `src_port` |
| `dest_port` | Destination port | `dest_port` |
| `size` | Packet size | `bytes` |
| `path` | SEND / RECEIVE | `direction` (TA-dependent) |

**CIM mapping:** `Network_Traffic`

**Gotchas:**
- Disabled by default on Windows hosts — requires GPO/policy to enable
- High volume on multi-homed hosts

---

### `WindowsUpdateLog`
**Format:** Plain text
**Source:** `WindowsUpdateLog` (modern hosts require `Get-WindowsUpdateLog` to materialise)

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `update_id` | Update identifier | `signature_id` |
| `kb_article` | KB article number | `signature` |
| `status` | Install status | `status` |
| `error_code` | Error code on failure | `error_code` (TA-dependent) |

**CIM mapping:** `Updates`

---

### `WinHostMon` (and related Splunk TA Windows scripted inputs)
**Format:** Scripted input from `Splunk_TA_windows` — point-in-time host state snapshots.
**Source field discriminates type:** `service`, `process`, `driver`, `roles`, `networkadapter`, `disk`, `processor`, `computer`, `operatingsystem`

**Note:** This is **state telemetry, not events** — snapshots on a TA-defined schedule, not real-time. Not suitable for security event detection; valuable for inventory and configuration drift.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `Name` | Service / process / object name | `service` (services), `process_name` (processes) |
| `State` | Running / Stopped (services) | `status` |
| `StartMode` | Auto / Manual / Disabled | `start_mode` |
| `PathName` | Executable path | `process_path` |
| `ProcessId` | PID (process variant) | `process_id` |
| `Computer` | Host | `dest`, `host` |

**CIM mapping:** `Endpoint` (Services, Processes — when tagged), `Performance`

**Related sourcetypes from this TA family:**
- `WinRegMon` — registry monitoring (real-time, event-based)
- `WinPrintMon` — print monitoring
- `WinNetMon` — network connection monitoring
- `WinBatchMon` — batch script execution
- `Perfmon:*` — performance counter outputs (CPU, Memory, Disk, Network)

---

## Microsoft Active Directory — `Splunk_TA_microsoft-ad` / `SA-ldapsearch`

### `ActiveDirectory` (admon)
**Format:** Splunk admon AD object events
**Source:** `ActiveDirectory`

**What it covers:** AD object state — users, groups, computers, OUs. Object-level snapshots, not change events.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `objectCategory` | Object class category | — |
| `objectClass` | LDAP object class | — |
| `distinguishedName` | Full DN | `dn` (TA-dependent) |
| `sAMAccountName` | Pre-Win2000 logon name | `user`, `sam_account_name` |
| `userAccountControl` | UAC flag bitmap | — |
| `memberOf` | Group memberships | `groups` (TA-dependent) |
| `whenCreated` | Object creation time | — |
| `whenChanged` | Last modification time | — |

**Use cases:**
- Identifying disabled / locked / privileged accounts
- Group membership baselines
- Identity correlation (mapping SIDs to display names)

**Gotchas:**
- This is **state**, not events. Use `XmlWinEventLog:Security` (4720/4722/4738 etc.) for change-driven detection
- Volume can be very high on first sync; subsequent updates are deltas

---

### `MSAD:NT6:*` family
**Format:** PowerShell scripted inputs (`source=Powershell`)

| Sourcetype | Purpose |
|---|---|
| `MSAD:NT6:Health` | Domain controller health metrics |
| `MSAD:NT6:DNS-Health` | AD-integrated DNS health |
| `MSAD:NT6:DNS-Zone-Information` | DNS zone configuration |
| `MSAD:NT6:SiteInfo` | AD site/subnet topology |

**No CIM mapping** — operational/inventory state. `source=Powershell` is shared across these sourcetypes; always filter by `sourcetype=` rather than `source=`.

---

### `Powershell:ScriptExecutionSummary` / `Powershell:ScriptExecutionErrorRecord`
**Format:** Splunk TA PowerShell input results (custom scripts)
**Use:** Reporting from PowerShell-driven inventory or health checks. Different from `Microsoft-Windows-PowerShell/Operational` events (which are in `XmlWinEventLog`).

**No CIM mapping.**

---

## Microsoft Sysmon — `Splunk_TA_microsoft_sysmon`

> Sysmon (System Monitor) is a Microsoft Sysinternals tool that produces a richly-detailed Windows event stream covering process, network, file, registry, image-load, and named-pipe activity. It runs as a service and writes to its own dedicated event channel.

### Channel and platform notes

**Windows channel:** `Microsoft-Windows-Sysmon/Operational`
**Sourcetype (typical):** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` when ingested through `Splunk_TA_windows`, or `xmlwineventlog` with the channel encoded in `source` when ingested through `Splunk_TA_microsoft_sysmon` directly.

| Platform | Notes |
|---|---|
| Windows (all supported versions) | The TA reads `Microsoft-Windows-Sysmon/Operational` |
| Windows 11 24H2 / Server 2025 | Sysmon ships as a built-in component; channel name is unchanged |
| Linux | Sysmon for Linux writes to `Microsoft-Windows-Sysmon/Operational` via `syslog`/journald rather than ETW. Sourcetype is environment-defined; many deployments use `sysmon_linux` or route through `linux:audit`-style props |

### High-value EventIDs

Sysmon EventIDs are stable across versions. The most useful for security detection:

| EventID | Purpose | Key fields | CIM mapping (intent) | Typical detection use |
|---|---|---|---|---|
| 1 | Process create | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `IntegrityLevel`, `LogonId`, `OriginalFileName` | `Endpoint` (Processes) | LOLBin abuse, suspicious parent-child chains (e.g. office spawning powershell), masquerading via `OriginalFileName` |
| 3 | Network connection | `Image`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `Protocol`, `Initiated`, `User` | `Endpoint` (Network), `Network_Traffic` | C2 callback hunting, beaconing, processes that shouldn't make network connections (e.g. `notepad.exe`) |
| 5 | Process terminated | `Image`, `ProcessGuid`, `ProcessId` | `Endpoint` (Processes) | Pairing with EID 1 to compute process lifetime; quick-exit detection |
| 7 | Image / DLL loaded | `Image`, `ImageLoaded`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` | `Endpoint` (Filesystem) | DLL sideloading, unsigned module loads in trusted processes |
| 8 | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule`, `StartFunction` | `Endpoint` (Processes) | Process injection, thread hijacking |
| 10 | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | `Endpoint` (Processes) | LSASS access patterns (credential dumping); high-volume — filter aggressively |
| 11 | FileCreate | `Image`, `TargetFilename`, `CreationUtcTime` | `Endpoint` (Filesystem) | Dropper detection, persistence file writes (Startup, scheduled task XML, etc.) |
| 12 / 13 / 14 | Registry: object create+delete / value set / key+value rename | `Image`, `TargetObject`, `Details`, `EventType` | `Endpoint` (Registry) | Persistence (Run keys, services), defence evasion (security-software registry tampering) |
| 17 / 18 | Named pipe created / connected | `Image`, `PipeName` | `Endpoint` (Processes) | Cobalt Strike default pipe names, lateral-movement tooling |
| 22 | DnsQuery | `Image`, `QueryName`, `QueryStatus`, `QueryResults` | `Network_Resolution` | DNS-based threat hunting from the endpoint, DGA, suspicious TLDs, DoH/DoT bypass attempts |
| 23 | FileDelete (archived) | `Image`, `TargetFilename`, `Hashes`, `Archived` | `Endpoint` (Filesystem) | Anti-forensics, log tampering. With `ArchiveDirectory` configured, deleted files are preserved |
| 25 | ProcessTampering | `Image`, `Type` (Image is replaced / Process Hollowing) | `Endpoint` (Processes) | Process hollowing, image replacement, Herpaderping-style attacks |
| 26 | FileDeleteDetected | `Image`, `TargetFilename`, `Hashes` | `Endpoint` (Filesystem) | Like EID 23 but without archival — lower-overhead deletion telemetry |
| 29 | FileExecutableDetected | `Image`, `TargetFilename`, `Hashes` | `Endpoint` (Filesystem) | New executable file written to disk — strong dropper/staging signal |

Other useful EIDs not detailed here: 2 (file creation time changed), 4 (Sysmon service state), 6 (driver loaded), 9 (RawAccessRead), 15 (FileCreateStreamHash — ADS detection), 16 (Sysmon config change), 19/20/21 (WMI event filter/consumer/binding — WMI persistence), 24 (clipboard), 27/28 (file-block executable / file-block shredding).

### Common shared fields

Most Sysmon EventIDs share a base set of process-context fields:

| Field | Meaning | CIM alias |
|---|---|---|
| `Image` | Full path to the executable image | `process`, `process_path` |
| `ProcessGuid` | GUID stable across host reboots — primary join key for correlating events from the same process | `process_guid` |
| `ProcessId` | OS PID — not stable across reboots, do not use as a join key on its own | `process_id` |
| `ParentImage` | Parent process image path | `parent_process`, `parent_process_path` |
| `ParentProcessGuid` | Parent process GUID | `parent_process_guid` |
| `ParentProcessId` | Parent PID | `parent_process_id` |
| `CommandLine` | Full command line of the process | `process` (Processes DM also exposes `process_command_line`) |
| `ParentCommandLine` | Full command line of the parent (EID 1 only) | `parent_process` |
| `User` | User context (`DOMAIN\user`) | `user` |
| `Hashes` | Multi-algorithm hash string | `process_hash` (split fields `MD5`/`SHA1`/`SHA256`/`IMPHASH` are TA-dependent) |
| `IntegrityLevel` | `Low` / `Medium` / `High` / `System` | `process_integrity_level` |
| `LogonId` | Hex logon session ID, joinable to Security 4624 events | — |
| `RuleName` | Name of the matching Sysmon config rule | — |
| `UtcTime` | Event timestamp in UTC | — |
| `SourceIp` (EID 3) | Source IP | `src`, `src_ip` |
| `DestinationIp` (EID 3) | Destination IP | `dest`, `dest_ip` |
| `SourcePort` / `DestinationPort` (EID 3) | Source / destination port | `src_port` / `dest_port` |
| `QueryName` (EID 22) | DNS query name | `query` |
| `QueryResults` (EID 22) | Resolved answer | `answer` |
| `TargetFilename` (EID 11/23/26/29) | File path written / deleted | `file_path`, `file_name` |
| `TargetObject` (EID 12/13/14) | Registry key / value path | `registry_path`, `registry_key_name` |
| `Details` (EID 13) | Registry value data | `registry_value_data` |

### CIM mapping and tagging

Sysmon is the canonical population source for the **`Endpoint`** data model on Windows hosts:

| Endpoint sub-DM | Sysmon EIDs |
|---|---|
| Processes | 1, 5, 8, 10, 25 |
| Filesystem | 11, 23, 26, 29, 15 |
| Registry | 12, 13, 14 |
| Network (and `Network_Traffic`) | 3 |
| `Network_Resolution` | 22 |

CIM mapping is **entirely tag-chain-dependent**. The TA ships eventtypes that match on the channel + EventID and apply tags (`process`, `endpoint`, `network`, etc.) — but if those eventtypes aren't enabled, the `XmlWinEventLog`-tagged events still arrive but **don't populate the data model**. The single most common Sysmon problem in Splunk is "data is there, DM is empty."

Validation:
```
| tstats summariesonly=false count from datamodel=Endpoint.Processes by Processes.process_path
```

### Sysmon gotchas

- **Tag chain dependency for Endpoint DM.** Events arriving with `sourcetype=XmlWinEventLog` and the Sysmon channel still need the eventtype/tag chain from `Splunk_TA_microsoft_sysmon` (or equivalent custom config) to populate `Endpoint`. Validate with `tstats`.
- **Sysmon does not produce a clear-log EventID.** If an attacker clears the Sysmon log, no Sysmon event records the clear. The corresponding signal is **Windows Security EID 1102** ("the audit log was cleared"), which lives in the Security channel and requires Security audit logging to be on.
- **`Hashes` field format is concatenated.** Default is a single string like `MD5=...,SHA256=...,IMPHASH=...` — searches looking for a specific hash type need to extract or use `eval` to split. Some props.conf builds split the field into `MD5`, `SHA1`, `SHA256`, `IMPHASH`, but coverage varies.
- **`ProcessGuid` is the correct join key** for chaining Sysmon events from the same process. `ProcessId` is reused as PIDs roll over.
- **EID 3 / EID 22 fields use Sysmon naming, not CIM.** `SourceIp`/`DestinationIp`/`QueryName` rather than `src_ip`/`dest_ip`/`query`. The TA aliases these for CIM, but only if eventtypes are enabled.
- **Channel name in source.** When ingested via `Splunk_TA_windows`, events arrive with `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. When `Splunk_TA_microsoft_sysmon` is the input source, the source field may differ — verify before writing source-pinned detections.
- **If both `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon` are configured to read the Sysmon channel from the same host, the same data appears under two sourcetypes.** Detection authors need to pick one (or write portable detections) — env-context will show which is collecting.
- **Sysmon coverage depends on the running config.** What EIDs are produced and what's filtered is set by the XML config the Sysmon service is running. A tightly-tuned config emits very different telemetry from a maximal config — the same EID may be present in one environment and entirely filtered out in another. Public configs vary widely (SwiftOnSecurity, Olaf Hartong sysmon-modular, ION-Storm).
- **EID 7 (image load) and EID 10 (process access) are typical volume drivers** and are heavily filtered in most production configs.

---

## Microsoft IIS — `Splunk_TA_microsoft-iis` (Splunkbase 3185)

> Multiple sourcetypes exist for IIS W3C logs — pick **one** per source. Mixing index-time and search-time extraction sourcetypes on the same data produces duplicate events.

### `ms:iis:auto` (recommended)
**Format:** W3C extended log file format, auto-detected fields
**Extraction:** Index-time — Splunk's built-in W3C parser reads the `#Fields:` header in each log file
**Source:** Default `C:\inetpub\logs\LogFiles\W3SVC<n>\*.log` (configurable per-site)

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `date`, `time` | Event timestamp (UTC by default) | — |
| `s_sitename` | IIS site identifier (e.g. `W3SVC1`) | `site` |
| `s_computername` | Server name | `dest`, `dest_nt_host` |
| `s_ip` | Server IP | `dest_ip` |
| `s_port` | Server port (use to distinguish HTTP/HTTPS) | `dest_port` |
| `c_ip` | Client IP — typically the proxy/load balancer if behind one | `src`, `src_ip` |
| `cs_username` | Authenticated username (blank for anonymous) | `user` |
| `cs_method` | HTTP method (GET, POST, PUT, etc.) | `http_method` |
| `cs_uri_stem` | Path portion of the URL (without query string) | `uri_path` |
| `cs_uri_query` | Query string | `uri_query` |
| `cs_host` | Host header | `dest`, `site` |
| `cs_user_agent` | User-Agent header | `http_user_agent` |
| `cs_referer` | Referer header | `http_referrer` |
| `cs_bytes` | Bytes received from client | `bytes_in` |
| `sc_bytes` | Bytes sent to client | `bytes_out` |
| `sc_status` | HTTP status code | `status` |
| `sc_substatus` | IIS sub-status (e.g. `401.1`) | — |
| `sc_win32_status` | Underlying Win32 error code | — |
| `time_taken` | Request duration in milliseconds | `response_time` |

**CIM mapping:** `Web`

**Use cases:**
- Web attack pattern detection (SQLi, path traversal, web shells via suspicious URIs)
- Authentication anomalies (high `sc_status=401` rates, unusual `cs_username` values)
- Failed-then-success login patterns
- Scanner/recon activity (bursts of `404`s, unusual user agents)
- Slow-loris / resource exhaustion (high `time_taken` values)
- Cert services auditing (`/CertSrv/*` paths)

**Gotchas:**
- **Multiple `#Fields:` headers in one file break index-time extraction.** Happens when IIS field selection changes mid-rotation.
- **HTTP vs HTTPS isn't in a dedicated field** — distinguish by `s_port` (typically 80 vs 443).
- **`c_ip` may be a load balancer.** True client IP often lives in `X-Forwarded-For` or a custom header — IIS needs to be configured to log it.
- **W3C fields are configurable per-site.** Two IIS sites on the same server can log different fields. Don't assume all fields are present in every event.
- **Log rotation is daily by default** — gaps at midnight UTC are normal during file roll.

---

### `ms:iis:webglobalmodule`
**Format:** Output of `Get-WebGlobalModule` PowerShell cmdlet — IIS module inventory.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `Name` | Module name | — |
| `Image` | Module DLL path | — |
| `PreCondition` | Conditional load expression | — |

**No CIM mapping** — used for inventory and anomaly detection across servers.

**Detection idea:** Compare module sets across servers — modules present on one server but not its peers, or modules added recently, are worth investigating (a common web shell / persistence technique loads as a global module).

---

### Deprecated sourcetypes (still in use in older deployments)

| Sourcetype | Reason for deprecation |
|---|---|
| `ms:iis:default` | Search-time extraction; replaced by `ms:iis:auto` |
| `ms:iis:default:85` | IIS 8.5+ specific variant; replaced by `ms:iis:auto` |
| `ms:iis:splunk` | Splunk-recommended-fields variant; replaced by `ms:iis:auto` |

All three deprecated sourcetypes use search-time extraction defined in `transforms.conf` — a common cause of CIM `Web` data model gaps when the transforms don't match the actual logged fields.

---

## Linux / Unix — `Splunk_TA_nix`

### `linux_secure`
**Format:** RFC 3164 syslog from `/var/log/secure` (RHEL/Fedora) or `/var/log/auth.log` (Debian/Ubuntu)
**Covers:** sshd, sudo, PAM, login, su

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `process` | sshd / sudo / etc. | `app` |
| `user` | Affected user | `user`, `dest_user` |
| `src_ip` | Source IP for remote auth | `src`, `src_ip` |
| `src_port` | Source port | `src_port` |
| `action` | `success` / `failure` | `action` |
| `vendor_action` | Vendor-specific action token | `vendor_action` |

**CIM mapping:** `Authentication`

**Use cases:** SSH brute force, sudo privilege escalation, PAM failures, key-based auth tracking.

**Gotchas:**
- Field extractions depend on TA version — older versions extract less reliably from journald-relayed syslog
- Distro variation: RHEL uses `/var/log/secure`, Debian uses `/var/log/auth.log`
- High signal-to-noise ratio for sshd; sudo less so

---

### `syslog`
**Format:** Generic RFC 3164/5424 syslog
**Source:** `/var/log/messages` typically

**Use:** Catch-all for non-auth Linux daemon logs. Specific apps (e.g. apache, nginx, named) often get their own sourcetype via TA props.

**No fixed CIM mapping** — varies by content.

---

### `systemd:log`
**Format:** journald-extracted structured records

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `_SYSTEMD_UNIT` | Unit name | `service` |
| `MESSAGE` | Log message | — |
| `_PID` | Process ID | `process_id` |
| `_COMM` | Command name | `process_name` |

**Use:** Service start/stop, unit failures, timer execution. Useful for persistence detection (new units, timer abuse).

---

### `dnf:log` / `dnf-too_small` / `dnf.librepo-3` / `dnf.rpm-2`
**Format:** DNF (RHEL/Fedora package manager) transaction logs

**Common sources:** `/var/log/dnf.log`, `/var/log/dnf.librepo.log`, `/var/log/dnf.rpm.log`

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `package` | Package name | `package`, `file_name` (TA-dependent) |
| `version` | Package version | `version` |
| `action` | install / upgrade / erase | `action` |

**Use cases:** Supply-chain auditing — package installs, removes, upgrades. Useful for detecting unexpected software installation.

**Gotcha:** The `*-too_small` suffix is Splunk's small-file auto-classification — these are valid log streams misclassified by file size, not corrupt data.

---

### `hawkey-too_small`
DNF dependency resolver (`hawkey`) log. Low-signal except for package resolution failures. **No CIM mapping.**

---

### `cron-too_small`
**Source:** `/var/log/cron`
**Use:** Cron and anacron job execution. Useful for persistence detection (cron-based malware) and missed-job diagnostics.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `user` | Cron user | `user` |
| `command` | Job command | `process` |

**No CIM mapping** by default.

---

### Linux auditd — `linux:audit`

**Format:** Linux Audit Framework records — key=value pairs, multi-line records sharing a common `msg=audit(<timestamp>:<serial>)` correlation key.
**Source:** `/var/log/audit/audit.log` (auditd) or `/var/log/audit.log` depending on distro.

**Sourcetype variants:** Coverage is split between TAs:
- `Splunk_TA_nix` — supports auditd ingestion but field extractions are limited; many fields land as raw `key=value` text without structured parsing
- **`TA-linux_auditd`** (community / partner) — purpose-built for auditd, much better field extraction, multi-line reassembly, and CIM mapping

Sourcetype name itself is environment-dependent: most commonly `linux:audit` or `auditd`.

#### Format and multi-line structure

A single auditd "event" is typically several records emitted in sequence, all sharing the same `audit(timestamp:serial)` ID. For an `execve` syscall, you might see four records:

```
type=SYSCALL msg=audit(1714502400.123:54321): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=... ppid=1234 pid=5678 auid=1001 uid=1001 euid=0 tty=pts0 comm="sudo" exe="/usr/bin/sudo" key="execve_audit"
type=EXECVE msg=audit(1714502400.123:54321): argc=3 a0="sudo" a1="-i" a2="-u" a3="root"
type=PATH msg=audit(1714502400.123:54321): item=0 name="/usr/bin/sudo" inode=... mode=0104755 ouid=0 ogid=0
type=PATH msg=audit(1714502400.123:54321): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=... mode=0100755 ouid=0 ogid=0
```

Reassembly — joining records by `audit(<ts>:<serial>)` — happens at search time in most TAs. Detections that need full context (especially command lines from EXECVE) typically use `transaction` or `stats values(...) by audit_id` patterns.

#### Common fields

| Field | Meaning | CIM alias |
|---|---|---|
| `type` | Record type — `SYSCALL`, `EXECVE`, `PATH`, `USER_LOGIN`, `USER_AUTH`, `USER_ACCT`, `USER_START`, `USER_END`, `CRED_ACQ`, `CRED_REFR`, `ANOM_*`, `CWD`, `CONFIG_CHANGE`, etc. | `vendor_action` (TA-dependent) |
| `success` | `yes` / `no` — whether the syscall succeeded | `action` (mapped — yes→success, no→failure) |
| `exit` | Syscall exit code (success=0; negative on failure) | `result_code` (TA-dependent) |
| `syscall` | Numeric syscall ID (architecture-dependent — e.g. 59 = `execve` on x86_64, 11 = `execve` on i386) | — |
| `a0` … `a3` | First four syscall arguments (hex) | — |
| `auid` | **Original** login UID before any `sudo`/`su` — accountability field | `user` (TA-dependent), `src_user` |
| `uid` | Real UID at the time of the event | `user` (TA-dependent) |
| `euid` / `suid` / `fsuid` | Effective / saved-set / filesystem UID | — |
| `gid` / `egid` / `sgid` / `fsgid` | Group equivalents | — |
| `pid` | Process ID | `process_id` |
| `ppid` | Parent process ID | `parent_process_id` |
| `comm` | Truncated command name (TASK_COMM_LEN = 16 bytes) | `process_name` |
| `exe` | Full path of the executable (resolved) | `process`, `process_path` |
| `tty` | Controlling terminal (`pts0`, `(none)`, etc.) | — |
| `key` | Audit rule tag — set by `-k` in `auditctl`/`audit.rules` | `signature` (TA-dependent) |
| `proctitle` | Hex-encoded full process command line | `process` (after decoding) |
| `name` (PATH) | File path involved in the syscall | `file_path`, `file_name` |
| `item` (PATH) | Index of the path within the syscall | — |
| `acct` (USER_*) | Account name in an authentication event | `user` |
| `addr` (USER_LOGIN) | Source address for remote logins | `src`, `src_ip` |
| `hostname` (USER_LOGIN) | Source hostname for remote logins | `src_nt_host` |
| `res` (USER_*) | Result — `success` or `failed` | `action` |
| `ses` | Session ID | `session_id` |

#### CIM mapping

Mapping depends on the TA and tag chain — `TA-linux_auditd` is significantly more complete than `Splunk_TA_nix` for auditd specifically.

| Record types | CIM data model | Notes |
|---|---|---|
| `SYSCALL` (with `syscall` matching `execve`) + paired `EXECVE` | `Endpoint` (Processes) | Requires multi-line reassembly to capture full command |
| `USER_LOGIN`, `USER_AUTH`, `USER_ACCT`, `USER_START`, `USER_END`, `CRED_ACQ` | `Authentication` | Distro-dependent — some pieces (`USER_AUTH`) only emit when PAM is configured to log |
| `PATH` (with watch keys), `CONFIG_CHANGE`, `USER_CHAUTHTOK` (passwd change) | `Change` | Watches on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/audit/`, etc. |
| `ANOM_*` (anomaly), `AVC` (SELinux denial) | `Intrusion_Detection` | If the TA tags AVC events; many don't by default |

#### Use cases

- **Privilege escalation detection.** Watch for `setuid` / `setgid` syscalls (`syscall=105`, `106`, `117` on x86_64) where `auid != 0` and `euid == 0` — process gaining root via setuid binary.
- **Command execution auditing.** `execve` with `key=` matching configured execve rule. Combined with `auid`, gives a per-user audit trail across `sudo` boundaries.
- **File integrity monitoring (lightweight).** Watches on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/audit/rules.d/` produce write/delete/attribute-change events.
- **Mount / unmount events.** `syscall=165` (mount), `166` (umount2) — useful for detecting loop-mounted disk images, fileless persistence via ramdisks.
- **Capability changes.** `CAPSET` records when a process's capability set is altered — commonly seen with container escape attempts.
- **Authentication forensics.** `USER_LOGIN` + `USER_AUTH` chain provides the source IP and result for SSH and console logins, and works even when sshd's own logs are tampered with.
- **Anti-forensics detection.** Watches on `/var/log/audit/` itself catch attempts to delete or rotate the audit log.

#### Common audit rules

A representative `/etc/audit/rules.d/audit.rules` for security-focused auditing:

```
# Track all execve calls
-a always,exit -F arch=b64 -S execve -k execve_audit
-a always,exit -F arch=b32 -S execve -k execve_audit

# Watch sensitive identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Watch sshd and pam config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/pam.d/ -p wa -k pam_config

# Detect kernel module loading
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Detect time changes (anti-forensics)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change

# Detect mount events
-a always,exit -F arch=b64 -S mount,umount2 -k mount_events

# Watch the audit log itself
-w /var/log/audit/ -p wa -k audit_log
```

Each `-k` key shows up as the `key` field in resulting events — group detections by key rather than by syscall number for portability.

#### Auditd gotchas

- **Multi-line reassembly is search-time.** Any TA that doesn't pre-merge the SYSCALL/EXECVE/PATH records means detections need to do the join themselves. `transaction startswith="type=SYSCALL"` or `stats values(*) by audit_id` patterns are common.
- **`auid` is the original user before sudo/su.** Critical for accountability — `uid=0` after `sudo` doesn't tell you *who* became root, but `auid=1001` does. Always include `auid` in privilege-escalation detections; never use `uid` alone for "who did this".
- **Architecture-dependent syscall numbers.** A SYSCALL record's `syscall` field is an integer that means different things on x86_64 vs aarch64 vs i386. Detections should filter by `arch` first, or use the symbolic name (`comm`, `key`) rather than the number.
- **`a0`–`a3` are mostly opaque pointers.** For `execve`, the actual command is in the paired EXECVE record's `a0`/`a1`/`a2`/... fields, not the SYSCALL record's.
- **`comm` is truncated to 16 bytes.** Use `exe` for the full path; `comm` is only useful as a quick filter.
- **EXECVE arguments may be hex-encoded.** When command-line arguments contain non-printable bytes or quotes, auditd encodes them as hex. The TA's field extractions decode this for `proctitle` but EXECVE `a*` fields may need manual hex-decoding.
- **`USER_AUTH` requires PAM to be logging.** Default sshd setups vary by distro — some emit `USER_AUTH`, others only emit `USER_LOGIN`.
- **auditd vs systemd-journal.** Some distros route auditd records into the journal as well. If both are ingested, expect duplicate auditd events under different sourcetypes.

---

### `Unix:*` scripted inputs (TA-nix)
TA-nix uses a sourcetype-as-source convention for its scripted inputs.

| Sourcetype | Provides | Notes |
|---|---|---|
| `Unix:Service` | systemd unit inventory | State, not events |
| `Unix:ListeningPorts` | Open TCP/UDP ports per host | Drift candidate |
| `Unix:UserAccounts` | `/etc/passwd` snapshot | Local accounts only |
| `Unix:SSHDConfig` | sshd_config snapshot | Hardening audit |
| `Unix:Update` | Pending package updates | Patch state |
| `Unix:Uptime` | Reboot tracking | |
| `Unix:Version` | OS version / kernel | |
| `netstat` | netstat output | Connection state, not event-based |
| `interfaces` | Network interface config | |
| `package` | Installed package inventory | |
| `time` | Time sync state | NTP drift detection |

**Common fields (varies by sourcetype):**
| Field | Meaning | CIM alias |
|---|---|---|
| `Name` / `service` | Service name | `service` |
| `STATE` | Running / Stopped | `status` |
| `USER` / `user` | Account name | `user` |
| `PORT` / `port` | Listening port | `dest_port` |
| `cmd` / `command` | Command / process | `process_name` |

**CIM mapping:** `Endpoint` (Services, Processes), `Performance`, `Network_Sessions`

**Note:** All scripted inputs are **state telemetry** on a schedule — useful for inventory, drift detection, and baselining; not for real-time security events.

---

### `Linux:SELinuxConfig`
**Source:** `Linux:SELinuxConfiger` (custom source name)
SELinux mode (enforcing/permissive/disabled) and policy snapshot.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `selinux_mode` | enforcing / permissive / disabled | — |
| `policy_version` | Loaded policy version | — |

**No CIM mapping.** Valuable for hardening drift detection.

---

## Microsoft Cloud — `Splunk_TA_microsoft-cloudservices`

### `azure:monitor:aad`
**Format:** JSON via Event Hub
**What it covers:** Microsoft Entra ID (Azure AD) sign-in logs — interactive, non-interactive, service principal, managed identity sign-ins.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `userPrincipalName` | UPN of the signing-in user | `user`, `src_user` |
| `appDisplayName` | Application name | `app` |
| `ipAddress` | Source IP | `src`, `src_ip` |
| `clientAppUsed` | Client app type (Browser, Mobile, etc.) | `user_agent` (TA-dependent) |
| `conditionalAccessStatus` | CA policy outcome | `signature` (TA-dependent) |
| `riskState` | Risk assessment | `risk_score` (TA-dependent) |
| `riskLevelAggregated` | Aggregated risk level | — |
| `location.city` | Geo city | `src_city` |
| `location.countryOrRegion` | Geo country | `src_country` |
| `status.errorCode` | Sign-in error code | `signature_id`, `reason` |
| `status.failureReason` | Failure description | `reason` |

**CIM mapping:** `Authentication` — requires correct eventtype/tag chain to populate the DM

**Use cases:**
- Failed cloud sign-ins, impossible travel, risky sign-ins
- MFA bypass / fatigue patterns
- Service principal abuse
- Conditional Access policy effectiveness

**Gotchas:**
- High latency possible (5–15 min from sign-in to ingest)
- Risk fields (`riskState`, `riskLevelAggregated`) are populated only when Entra ID P2 licensing is present at the source
- Service principal sign-ins have a different shape from interactive user sign-ins — `userPrincipalName` may be empty; use `servicePrincipalName` and `appId`

---

### `azure:monitor:activity`
**Format:** JSON via Event Hub
**What it covers:** Azure subscription audit / activity logs — control-plane operations across Azure resources.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `operationName` | Operation performed (e.g. `Microsoft.Authorization/roleAssignments/write`) | `signature`, `vendor_action` |
| `resourceId` | Full Azure resource ID | `object`, `dest` |
| `caller` | Identity that performed the action | `user`, `src_user` |
| `status` | Started / Succeeded / Failed | `result`, `action` |
| `level` | Informational / Warning / Error | `severity` |
| `category` | Log category | `category` |
| `properties.*` | Operation-specific payload | varies |

**CIM mapping:** `Change`

**Use cases:** Resource creation/modification/deletion, role assignment changes, key vault access.

---

## Microsoft Office 365 — `splunk_ta_o365` (Splunkbase 4055)

> The Office 365 Management Activity API exposes the same audit stream regardless of which TA collects it. Two TAs can both collect from this API — `splunk_ta_o365` and the older O365 modular input in `Splunk_TA_microsoft-cloudservices`. If both are enabled, the same events arrive under both sourcetypes (`o365:management:activity` and `ms:o365:management`) — env-context will show which is configured.

### `o365:management:activity`
**Format:** JSON via Office 365 Management Activity API
**Covers:** Audit logs across Entra ID, SharePoint Online, OneDrive, Exchange Online, plus DLP events.

**Key disambiguator field:** `Workload` — controls which tenant service the event came from. Always filter by this rather than guessing from other fields.

| Workload value | Service |
|---|---|
| `AzureActiveDirectory` | Entra ID sign-ins, directory changes |
| `Exchange` | Mailbox operations (Send, MailItemsAccessed, etc.) |
| `SharePoint` | SharePoint Online file/site activity |
| `OneDrive` | OneDrive for Business file activity |
| `SecurityComplianceCenter` | DLP, audit log search, retention |
| `MicrosoftTeams` | Teams activity (if enabled in tenant audit settings) |

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `Operation` | Operation name (e.g. `UserLoggedIn`, `MailItemsAccessed`) | `signature`, `vendor_action` |
| `UserId` | Acting user UPN | `user`, `src_user` |
| `ClientIP` | Source IP | `src`, `src_ip` |
| `UserAgent` | Client user agent | `http_user_agent` |
| `ResultStatus` | Success / Failed | `action`, `result` |
| `Workload` | Tenant service (see table above) | `app` |
| `RecordType` | Numeric record type | `signature_id` |
| `ObjectId` | Object the operation was performed on | `object`, `dest` |
| `OrganizationId` | Tenant ID | `vendor_account` |

**CIM mapping:**
- `Authentication` — when `Workload=AzureActiveDirectory` and the operation is a sign-in
- `Change` — directory and configuration changes
- `Email` — Exchange operations affecting mail items

**Use cases:**
- Mailbox access auditing (`MailItemsAccessed` for compromise investigations)
- SharePoint/OneDrive data access and exfiltration patterns
- Entra ID admin role assignment, application consent grants
- DLP policy violations
- Teams external sharing and guest access

**Gotchas:**
- **Latency:** typically 30+ minutes from event to ingest — Microsoft-side API delay
- **At-least-once delivery:** the API can return the same event multiple times. Duplicates are expected and may need deduplication in detections
- **Tenant audit must be enabled** — many M365 tenants have unified audit logging disabled by default; absence-of-events is more often a configuration gap than a Splunk issue
- DLP events require additional Entra ID licensing (P1/P2) on the source side

---

### `ms:o365:management`
**Format:** JSON via Office 365 Management Activity API
**Source TA:** `Splunk_TA_microsoft-cloudservices` (modular input variant)

**Same logical data as `o365:management:activity`** — same `Workload` disambiguator, same Operation values, same use cases. Field extractions and aliases differ between the two TAs in places, so detections written against one sourcetype don't always match the other.

**Common fields:** as `o365:management:activity` (above).

**CIM mapping:** `Authentication`, `Change`, `Email` — coverage is generally narrower than `splunk_ta_o365`.

---

### `o365:service:healthIssue`
**Format:** JSON via Microsoft Graph (Service Health API)
**Covers:** Service health issues — incidents and advisories affecting tenant services.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Issue ID | `signature_id` |
| `title` | Issue title | `signature` |
| `service` | Affected service | `app` |
| `status` | Current status | `status` |
| `classification` | Incident / advisory | `category` |
| `impactDescription` | Impact text | — |
| `startDateTime` | Start time | — |
| `endDateTime` | End time | — |

**CIM mapping:** none directly; use as contextual data.

---

### `o365:service:message`
**Format:** JSON via Microsoft Graph
**Covers:** Service messages — announcements, planned changes, and communications from Microsoft about the tenant.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Message ID | — |
| `title` | Message title | — |
| `category` | Message category | `category` |
| `severity` | Severity | `severity` |
| `services[]` | Affected services | `app` |

**CIM mapping:** none.

---

### `o365:graph:messagetrace`
**Format:** JSON via Microsoft Graph Message Trace API
**Covers:** Email message flow — sender, recipient, subject, delivery status, message size, transit.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `senderAddress` | Envelope sender | `src_user`, `sender` |
| `recipientAddress` | Envelope recipient | `recipient` |
| `subject` | Subject | `subject` |
| `status` | Delivery status | `action`, `delivery_status` |
| `messageSize` | Bytes | `size`, `bytes` |
| `received` | Receipt time | — |
| `messageTraceId` | Correlation ID | `message_id` |

**CIM mapping:** `Email`

**Gotchas:**
- This sourcetype does **not** have `Workload` or `app` fields — searches that filter on `Workload=*` will exclude these events
- Older deployments may also see `o365:reporting:messagetrace` from the legacy reporting input — same purpose, different field schema

---

### Legacy / retired sourcetypes (still present in older deployments)
| Sourcetype | Status |
|---|---|
| `o365:service:status` | Retired — use `o365:service:healthIssue` |
| `o365:reporting:messagetrace` | Legacy — use `o365:graph:messagetrace` |

---

## Microsoft Defender / MS Security stack

> Defender alerts and telemetry are exposed across multiple sourcetypes covering different APIs (Microsoft Graph Security alerts vs MDE Advanced Hunting). Several TAs can collect from the same APIs; if more than one is configured, the same data may appear under different sourcetypes — env-context will show which is in use.

### `ms:graph:security:alert` / `ms:graph:security:alertv2`

**Format:** JSON via Microsoft Graph Security API
**Covers:** Aggregated security alerts across the Microsoft Defender stack — Defender for Endpoint, Defender for Cloud Apps (MCAS), Defender for Identity, Defender for Office 365, Entra ID Identity Protection. The `vendorInformation.provider` field disambiguates the source product.

The two sourcetypes correspond to Graph alerts v1 (`/security/alerts`) and v2 (`/security/alerts_v2`). Schemas differ — see Gotchas.

**Common fields (v1 / v2 mostly aligned at top level):**

| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Unique alert ID | `signature_id` |
| `category` | High-level category (`Malware`, `CommandAndControl`, `CredentialAccess`, etc.) | `category` |
| `severity` | `informational` / `low` / `medium` / `high` | `severity` |
| `status` | `newAlert` / `inProgress` / `resolved` (v1); `new` / `inProgress` / `resolved` (v2) | `status` |
| `vendorInformation.provider` | Source product | `vendor_product` |
| `vendorInformation.subProvider` | Sub-source within the vendor | — |
| `title` | Alert title | `signature` |
| `description` | Alert detail | — |
| `userStates[].accountName` | Affected user | `user`, `dest_user` |
| `userStates[].userPrincipalName` | Affected UPN | `user` |
| `hostStates[].netBiosName` | Affected host | `dest`, `dest_nt_host` |
| `hostStates[].fqdn` | Affected FQDN | `dest`, `dest_dns` |
| `hostStates[].privateIpAddress` | Affected host private IP | `dest_ip` |
| `hostStates[].publicIpAddress` | Affected host public IP | `dest_translated_ip` |
| `hostStates[].os` | OS | `os` |
| `fileStates[].name` | File name | `file_name` |
| `fileStates[].path` | File path | `file_path` |
| `fileStates[].fileHash.hashValue` | File hash | `file_hash` |
| `fileStates[].fileHash.hashType` | Hash algorithm | `file_hash_type` |
| `networkConnections[]` | Source/dest IPs and ports involved | `src`, `dest`, `src_port`, `dest_port` |
| `processes[].name` | Process name | `process_name` |
| `processes[].path` | Process path | `process_path` |
| `processes[].commandLine` | Command line | `process` |
| `processes[].processId` | PID | `process_id` |
| `processes[].parentProcessId` | Parent PID | `parent_process_id` |
| `mitreTechniques[]` (v2) | MITRE ATT&CK technique IDs | `mitre_technique_id` |
| `recommendedActions[]` | Suggested remediation steps | — |
| `eventDateTime` | Event timestamp | — |
| `createdDateTime` / `lastModifiedDateTime` | Lifecycle timestamps | — |

**CIM mapping:** `Alerts` (both v1 and v2). When `vendorInformation.provider=IPC` and the alert involves a sign-in risk, also `Authentication`.

**Use cases:**
- Unified alert triage across Defender for Endpoint, Cloud Apps, Identity, Office 365, and Entra ID Identity Protection
- Cross-tool evidence joining (pivot to MDE advanced hunting from the alert)
- MCAS OAuth abuse, anomalous file-share activity
- Defender for Identity DC-side detections (Kerberoasting, golden ticket, DCSync) via `provider=Azure Advanced Threat Protection`

**Gotchas:**
- **Graph alerts v1 vs v2 schema differences.** v2 is not a strict superset. Notable differences: `status` enum values changed (`newAlert` → `new`); `mitreTechniques` is v2-only; some nested arrays (e.g. `processes[]`) restructured. Detections written against v1 will not match v2 events without macro/eventtype abstraction.
- **Latency.** Typical 5–30 minutes from event generation to API availability, sometimes longer for Defender for Cloud Apps.
- **Provider scoping.** `vendorInformation.provider` values include `Microsoft Defender ATP`, `MCAS`, `Azure Advanced Threat Protection`, `IPC`, `Office 365 Security & Compliance` — filter by this rather than treating Graph Security as one homogeneous stream.
- **Tenant context.** Tenant identity is captured in the alert payload but isn't a top-level field — extract from `tenantId` or `aadTenantId` for filtering in multi-tenant collections.

---

### MDE advanced hunting sourcetypes

The Microsoft Defender for Endpoint Advanced Hunting schema — the same schema queryable in the Defender portal via KQL — is exposed via the Defender for Endpoint API. Each table maps to a sourcetype:

| Sourcetype | MDE table | Content |
|---|---|---|
| `MicrosoftDefenderAdvancedHunting:DeviceProcessEvents` | DeviceProcessEvents | Process create/terminate, with rich parent/process metadata and signature info |
| `MicrosoftDefenderAdvancedHunting:DeviceNetworkEvents` | DeviceNetworkEvents | Outbound/inbound connection events from the endpoint sensor |
| `MicrosoftDefenderAdvancedHunting:DeviceFileEvents` | DeviceFileEvents | File create/modify/rename/delete with content hashes |
| `MicrosoftDefenderAdvancedHunting:DeviceRegistryEvents` | DeviceRegistryEvents | Registry key/value create/modify/delete |
| `MicrosoftDefenderAdvancedHunting:DeviceLogonEvents` | DeviceLogonEvents | Endpoint-observed logons (interactive, network, etc.) |
| `MicrosoftDefenderAdvancedHunting:DeviceImageLoadEvents` | DeviceImageLoadEvents | DLL / image loads |
| `MicrosoftDefenderAdvancedHunting:DeviceEvents` | DeviceEvents | Mixed signal events — security telemetry not fitting other tables |
| `MicrosoftDefenderAdvancedHunting:AlertInfo` | AlertInfo | MDE-native alerts |
| `MicrosoftDefenderAdvancedHunting:AlertEvidence` | AlertEvidence | Evidence supporting alerts (process IDs, file hashes, account names) |
| `MicrosoftDefenderAdvancedHunting:EmailEvents` | EmailEvents | Email security telemetry (Defender for Office 365) |
| `MicrosoftDefenderAdvancedHunting:EmailUrlInfo` | EmailUrlInfo | URLs found in emails |
| `MicrosoftDefenderAdvancedHunting:EmailAttachmentInfo` | EmailAttachmentInfo | Email attachments |

**Common fields across the device tables:**
| Field | Meaning | CIM alias |
|---|---|---|
| `Timestamp` | Event time | — |
| `DeviceId` | MDE device ID | `dest_id` (TA-dependent) |
| `DeviceName` | Hostname | `dest`, `dest_nt_host` |
| `ActionType` | Specific action (e.g. `ProcessCreated`) | `action`, `vendor_action`, `signature` |
| `FileName` | File name | `file_name` |
| `FolderPath` | File folder | `file_path` |
| `SHA1` | SHA1 hash | `file_hash` |
| `SHA256` | SHA256 hash | `file_hash` |
| `MD5` | MD5 hash | `file_hash` |
| `ProcessId` | PID | `process_id` |
| `ProcessCommandLine` | Command line | `process` |
| `InitiatingProcessFileName` | Initiating process | `parent_process_name` |
| `InitiatingProcessCommandLine` | Initiating command line | `parent_process` |
| `InitiatingProcessParentFileName` | Grandparent process | — |
| `AccountName` | User account | `user`, `src_user` |
| `AccountDomain` | User domain | `user_domain` |
| `RemoteIP` | Remote IP | `dest_ip` |
| `RemotePort` | Remote port | `dest_port` |
| `LocalIP` | Local IP | `src_ip` |
| `LocalPort` | Local port | `src_port` |

**CIM mapping:**
| Sourcetype | CIM data model |
|---|---|
| `MicrosoftDefenderAdvancedHunting:DeviceProcessEvents` | `Endpoint` (Processes) |
| `MicrosoftDefenderAdvancedHunting:DeviceNetworkEvents` | `Endpoint` (Network), `Network_Traffic` |
| `MicrosoftDefenderAdvancedHunting:DeviceFileEvents` | `Endpoint` (Filesystem) |
| `MicrosoftDefenderAdvancedHunting:DeviceRegistryEvents` | `Endpoint` (Registry) |
| `MicrosoftDefenderAdvancedHunting:DeviceLogonEvents` | `Authentication` |
| `MicrosoftDefenderAdvancedHunting:AlertInfo` | `Alerts`, `Malware` (where applicable) |
| `MicrosoftDefenderAdvancedHunting:AlertEvidence` | `Alerts` |
| `MicrosoftDefenderAdvancedHunting:EmailEvents` | `Email` |

The advanced hunting schema is **far richer than what Sysmon produces** in some respects (signature info, threat intelligence joins, sensor-correlated alerts), but coverage is MDE-only — non-MDE-onboarded hosts produce nothing.

**Gotchas:**
- **Advanced hunting requires E5-tier MDE licensing** (Defender for Endpoint Plan 2, Microsoft 365 E5, or standalone MDE P2). Plan 1 customers can ingest alerts (via Graph Security) but not advanced hunting telemetry.
- **`ActionType` is the primary disambiguator within a table.** `DeviceEvents` in particular contains many sub-event types — always scope detections by `ActionType`.
- **`InitiatingProcess*` is the parent.** Mental model is "process X (`InitiatingProcess*`) caused thing Y (`Process*`/`File*`/etc.)". Don't conflate `InitiatingProcessCommandLine` with the current event's command line.

---

## Amazon Web Services — `Splunk_TA_aws` (Splunkbase 1876)

> Large add-on covering 20+ sourcetypes spanning security, network, web, billing, and inventory data sources.

### Security & audit

#### `aws:cloudtrail`
**The primary AWS security sourcetype.** API call history across all AWS services — every control-plane action and many data-plane actions.

**Format:** JSON

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `eventName` | API action (e.g. `ConsoleLogin`, `AssumeRole`) | `signature`, `vendor_action` |
| `eventSource` | Service (e.g. `iam.amazonaws.com`) | `app` |
| `eventTime` | Event timestamp | — |
| `userIdentity.type` | `IAMUser` / `AssumedRole` / `Root` / `AWSService` / `FederatedUser` | `user_type` |
| `userIdentity.arn` | Full ARN | `user`, `src_user` |
| `userIdentity.userName` | Username component | `user` |
| `sourceIPAddress` | Source IP | `src`, `src_ip` |
| `userAgent` | Client user agent | `http_user_agent`, `user_agent` |
| `awsRegion` | AWS region | `region` |
| `requestParameters.*` | Action-specific request payload | varies |
| `responseElements.*` | Action-specific response payload | varies |
| `errorCode` | Failure code | `result`, `signature_id` |
| `errorMessage` | Failure description | `reason` |

**CIM mapping:** `Authentication` (sign-in events like `ConsoleLogin`, `AssumeRole`), `Change` (resource modifications)

**Use cases:**
- Console login monitoring (especially `ConsoleLogin` with `errorMessage=Failed authentication`)
- IAM role assumption chains (`AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`)
- Privilege escalation patterns (`AttachRolePolicy`, `PutRolePolicy`, `CreateAccessKey`)
- Resource enumeration / reconnaissance (high-volume `Describe*` / `List*` calls)
- Defence evasion (`StopLogging`, `DeleteTrail`, `PutBucketPolicy` on log buckets)

**Gotchas:**
- **`userIdentity` structure varies significantly by identity type** — check `userIdentity.type` first (`IAMUser`, `AssumedRole`, `Root`, `AWSService`, `FederatedUser`). Field paths inside `userIdentity` differ between types.
- **`Root` user activity is rare and high-priority** — nearly always worth alerting on.
- **High-volume in active accounts** — be specific with `eventSource` and time ranges.

#### `aws:cloudwatchlogs:guardduty` / `aws:cloudwatch:guardduty`
GuardDuty findings — managed threat detection. Two sourcetypes for the same logical data delivered via different paths; field names align.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `type` | Finding type (e.g. `UnauthorizedAccess:EC2/SSHBruteForce`) | `signature`, `category` |
| `severity` | Numeric severity | `severity` |
| `service.action.actionType` | Action subtype | `vendor_action` |
| `resource.instanceDetails.instanceId` | Affected EC2 instance | `dest`, `dest_id` |
| `service.evidence.threatIntelligenceDetails[]` | TI matches | `threat_match_field` |

**CIM mapping:** `Alerts`, `Intrusion_Detection`

**Use cases:** EC2 instance compromise, IAM credential exfiltration, S3 anomalies, EKS audit findings.

#### `aws:securityhub:finding` / `ocsf:aws:securityhub:finding`
Security Hub findings — aggregated CSPM and security findings across AWS services.

**Common fields (ASFF):**
| Field | Meaning | CIM alias |
|---|---|---|
| `Title` | Finding title | `signature` |
| `Description` | Finding description | — |
| `Severity.Label` / `Severity.Normalized` | Severity | `severity` |
| `Resources[].Id` | Affected resource ARN | `object`, `dest` |
| `ProductFields.*` | Product-specific fields | — |
| `Compliance.Status` | Compliance status | `compliance` |

**CIM mapping:** `Alerts` (ASFF only — OCSF currently has no CIM mapping)

**Use cases:** Misconfigurations, AWS Foundational Best Practices violations, compliance findings, integrations from third-party tools that publish to Security Hub.

#### `aws:accessanalyzer:finding`
IAM Access Analyzer findings — externally-shared resources detected.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Finding ID | `signature_id` |
| `resource` | Shared resource ARN | `object`, `dest` |
| `principal.*` | External principal | `user`, `src_user` |
| `condition.*` | Sharing condition | — |
| `status` | `ACTIVE` / `ARCHIVED` / `RESOLVED` | `status` |

**CIM mapping:** none

**Use cases:** Detection of S3 buckets, IAM roles, KMS keys, etc. shared outside the trust boundary.

#### `aws:inspector` / `aws:inspector:v2:findings`
Vulnerability and configuration scanning findings.

**Common fields (v2):**
| Field | Meaning | CIM alias |
|---|---|---|
| `findingArn` | Finding ID | `signature_id` |
| `title` | Finding title | `signature` |
| `severity` | Severity | `severity` |
| `packageVulnerabilityDetails.vulnerabilityId` | CVE ID | `cve` |
| `packageVulnerabilityDetails.vulnerablePackages[].name` | Vulnerable package | `bugtraq`, `affected_package` |
| `resources[].id` | Affected resource | `dest` |
| `inspectorScore` | Inspector score | `cvss` |

**CIM mapping:** `Vulnerabilities`, `Inventory`, `Alerts`

**Use cases:** EC2 / ECR / Lambda CVE detection, prioritisation by exploitability score.

#### `aws:config` / `aws:config:notification`
AWS Config — point-in-time and historical resource configuration snapshots.

- `aws:config` — full config snapshots (state)
- `aws:config:notification` — change notifications (events)

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `resourceId` | Resource ID | `object`, `dest` |
| `resourceType` | AWS resource type | `object_category` |
| `configurationItemStatus` | Discovery status | `status` |
| `awsRegion` | Region | `region` |

**CIM mapping:** `Change_Analysis` (deprecated DM — use `Change` from CloudTrail for current detections)

**Use cases:** Configuration drift, "what did this resource look like at time X", compliance baselines.

#### `aws:config:rule`
AWS Config Rules compliance evaluations.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `configRuleName` | Rule name | `signature` |
| `complianceType` | `COMPLIANT` / `NON_COMPLIANT` / `NOT_APPLICABLE` | `compliance` |
| `resourceId` | Evaluated resource | `object`, `dest` |

**CIM mapping:** `Inventory`

**Use cases:** CIS / PCI / NIST framework compliance reporting, drift from approved state.

---

### Network telemetry

#### `aws:cloudwatchlogs:vpcflow` / `aws:transitgateway:flowlogs`
VPC and Transit Gateway flow logs.

**Format:** Space-delimited or JSON depending on flow log version (v2–v5).

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` | Source port | `src_port` |
| `dest_port` | Destination port | `dest_port` |
| `protocol` | IP protocol number | `transport`, `protocol` |
| `action` | ACCEPT / REJECT | `action` |
| `bytes` | Bytes transferred | `bytes` |
| `packets` | Packet count | `packets` |
| `interface_id` | ENI ID | `interface` |
| `account_id` | AWS account | `vendor_account` |
| `vpc_id` (v3+) | VPC ID | `vlan` (TA-dependent) |

**CIM mapping:** `Network_Traffic`

**Use cases:** Lateral movement detection, exfiltration patterns, security group effectiveness validation, suspicious outbound destinations.

**Gotchas:**
- **High volume** in busy VPCs — sampling or aggregation strongly recommended at the search layer
- Flow logs versions vary — older v2 logs lack `vpc_id`, `subnet_id`, `instance_id`
- `aws:cloudwatchlogs:vpcflow:metric` is the metric variant (counts/aggregates), not raw flow records

---

### Web / access logs

| Sourcetype | Source | CIM |
|---|---|---|
| `aws:s3:accesslogs` | S3 bucket access logs | `Web` |
| `aws:cloudfront:accesslogs` | CloudFront edge access logs | none |
| `aws:elb:accesslogs` | Classic ELB / ALB access logs | none |

**Common fields (representative — `aws:s3:accesslogs`):**
| Field | Meaning | CIM alias |
|---|---|---|
| `bucket_name` | S3 bucket | `dest`, `site` |
| `remote_ip` | Source IP | `src`, `src_ip` |
| `requester` | Requesting principal | `user`, `src_user` |
| `operation` | S3 operation | `http_method`, `vendor_action` |
| `key` | Object key | `uri_path` |
| `http_status` | HTTP status | `status` |
| `bytes_sent` | Response bytes | `bytes_out` |
| `total_time` | Request time | `response_time` |

**Use cases:** Web attack patterns (scanners, injection attempts), CDN abuse, S3 object access auditing for sensitive buckets.

---

### Generic / data movers

| Sourcetype | Purpose | Notes |
|---|---|---|
| `aws:s3` | Generic data from S3 buckets | Sourcetype-of-last-resort; prefer specific sourcetypes |
| `aws:s3:csv` | Delimited file data from S3 | CSV/PSV/TSV/space-separated |
| `aws:sqs` | Generic SQS message data | |
| `aws:cloudtrail:lake` | CloudTrail Lake event data | JSON; queryable via Lake API in addition to Splunk |
| `aws:firehose:json` | Generic JSON via Firehose | |
| `aws:firehose:text` | Generic text via Firehose | |
| `aws:firehose:cloudwatchevents` | CloudWatch Events via Firehose | |

These are generic shapes — fields depend on the producer. No fixed CIM mapping.

---

### Operational

#### `aws:cloudwatch`
CloudWatch metrics — performance and operational counters.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `metric_name` | Metric name | — |
| `Namespace` | CloudWatch namespace | — |
| `Dimensions.*` | Metric dimensions | varies |
| `Average` / `Sum` / `Maximum` / `Minimum` | Aggregate values | — |

**CIM mapping:** `Performance`, `Databases`

**Note:** Metrics, not events — better suited to dashboards than security detections.

#### `aws:billing` / `aws:billing:cur`
Billing data and Cost & Usage Reports.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `lineItem/UsageAccountId` | Account | `vendor_account` |
| `lineItem/ProductCode` | Service | `app` |
| `lineItem/UnblendedCost` | Cost | — |

**Use cases:** Cost anomaly detection (often a leading indicator of crypto-mining compromise), budget tracking. **No CIM mapping.**

---

### Inventory / asset context

#### `aws:metadata`
EC2 instance, reserved instance, and EBS snapshot descriptions.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Instance / resource ID | `dest_id` |
| `private_ip_address` | Private IP | `dest_ip` |
| `public_ip_address` | Public IP | `dest_translated_ip` |
| `instance_type` | Instance type | — |
| `tags.*` | Resource tags | varies |

**ES integration:** Feeds the **Assets and Identities** framework — use this to enrich detections with EC2 instance ownership, tags, and account context.

---

### Amazon Security Lake

#### `aws:asl`
Amazon Security Lake data. Format: OCSF (Open Cybersecurity Schema Framework).

**Common fields:** OCSF-defined — `class_uid`, `category_uid`, `time`, `actor.user.name`, `device.hostname`, `src_endpoint.ip`, `dst_endpoint.ip`, etc.

**CIM mapping:** none currently — OCSF has its own schema. Most detections will need OCSF-aware SPL rather than CIM-based, or rely on an OCSF-to-CIM translator app.

**Use cases:** Multi-account security data lake architectures, federated detection across AWS organisations.

---

## Palo Alto Networks — `Splunk_TA_paloalto` (Splunkbase 7523)

> PAN-OS log types are split across multiple sourcetypes by content (traffic, threat, system, etc.). Cloud-delivered variants (Strata Logging Service / formerly Cortex Data Lake) carry the same data shapes under `:cloud`-suffixed sourcetypes. Detection portability across delivery paths is best achieved via eventtypes — particularly `pan_firewall`, which spans both on-prem and cloud delivery for traffic.

### `pan:traffic`
**Format:** CSV syslog
**Covers:** Session traffic events — every connection through the firewall.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` | Source port | `src_port` |
| `dest_port` | Destination port | `dest_port` |
| `transport` | IP protocol | `transport`, `protocol` |
| `action` | Allow / Deny / Drop | `action` |
| `app` | App-ID classification | `app` |
| `bytes_in` | Bytes received | `bytes_in` |
| `bytes_out` | Bytes sent | `bytes_out` |
| `packets` | Total packets | `packets` |
| `session_id` | Session identifier | `session_id` |
| `vsys` | Virtual system | — |
| `src_zone` | Source zone | `src_zone` |
| `dest_zone` | Destination zone | `dest_zone` |
| `rule` | Security policy rule name | `rule`, `signature` |
| `user` | User-ID resolved user | `user`, `src_user` |
| `url_category` | URL category | `category` |
| `session_end_reason` | Why session ended | `reason` |

**Eventtypes:** `pan_traffic`, `pan_traffic_start`, `pan_traffic_end`, `pan_firewall`
**CIM mapping:** `Network_Traffic`

**Use cases:**
- East/west and north/south connection auditing
- Policy effectiveness review (deny patterns, top-talkers)
- App-ID-based unusual application detection
- Session reconstruction for incident timelines

**Gotchas:**
- **Highest-volume PAN-OS log type by far** — be specific with time ranges and zone/rule filters.
- App-ID is dynamic; same session may show as `incomplete` then `ssl` then a specific app as classification proceeds — filter by `session_end_reason` if you only want completed classifications.
- `user` field is populated by User-ID mapping (from `pan:userid` events) — won't be present without User-ID configured.

### `pan:traffic:cloud`
**Format:** JSON via Strata Logging Service API (formerly Cortex Data Lake)
**Covers:** Same traffic content as `pan:traffic` — session events delivered via Palo Alto's cloud log service rather than direct syslog.

**Common fields:** as `pan:traffic` (above) — same logical content. Field-name normalisation is mostly aligned but a small number of cloud-specific fields exist (`log_source_id`, `customer_id`).

**Eventtypes:** `pan_traffic`, `pan_firewall`
**CIM mapping:** `Network_Traffic`

**Detection portability note:** Detections written against `sourcetype=pan:traffic` will not match `pan:traffic:cloud` events. Use `eventtype=pan_firewall` to span both — it's the unifying tag across delivery paths.

---

### `pan:threat`
**Format:** CSV syslog
**Covers:** Threat events — IPS hits, antivirus, anti-spyware, URL filtering, file blocking, WildFire submissions, data filtering.

**Common fields:** all `pan:traffic` fields, plus:
| Field | Meaning | CIM alias |
|---|---|---|
| `threat_id` | Threat signature ID | `signature_id` |
| `threat_name` | Signature name | `signature` |
| `severity` | Threat severity | `severity` |
| `subtype` | `vulnerability` / `virus` / `spyware` / `url` / `file` / `data` / `wildfire` / `email` | `category` |
| `direction` | client-to-server / server-to-client | `direction` |
| `category` | URL / file / threat category | `category` |

**Eventtypes:** `pan_threat`, `pan_file`, `pan_url`, `pan_email`, `pan_data`, `pan_virus`, `pan_spyware`, `pan_firewall`
**CIM mapping:** `Intrusion_Detection`, `Web` (`subtype=url` events)

**Use cases:**
- IPS signature hits and trends
- URL filtering — blocked categories, suspicious destinations
- WildFire verdicts on submitted samples
- Data filtering policy violations

**Gotcha:** Disambiguate threat subtypes via the `subtype` field — `subtype=url` events go to the `Web` data model, others go to `Intrusion_Detection`.

### `pan:threat:cloud`
**Format:** JSON via Strata Logging Service
**Covers:** As `pan:threat` — same logical events, delivered via cloud.

**Common fields / eventtypes / CIM mapping:** as `pan:threat`. Use `eventtype=pan_threat` (or `pan_url` / etc.) for portable detections.

---

### `pan:system`
**Covers:** PAN-OS system events — admin authentication, HA state changes, service restarts, configuration commits.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `event_id` | System event ID | `signature_id` |
| `subtype` | Event category | `category` |
| `severity` | Severity | `severity` |
| `description` | Event detail | — |
| `admin` | Admin user (auth events) | `user`, `src_user` |
| `client` | Admin source IP | `src`, `src_ip` |

**Eventtypes:** `pan_system`, `pan_system_auth`, `pan_system_alert`, `pan_system_change`
**CIM mapping:** `Authentication` (admin auth), `Change`

**Use cases:** Admin login auditing, device health, failover events.

### `pan:system:cloud`
**Format:** JSON via Strata Logging Service. **Same content** as `pan:system`.

---

### `pan:config`
**Covers:** Configuration changes — every commit, every config edit.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `admin` | Admin user | `user`, `src_user` |
| `client` | Admin source IP | `src`, `src_ip` |
| `cmd` | Configuration command | `command`, `vendor_action` |
| `path` | Configuration tree path | `object` |
| `before-change-detail` / `after-change-detail` | Old / new values | `change` |
| `result` | Submitted / Succeeded / Failed | `result` |

**CIM mapping:** `Change`

**Use cases:** Change auditing, unauthorised modification detection, drift from baseline.

### `pan:config:cloud`
**Format:** JSON via Strata Logging Service. **Same content** as `pan:config`.

---

### `pan:userid`
**Covers:** User-ID events — IP-to-user mappings being added, removed, or updated.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `srcuser` | Mapped user | `user`, `src_user` |
| `ip` | Mapped IP | `src`, `src_ip` |
| `event_id` | Mapping change type | `signature_id` |
| `datasource` | Source of mapping (AD, syslog, etc.) | `app` |

**Eventtypes:** `pan_userid`, `pan_userid_login`, `pan_userid_logout`
**CIM mapping:** `Authentication`, `Change`

**Use cases:** Identity attribution for traffic, lateral movement context, AD/LDAP integration health.

---

### `pan:globalprotect`
**Covers:** GlobalProtect VPN events — connection, authentication, posture check.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `srcuser` | VPN user | `user`, `src_user` |
| `public_ip` | Client public IP | `src`, `src_ip` |
| `private_ip` | Assigned tunnel IP | `dest_ip` |
| `event_id` | GP event type | `signature`, `signature_id` |
| `status` | Success / Failure | `action` |
| `reason` | Failure reason | `reason` |

**CIM mapping:** `Authentication`

**Use cases:** VPN authentication monitoring, geographic anomaly detection on remote access, MFA bypass attempts.

### `pan:globalprotect:cloud`
**Format:** JSON via Strata Logging Service. **Same content** as `pan:globalprotect`.

---

### `pan:decryption`
**Covers:** SSL/TLS decryption policy events — what was decrypted, what was bypassed, decryption errors.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` / `dest_ip` | Connection endpoints | `src`/`dest` |
| `app` | App-ID | `app` |
| `tls_version` | TLS protocol version | `ssl_version` |
| `cipher` | Cipher suite | `ssl_cipher` |
| `error` | Decryption error | `reason` |
| `action` | Decrypt / No-decrypt | `action` |

**CIM mapping:** `Network_Traffic`

**Use cases:** Decryption coverage measurement, certificate validation failures, decryption bypass auditing.

### `pan:decryption:cloud`
**Format:** JSON via Strata Logging Service. **Same content** as `pan:decryption`.

---

### `pan:hipmatch`
**Covers:** Host Information Profile match events — endpoint posture results from GlobalProtect clients.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `srcuser` | User | `user` |
| `machinename` | Hostname | `dest`, `dest_nt_host` |
| `hip` | HIP profile name | `signature` |
| `matchtype` | Match category | `category` |

**CIM mapping:** `Intrusion_Detection`

**Use cases:** Endpoint compliance, posture-based access decisions.

---

### `pan:correlation`
**Covers:** PAN-OS automated correlation events — multi-event patterns identified by the firewall itself.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `correlation_object_name` | Correlation name | `signature` |
| `severity` | Severity | `severity` |
| `evidence` | Supporting events | — |

**CIM mapping:** `Alerts`

**Use cases:** Lightweight detection at the firewall layer; useful as an additional signal alongside Splunk-side correlation.

---

### `pan:firewall:cloud`
**Format:** JSON via Strata Logging Service — generic SLS firewall events when the LogType-specific child sourcetype isn't applied.
**Note:** The narrower `pan:traffic:cloud` / `pan:threat:cloud` / etc. sourcetypes are preferred. Plain `pan:firewall:cloud` events are typically a TA configuration gap.

---

### IoT Security

#### `pan:iot_alert`
**Covers:** IoT Security alerts — anomalous device behaviour, vulnerabilities, threats targeting IoT devices.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `alert_type` | Alert category | `category`, `signature` |
| `severity` | Severity | `severity` |
| `device_id` | IoT device | `dest`, `dest_id` |
| `mac` | Device MAC | `dest_mac` |

**CIM mapping:** `Alerts`

#### `pan:pan_iot_device`
**Covers:** IoT device inventory and metadata — discovered devices, classifications, risk scores.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `device_id` | Device ID | `dest_id` |
| `mac` | Device MAC | `dest_mac` |
| `category` | Device category | `category` |
| `vendor` | Manufacturer | `vendor` |
| `model` | Model | `model` |
| `risk_score` | Calculated risk | `risk_score` |

**CIM mapping:** `Inventory`

**Use cases:** OT/IoT asset inventory, risk reporting, asset enrichment for ES Assets & Identities framework.

---

### Data Security (SaaS Security)

#### `pan:data:security`
**Covers:** SaaS data security events — DLP findings, policy violations, sanctioned/unsanctioned app activity.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `policy_name` | DLP policy | `signature` |
| `severity` | Severity | `severity` |
| `user` | Acting user | `user`, `src_user` |
| `app` | SaaS app | `app` |
| `file_name` | File involved | `file_name` |
| `action_taken` | Block / Notify / Allow | `action` |

**Eventtypes:** `pan_data_security_activity`, `pan_data_security_incidents`, `pan_data_security_remediation`, `pan_data_security_policy_violation`
**CIM mapping:** `Alerts`, `Ticket_Management`

**Use cases:** DLP across cloud apps (Office 365, Google Workspace, etc.), shadow IT detection, sensitive data exposure.

---

### Cortex XDR

#### `pan:xdr:incident`
**Covers:** Cortex XDR incidents — Palo Alto's XDR consolidates alerts into incidents.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `incident_id` | Incident ID | `signature_id` |
| `severity` | Severity | `severity` |
| `status` | Open / Resolved | `status` |
| `assigned_user` | Assignee | `owner` |
| `mitre_tactics` | MITRE tactic IDs | `mitre_tactic_id` |
| `mitre_techniques` | MITRE technique IDs | `mitre_technique_id` |

**Eventtypes:** `pan_xdr_incident`, `pan_xdr_incident_detailed`
**CIM mapping:** `Ticket_Management`

#### `pan:xdr:incident:alert`
**Covers:** The individual alerts that make up a Cortex XDR incident.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `alert_id` | Alert ID | `signature_id` |
| `name` | Alert name | `signature` |
| `severity` | Severity | `severity` |
| `category` | Category | `category` |
| `host_name` | Affected host | `dest`, `dest_nt_host` |
| `user_name` | Affected user | `user`, `dest_user` |
| `process_command_line` | Process command line | `process` |
| `action_local_ip` / `action_remote_ip` | Network endpoints | `src_ip` / `dest_ip` |

**CIM mapping:** `Alerts`

**Use cases:** Cross-source alert correlation, integration with Splunk ES findings/risk for unified investigation.

---

## Cisco ASA / FTD — `Splunk_TA_cisco-asa` (Splunkbase 1620)

> Two sourcetypes, identical eventtype mappings. Classification is driven by Cisco's numeric message IDs (e.g. `%ASA-6-302013`) — the TA maps these to eventtypes and CIM data models. Write detections against eventtypes, not message IDs.

### `cisco:asa` / `cisco:ftd`

**Format:** Syslog (RFC 3164) — Cisco's structured format `%ASA-<level>-<message_id>: <message>` where:
- `<level>` is syslog severity 0–7 (0=emergency, 7=debug)
- `<message_id>` is a numeric ID that determines what kind of event it is

`cisco:asa` is for ASA firewalls. `cisco:ftd` is for Firepower Threat Defense devices using the ASA syslog format. **Same field extractions** — the sourcetype split exists to allow filtering and routing.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` / `dest_port` | Ports | `src_port` / `dest_port` |
| `protocol` | IP protocol | `protocol` |
| `transport` | Transport | `transport` |
| `action` | allowed / blocked / built / teardown | `action` |
| `user` | Authenticated user | `user`, `src_user` |
| `vendor_action` | Vendor-specific action token | `vendor_action` |
| `message_id` | Cisco message ID | `signature_id` |
| `severity_id` | Severity 0–7 | `severity` |
| `bytes` | Connection bytes | `bytes` |
| `duration` | Connection duration | `duration` |
| `tunnel_protocol` | VPN tunnel protocol | — |
| `xlate_src_ip` / `xlate_dest_ip` | NAT-translated addresses | `src_translated_ip` / `dest_translated_ip` |

---

### Eventtypes and CIM mapping

| Eventtype | Purpose | CIM data model | Example message IDs |
|---|---|---|---|
| `cisco_authentication` | User authentication events (success/failure) | `Authentication` | 113008, 113005, 113004, 605004, 605005, 713198, 716039, 109031 |
| `cisco_authentication_privileged` | Privileged auth (enable mode etc.) | `Authentication` | 113021 |
| `cisco_connection` | TCP/UDP connection build/teardown, ACL hits | `Network_Traffic` | 302013/14 (TCP build/teardown), 302015/16 (UDP), 106023 (ACL deny), 106100 |
| `cisco_asa_audit_change` | Admin / audit configuration changes | `Change` | 111001, 111004, 111009, 111010, 502101–502112, 505015 |
| `cisco_asa_configuration_change` | Configuration commits | `Change` | 113003, 502101–502112, 504001–504002, 505001–505009 |
| `cisco_asa_network_sessions` | Network session events (NAT etc.) | `Network_Sessions` | 609001/2, 716058/9, 722028–722037, 725003, 725007, 751025 |
| `cisco_vpn_start` | VPN session start | `Network_Sessions` | 113039, 602303, 716001, 722022, 722033, 722034 |
| `cisco_vpn_end` | VPN session end | `Network_Sessions` | 113019, 602304, 716002, 722023 |
| `cisco_vpn` | VPN session general | `Network_Sessions` | 713228, 722051 |
| `cisco_network_session_start` | Network session start | `Network_Sessions` | 302022, 302024, 302026 |
| `cisco_network_session_end` | Network session end | `Network_Sessions` | 302023, 302025 |
| `cisco_asa_certificates` | Certificate validation events | `Certificates` | 717009, 717022, 717027–717029, 717037 |
| `cisco_intrusion` | IPS events (ASA inspection) | `Intrusion_Detection` | 106016, 106017, 400032, 430001 |
| `cisco_asa_alert` | Alert-class events | `Alerts` | 110003, 212011, 405001 |

---

### Use cases

- **VPN auditing:** AnyConnect session lifecycle (722xxx series), failed VPN authentication patterns, geographic anomalies in remote access
- **ACL effectiveness:** `cisco_connection` events with `action=blocked` (often message 106023) — top denied source/destination/port combinations
- **Privileged access:** `cisco_authentication_privileged` for enable-mode access
- **Configuration drift:** `cisco_asa_configuration_change` for unauthorised modifications
- **Connection volume baselining:** TCP/UDP build/teardown rates per interface
- **Failed authentication:** Brute-force detection against management interfaces, RADIUS/TACACS+ failures

---

### Gotchas

- **Volume is heavily severity-driven.** ASA syslog severity is configurable per-message-class; many environments log at level 6 (informational) which produces enormous connection log volume. Level 4 (warning) cuts volume dramatically but loses connection telemetry.
- **`cisco:ftd` is the same shape, different device family.** Don't write detections that hardcode `sourcetype=cisco:asa` if FTD is also in the environment — use the eventtype, or `(sourcetype=cisco:asa OR sourcetype=cisco:ftd)`.
- **Message IDs change with ASA versions.** New IDs may appear before TA updates — events with unmapped IDs will land without an eventtype and won't reach CIM data models.
- **NAT translation is in connection events.** `xlate_src_ip` / `xlate_dest_ip` fields appear in build/teardown messages — useful for correlating internal and external addresses.
- **FTD has its own richer log format** (eStreamer / Firepower eventing) that this add-on does **not** parse — for full FTD telemetry beyond the ASA syslog subset, the `Splunk_TA_cisco-firepower` or eStreamer eBridge produces different sourcetypes.

---

## F5 BIG-IP — `Splunk_TA_f5-big-ip` (Splunkbase 2680)

> Each F5 module (LTM, GTM/DNS, APM, AFM, ASM) writes to its own sourcetypes. Where the same logical event arrives via different mechanisms (e.g. ASM via syslog vs Telemetry Streaming), the resulting sourcetypes have different field names and structures — detections need to either pick one or use eventtypes that span both.

### Application Security Manager (ASM — WAF)

#### `f5:bigip:asm:syslog`
**Format:** Syslog with key=value pairs
**Eventtypes:** `f5_bigip_asm_syslog`, `f5_bigip_asm_syslog_attack` (the latter for actual blocked attacks)
**CIM mapping:** `Intrusion_Detection`

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `attack_type` | Attack category (e.g. SQLi, XSS) | `category`, `signature` |
| `severity` | Severity | `severity` |
| `src_ip` | Attacker IP | `src`, `src_ip` |
| `dest_ip` | Protected resource IP | `dest`, `dest_ip` |
| `signature_id` | WAF signature ID | `signature_id` |
| `request` | Offending HTTP request | `url` |
| `response_code` | Response code returned | `status` |
| `policy_name` | ASM policy name | `policy` |
| `violation_details` | Violation breakdown | `description` |

**Use cases:** SQLi/XSS/RCE detection at the WAF layer, bot mitigation, signature hit trending, false-positive tuning for WAF policies.

#### `f5:telemetry:json` (`source=f5:bigip:asm`)
Same WAF events delivered via Telemetry Streaming. Eventtype `f5_bigip_asm_ts`. Same CIM mapping (`Intrusion_Detection`).

**Common fields:** different naming from `f5:bigip:asm:syslog` — events arrive as JSON with field paths like `attack_type`, `severity`, `request_status`, `client_ip`, `host`, `signature_ids[]`. Detections need to either pin to one path or use the `f5_bigip_asm_*` eventtype family.

---

### Access Policy Manager (APM — VPN / SSO / Identity-aware proxy)

#### `f5:bigip:apm:syslog`
**Format:** Syslog with structured key=value pairs

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `user` | VPN / SSO user | `user`, `src_user` |
| `src_ip` | Client IP | `src`, `src_ip` |
| `session_id` | APM session ID | `session_id` |
| `policy_result` | allowed / denied | `action` |
| `client_ip` | Client public IP | `src` |
| `user_agent` | Client user agent | `http_user_agent` |
| `acl_name` | Applied ACL | `policy` |
| `mac_address` | Client MAC | `src_mac` |

**Eventtypes (selection):** `f5_bigip_apm_session_created`, `f5_bigip_apm_session_deleted`, `f5_bigip_apm_access_policy_result`, `f5_bigip_apm_acl_applied_result`, `f5_bigip_apm_username_received`, `f5_bigip_apm_user_agent_received`, `f5_bigip_apm_http_response_status`, `f5_bigip_apm_following_rule`, `f5_bigip_apm_client_info_received`, `f5_bigip_apm_assigned_ppp`

**CIM mapping:**
- `Network_Sessions` (`f5_bigip_apm_session_created`)
- `Network_Traffic` (`f5_bigip_apm_acl_applied_result`, `f5_bigip_apm_assigned_ppp`)
- Other eventtypes are unmapped — useful for context but not data-model-backed

**Use cases:**
- VPN authentication monitoring (especially `policy_result=denied`)
- SSO / identity-aware proxy auditing
- MFA bypass attempts (looking at `following_rule` chains)
- Concurrent-session anomalies (geographic impossibility)
- VPN client posture/compliance tracking

---

### Local Traffic Manager (LTM — load balancer)

#### `f5:bigip:ltm:http:irule`
**Format:** key=value HSL-delivered records (format defined by the iRule + log destination — the standard template logs in `key=value`)

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Client IP | `src`, `src_ip` |
| `dest_ip` | VIP IP | `dest`, `dest_ip` |
| `cs_method` | HTTP method | `http_method` |
| `cs_uri_stem` | URL path | `uri_path` |
| `cs_user_agent` | User agent | `http_user_agent` |
| `sc_status` | Response code | `status` |
| `bytes_in` / `bytes_out` | Traffic volume | `bytes_in` / `bytes_out` |
| `virtual_server` | F5 virtual server | `dest`, `site` |
| `pool_name` | Backend pool | — |
| `pool_member` | Backend pool member | — |

**CIM mapping:** `Web`

**Use cases:** Per-VIP traffic auditing, load balancing decision tracking, HTTP attack detection at the load balancer layer (before reaching backend).

**Gotcha:** What's logged depends entirely on the iRule. Default templates capture standard fields but custom iRules vary widely — environment-specific validation required.

#### `f5:bigip:ltm:lb:failed:irule`
LB failure events from iRule HSL.

**Common fields:** `virtual_server`, `pool_name`, `pool_member`, `event` (failure cause).
**No CIM mapping.**

#### `f5:bigip:ltm:ssl:error`
SSL/TLS handshake failures.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `virtual_server` | F5 VIP | `dest` |
| `tls_version` | Negotiated / requested TLS | `ssl_version` |
| `cipher` | Cipher | `ssl_cipher` |
| `error` | Failure reason | `reason` |

**Eventtype:** `f5_bigip_ltm_ssl_handshake_failed`
**CIM mapping:** `Network_Traffic`

**Use cases:** Cipher mismatch troubleshooting, certificate expiry detection, TLS downgrade attempts.

#### Other LTM error sourcetypes
| Sourcetype | Purpose | CIM |
|---|---|---|
| `f5:bigip:ltm:tcl:error` | iRule (Tcl) execution errors | none |
| `f5:bigip:ltm:traffic` | Packet errors — packets not matching virtual servers, self-IPs, or SNATs | none |
| `f5:bigip:ltm:log:error` | HTTP server returning excessive data, content-length mismatches | none |

---

### Global Traffic Manager (GTM — DNS / wide-IP)

#### `f5:bigip:gtm:dns:request:irule` / `f5:bigip:gtm:dns:response:irule`
**Format:** HSL via iRule

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `query` | DNS query name | `query` |
| `query_type` | DNS query type (A, AAAA, MX, etc.) | `query_type`, `record_type` |
| `src_ip` | Resolver / client IP | `src`, `src_ip` |
| `dest_ip` | F5 GTM IP | `dest`, `dest_ip` |
| `record_type` | Returned record type | `record_type` |
| `response_code` | DNS rcode | `reply_code` |
| `answer` | Resolved answer | `answer` |

**CIM mapping:** `Network_Resolution`

**Use cases:**
- DNS-based threat hunting (DGA detection, suspicious TLDs, DNS tunnelling)
- Wide-IP / GSLB decision auditing
- Query volume and response-code trending

**Gotcha:** DNS volume on a busy GTM is enormous — sampling or aggregation strongly recommended.

---

### System / platform

#### `f5:bigip:syslog`
**Format:** Linux-style syslog from the BIG-IP base OS

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `process` | Daemon name | `app` |
| `user` | Affected user (auth events) | `user`, `dest_user` |
| `src_ip` | Source IP (auth events) | `src`, `src_ip` |
| `action` | success / failure | `action` |
| `severity` | Syslog severity | `severity` |

**Eventtypes:** `f5_bigip_user_authenticated`, `f5_bigip_syslog_login_failed`, `f5_bigip_syslog_pam_auth`, `f5_bigip_syslog_audit_process`, `f5_bigip_syslog_connection_error`

**CIM mapping:**
- `Authentication` (`f5_bigip_user_authenticated`)
- `Network_Traffic` (`f5_bigip_syslog_connection_error`)

**Use cases:** Admin login auditing on the BIG-IP itself, SSH access, audit shell activity, system errors.

#### `f5:bigip:secure`
**Format:** Syslog containing RADIUS authentication events

**Common fields:** `user`, `src_ip`, `action` (RADIUS Accept / Reject).
**CIM mapping:** `Authentication`

---

### Telemetry Streaming

#### `f5:telemetry:json`
**Format:** JSON via HEC, pushed by F5's Telemetry Streaming module
**The umbrella sourcetype** — module data arrives here, differentiated by `source` and `eventtype`.

| `source` | Module | CIM via eventtype |
|---|---|---|
| `f5:bigip:apm` | APM session/access events | (not CIM-mapped via TS) |
| `f5:bigip:asm` | WAF events | `Intrusion_Detection` (`f5_bigip_asm_ts`) |
| `f5:bigip:afm` | Advanced Firewall Manager | `Network_Traffic` (`f5_bigip_afm_ts`) |
| `f5:bigip:avr` | Application Visibility & Reporting | `Network_Traffic` (`f5_bigip_avr_ts`) |
| `f5:bigip:ltm` | Load balancer | `Web` (`f5_bigip_ltm_http_irule_ts`) |
| `f5:bigip:syslog` | System logs | (varies by content) |
| `f5:bigip:system` | System info / stats | (none) |

**Common fields:** JSON payload — field names depend on the F5 module emitting the data; not aligned with the syslog variants. Detection authors should treat `f5:telemetry:json` events as a separate field schema from `f5:bigip:*:syslog`, even when the underlying logical event is the same.

**Detection portability note:** Where the same logical event (e.g. an ASM attack) can arrive via syslog (`f5:bigip:asm:syslog`) or TS (`f5:telemetry:json` with `source=f5:bigip:asm`), the field names differ. Use the `f5_bigip_asm_*` eventtypes to span both.

---

### iControl API (polled stats via modular input)

State queries against the F5 iControl REST API. Output sourcetypes:

| Sourcetype | Purpose |
|---|---|
| `f5:bigip:ts:ltm:locallb:icontrol` | LTM virtual server config |
| `f5:bigip:ts:ltm:locallb:pool:icontrol` | LTM pool status |
| `f5:bigip:ts:gtm:globallb:icontrol` | GTM wide-IP config |
| `f5:bigip:ts:gtm:globallb:pool:icontrol` | GTM pool status |
| `f5:bigip:ts:system:systeminfo:icontrol` | System info (model, version, hostname) |
| `f5:bigip:ts:system:statistics:icontrol` | System statistics |
| `f5:bigip:ts:system:disk:icontrol` | Disk usage |
| `f5:bigip:ts:management:device:icontrol` | Device management info |
| `f5:bigip:ts:management:usermanagement:icontrol` | User account inventory |
| `f5:bigip:ts:networking:adminip:icontrol` | Admin IP config |
| `f5:bigip:ts:networking:interfaces:icontrol` | Interface state |

**Note:** State queries, not events — feed dashboards. **No CIM mapping** for any iControl sourcetypes.

---

## Lansweeper — `TA-lansweeper-add-on-for-splunk` (Splunkbase 5418)

> **Asset enrichment source**, not an event source. Data is point-in-time inventory of devices, software, users — not security events. Treat it as context/lookup data rather than detection telemetry.

### `lansweeper:asset:v2`
**Format:** JSON from Lansweeper GraphQL API V2
**Older variant:** `lansweeper:asset` (V1 API, pre-1.2.0)

**What it covers:**
Asset inventory from Lansweeper Cloud or Lansweeper On-Prem. Each event represents a discovered device with its current state.

**Common fields** (high-level — exact fields depend on Lansweeper API version and what fields the input is configured to retrieve):

| Field | Meaning | CIM alias |
|---|---|---|
| `hostname` | Device hostname | `dest`, `dest_nt_host`, `nt_host` |
| `assetName` | Asset display name | `dest` |
| `domain` | AD domain | `dest_nt_domain` |
| `ip` | Device IP | `ip`, `dest_ip` |
| `mac` | Device MAC | `mac`, `dest_mac` |
| `assetType` | Device type (Workstation, Server, Printer, etc.) | `category` |
| `manufacturer` | Vendor | `vendor` |
| `model` | Hardware model | `model` |
| `serialNumber` | Hardware serial | `serial` |
| `os` | Operating system | `os` |
| `osVersion` | OS version | `os_version` |
| `osBuild` | OS build number | `os_build` |
| `lastSeen` | Last discovery time | — |
| `firstSeen` | First discovery time | — |
| `installedSoftware` | Installed software (nested) | — |
| `lastLoggedOnUser` | Last interactive user | `user`, `owner` |
| `assignedUser` | Assigned owner | `owner` |
| `subnet` / `vlan` | Network location | `vlan` (TA-dependent) |
| `switch` / `switchPort` | Network attachment | — |
| `siteId` / `siteName` | Lansweeper site | — |
| `assetId` | Lansweeper asset ID | `dest_id` |

**CIM mapping:** Asset enrichment for ES Asset & Identity framework. The TA provides CIM-mapped fields for IP/MAC lookups specifically. Likely candidates for `Compute_Inventory` data model population, though native CIM tagging coverage is limited compared to event-based sourcetypes.

**Use cases:**
- **ES Asset & Identity enrichment** — feeding the assets lookup so detections include device context (owner, location, OS, criticality)
- **Investigation by IP/MAC** — workflow actions provided by the TA pivot from any IP/MAC in any sourcetype to the matching asset record
- **Drift detection** — first-seen/last-seen tracking, new devices on the network
- **Software inventory baselining** — what's installed where, useful for vulnerability prioritisation
- **Coverage validation for other tools** — comparing Lansweeper inventory to CrowdStrike / SentinelOne / Defender enrolled hosts to find gaps

---

### Gotchas

- **Polling interval matters.** Asset inventory polled on a schedule means latency between Lansweeper detecting a change and Splunk seeing it. For investigations, the asset record may be slightly stale.
- **API V1 vs V2 sourcetype rename.** Pre-1.2.0 used `lansweeper:asset` — old saved searches and lookups may still reference it.
- **Asset inventory != endpoint coverage.** Lansweeper discovers what's on the network, not what has security agents installed. Useful for finding *missing* coverage from CrowdStrike/SentinelOne/Defender, but it doesn't replace those tools.
- **State, not events.** Don't write detections that look for "creation" of a Lansweeper asset event — the data is updated inventory, not changes. For change tracking, you'd need to baseline and diff over time.

---

## Check Point — `Splunk_TA_checkpoint_log_exporter` (Splunkbase 5478)

> Two TAs exist on Splunkbase that both extract from Check Point Log Exporter syslog: a Splunk-built TA (5478) and a Check Point-built app (4293). Both produce the same primary sourcetype (`cp_log`) but with different field extractions, eventtypes, and tags. If both are installed and active, the same event arrives with inconsistent CIM mapping — env-context will show which is configured.

### `cp_log` / `cp_log:syslog`
**Format:** Syslog with key-value pairs (Check Point's structured format from Log Exporter)
**Two sourcetype variants:** Both have the same field extractions in the Splunk-built TA; the suffix exists to allow routing different inputs separately if needed.

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `product` | The Check Point **blade** that produced the event (most important disambiguator) | `vendor_product`, `app` |
| `fw_subproduct` | Sub-product within a blade | — |
| `action` | Allow / Drop / Reject / Detect / Prevent | `action` |
| `src` | Source IP | `src`, `src_ip` |
| `dst` | Destination IP | `dest`, `dest_ip` |
| `s_port` | Source port | `src_port` |
| `d_port` | Destination port | `dest_port` |
| `proto` | Network protocol | `transport`, `protocol` |
| `service` | Application / service name | `app` |
| `rule` | Security policy rule number | `rule` |
| `rule_uid` | Rule UID | `rule_uid` |
| `rule_name` | Rule name | `rule`, `signature` |
| `policy_name` | Policy package name | `policy` |
| `nat_rulenum` | NAT rule | `transport_rule` (TA-dependent) |
| `conn_direction` | Inbound / outbound | `direction` |
| `bytes` | Total bytes | `bytes` |
| `bytes_in` / `bytes_out` | Directional bytes | `bytes_in` / `bytes_out` |
| `packets_in` / `packets_out` | Packet counts | `packets_in` / `packets_out` |
| `interface` | Interface name | `interface` |
| `i/f_dir` | Interface direction | `direction` |
| `i/f_name` | Interface name | `interface` |
| `event_name` | Human-readable event type | `signature` |
| `protection_name` | Threat Prevention signature/protection name | `signature` |
| `severity` | Severity | `severity` |
| `confidence` | Confidence score | `confidence` |

---

### Check Point blade → CIM mapping

Detections should filter by `product` (and sometimes `fw_subproduct`) to scope to the right blade.

| Blade (`product` value) | Typical use | CIM data model |
|---|---|---|
| `Firewall` (no `fw_subproduct=*VPN*`) | Network traffic accept/deny | `Network_Traffic` |
| `VPN-1 & FireWall-1` / `IKE` (with `fw_subproduct=*VPN*`) | IPsec VPN | `Network_Sessions` |
| `Mobile Access` | SSL VPN / web portal | `Network_Sessions`, `Authentication` |
| `URL Filtering` | Web filtering decisions | `Web` |
| `Anti-Bot`, `Anti-Virus`, `IPS`, `Threat Emulation` | Threat Prevention blades | `Intrusion_Detection`, `Malware` |
| `Anti Phishing`, `Anti-Spam and Email Security` | Email security | `Email` |
| `DLP` | Data loss prevention | `Alerts` |
| `Application Control` | Layer 7 app control | `Network_Traffic` (with app metadata) |
| `Identity Awareness` | Identity → IP mappings | `Authentication` (via `checkpoint:sessions`) |
| `Endpoint Security` | Endpoint blades | (via `checkpoint:endpoint`) |
| `Audit / CLI` | Management actions | `Change` (via `checkpoint:audit`) |

---

### Sub-sourcetypes for specific blades

Some blades are routed to their own narrower sourcetypes:

| Sourcetype | Blade | CIM | Distinguishing fields |
|---|---|---|---|
| `checkpoint:audit` | CLI / Audit logs from management server | `Change` | `admin`, `operation`, `object_name` |
| `checkpoint:sessions` | Identity Awareness (User-to-IP mappings) | `Authentication`, identity enrichment | `srcuser`, `src`, `mapping_state` |
| `checkpoint:endpoint` | Endpoint Security blade | `Endpoint`, `Malware` | `host_name`, `process_name`, `file_name` |

These are populated by index-time sourcetype routing based on the source field.

---

### Use cases by blade

- **Firewall:** Traditional accept/deny analysis, top-talkers, rule effectiveness
- **VPN:** Tunnel establishment failures, brute force against IPsec, geographic anomalies in remote access
- **Mobile Access:** SSL VPN authentication patterns, MFA bypass attempts, posture-check failures
- **URL Filtering:** Suspicious destination patterns, category-based detection (gambling/proxies/anonymisers), blocked-then-allowed retries
- **Threat Prevention (IPS/Anti-Bot/AV/TE):** Active exploitation attempts, malware callbacks, sandbox detonation results
- **Identity Awareness:** User attribution for traffic events, AD/LDAP integration health
- **DLP:** Sensitive data egress, policy violations
- **Audit:** Admin login auditing on the SmartConsole, policy changes

---

### Gotchas

- **`product` is the key disambiguator.** Don't assume `cp_log` events all behave the same — VPN events vs Firewall events vs URL Filtering events have different field semantics. Always scope queries by `product` first.
- **Field extractions live at search-time.** Don't expect to see the full set of CP fields in raw events — they're extracted via props/transforms. Verify extraction is correct on a sample before relying on a field.
- **Per-version log format variations.** Check Point's syslog format changes between major versions; field availability is version-dependent.
- **If both Splunk-built TA (5478) and Check Point-built app (4293) are installed with their full eventtype/tag chains active, the same `cp_log` event will be tagged inconsistently** — env-context will show which is the source of truth.

---

## CrowdStrike — `Splunk_TA_crowdstrike`

### Common sourcetypes (FDR / SIEM connector / API)
| Sourcetype | Content |
|---|---|
| `crowdstrike:falcon:streamingapi:json` | Streaming API events — detections, audit, sensor lifecycle |
| `crowdstrike:falcon:fdr:json` | Falcon Data Replicator events — full sensor telemetry (process, network, file, etc.) |
| `crowdstrike:falcon:host:json` | Host inventory |

**Common fields (representative — varies by event type):**
| Field | Meaning | CIM alias |
|---|---|---|
| `event_simpleName` | CrowdStrike event name | `signature`, `vendor_action` |
| `aid` | Falcon agent ID | `dest_id`, `dvc_id` |
| `ComputerName` | Hostname | `dest`, `dest_nt_host` |
| `UserName` | User context | `user`, `src_user` |
| `FileName` | File involved | `file_name` |
| `FilePath` | File path | `file_path` |
| `SHA256HashData` | SHA256 | `file_hash` |
| `MD5HashData` | MD5 | `file_hash` |
| `CommandLine` | Process command line | `process` |
| `ImageFileName` | Image path | `process_path` |
| `TargetProcessId` | PID | `process_id` |
| `ContextProcessId` | Parent PID | `parent_process_id` |
| `RemoteAddressIP4` | Remote IP | `dest_ip` |
| `RemotePort` | Remote port | `dest_port` |
| `LocalAddressIP4` | Local IP | `src_ip` |
| `LocalPort` | Local port | `src_port` |

**CIM mapping:** `Endpoint`, `Authentication`, `Network_Traffic`, `Malware`, `Intrusion_Detection`

**Use cases:** Endpoint detections, process telemetry, host inventory, network connection events.

**Gotcha:** FDR events are voluminous — `event_simpleName` is the primary scoping field; resist the urge to query without it.

---

## SentinelOne — `sentinelone_app_for_splunk` (Splunkbase 5433) and family

> SentinelOne data can arrive via REST API polling or via syslog (CEF or JSON). Sourcetype patterns differ between the two paths — env-context will show which is in use.

### REST API ingestion sourcetype pattern: `sentinelone:channel:*`

Each "channel" (data type) gets its own sourcetype.

| Sourcetype | Channel | Content |
|---|---|---|
| `sentinelone:channel:agents` | Agents | Endpoint device inventory — agent version, OS, status, last seen |
| `sentinelone:channel:threats` | Threats | Threat detections — verdict, classification, mitigation status |
| `sentinelone:channel:activities` | Activities | Console activity — admin actions, policy changes |
| `sentinelone:channel:applications` | Applications | Installed application inventory across endpoints |
| `sentinelone:channel:application_management:risks` | Application Risk | Vulnerability findings on installed software |
| `sentinelone:channel:groups` | Groups | Console group structure |
| `sentinelone:channel:policies` | Policies | Policy configurations |

**Common fields across channels:**
| Field | Meaning | CIM alias |
|---|---|---|
| `id` | Unique record ID within the channel | `signature_id` |
| `siteId` | SentinelOne site identifier | `vendor_account` |
| `console` | Console/management URL — disambiguator for multi-console deployments | — |
| `subdomain` | Tenant subdomain | — |
| `management` | Management server URL | — |
| `ComputerName` | Hostname | `dest`, `dest_nt_host` |
| `Username` | User | `user`, `src_user` |
| `agent_version` | Agent version (`agents` channel) | `version` |
| `agent_uuid` | Agent UUID (`agents` channel) | `dest_id` |

**Threats channel additional fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `threatName` | Threat name | `signature` |
| `classification` | Threat classification | `category` |
| `confidenceLevel` | Confidence | `confidence` |
| `mitigationStatus` | Mitigation outcome | `action` |
| `analystVerdict` | Verdict (TP / FP) | `vendor_action` |
| `incidentStatus` | Incident state | `status` |
| `processName` | Process | `process_name` |
| `filePath` | File path | `file_path` |
| `fileHash` | File hash | `file_hash` |
| `commandline` | Command line | `process` |
| `mitre.tactics` | MITRE tactic IDs | `mitre_tactic_id` |
| `mitre.techniques` | MITRE technique IDs | `mitre_technique_id` |

---

### Syslog ingestion sourcetypes

When SentinelOne is configured to forward via syslog, sourcetypes follow a different pattern:

| Sourcetype | Format | Content |
|---|---|---|
| `sentinelone:syslog:cef` | CEF | Threat / activity events in CEF format |
| `sentinelone:cloud:funnel` | JSON | Cloud Funnel (XDR) firehose — full deep-visibility telemetry |
| `sentinelone:dv` | JSON | Deep Visibility API events |

**Note:** Exact sourcetype names vary by TA version — verify against the actual installed TA's `props.conf` post-install.

**Common fields (CEF):** standard CEF — `deviceVendor`, `deviceProduct`, `deviceVersion`, `signatureId`, `name`, `severity`, plus Custom Extension fields populated by the TA. CIM aliases align via the TA's `FIELDALIAS-` definitions.

---

### CIM mapping

| Channel / sourcetype | CIM data model |
|---|---|
| `sentinelone:channel:threats` / CEF threats | `Malware`, `Alerts` |
| `sentinelone:channel:agents` | `Inventory` (asset enrichment for ES Assets & Identities) |
| `sentinelone:channel:activities` | `Change` (admin actions) |
| `sentinelone:channel:application_management:risks` | `Vulnerabilities` |
| `sentinelone:cloud:funnel` (Deep Visibility) | `Endpoint` (Processes, Filesystem, Registry, Network) |

The richest endpoint telemetry — process create, file events, network connections — comes from **Cloud Funnel (XDR firehose)**, which is a separate paid SentinelOne licensing tier from base EPP.

---

### Use cases

- **Threat triage:** Pull `sentinelone:channel:threats` for current open threats with verdict and mitigation status
- **Endpoint inventory & coverage gaps:** Compare `sentinelone:channel:agents` against asset inventory (Lansweeper, AD, etc.) to find unmonitored hosts
- **Application risk reporting:** `sentinelone:channel:application_management:risks` for vulnerable software inventory
- **Deep Visibility hunting:** Process / file / network telemetry for DFIR (requires Cloud Funnel licensing)

---

### Gotchas

- **Multi-console / regional deployments.** Filter by `console` field when querying across multiple SentinelOne consoles. Searches without `console` scope may return unexpected results.
- **Cloud Funnel volume.** Deep Visibility / Cloud Funnel telemetry is **enormous**. Not all channels need to be enabled for all use cases.
- **Older sourcetype names.** Pre-v5 versions of the App used naming like `sourcetype=agent`, `sourcetype=group` (without the `sentinelone:channel:` prefix). Old saved searches and lookups may still reference these.

---

## Mimecast Email Security — `mimecast_for_splunk` / `TA-mimecast-for-splunk` (Splunkbase 4075)

> Multiple Mimecast feature areas each produce their own sourcetype. The TA's modular inputs poll separate API endpoints per feature.

### What's covered

| Mimecast feature | Purpose |
|---|---|
| **MTA SIEM** (Process / Receipt) | Core mail flow — delivery, rejection, queueing |
| **TTP URL Protect** | URL rewriting + click-time analysis (phishing link clicks) |
| **TTP Attachment Protect** | Sandboxed attachment analysis (malware) |
| **TTP Impersonation Protect** | BEC / spoofing / executive impersonation detection |
| **SIEM AV** | Antivirus engine verdicts |
| **SIEM Spam / Process** | Spam scoring, processing decisions |
| **DLP** | Data loss prevention policy hits |
| **Audit** | Admin actions on the Mimecast console |
| **Service Health** | Mimecast platform status |

---

### Sourcetypes

| Typical sourcetype | Log type |
|---|---|
| `mimecast:siem` (or split into `mimecast:siem:process`, `mimecast:siem:receipt`) | MTA SIEM logs |
| `mimecast:ttp:url` | URL Protect — clicks, scan results |
| `mimecast:ttp:ap` | Attachment Protect — sandbox verdicts |
| `mimecast:ttp:impersonation` | Impersonation Protect — BEC detection |
| `mimecast:siem:av` | Antivirus events |
| `mimecast:dlp` | DLP findings |
| `mimecast:audit` | Console admin audit |
| `mimecast:service_health` | Platform health |

Exact sourcetype names should be verified against `props.conf` post-install — the partner-built TA's naming has changed across versions.

---

### Common fields

Fields vary substantially between log types because the Mimecast features they represent are different.

**Across most email-related sourcetypes:**

| Field | Meaning | CIM alias |
|---|---|---|
| `senderAddress` | Envelope sender | `src_user`, `sender` |
| `recipientAddress` | Envelope recipient | `recipient` |
| `subject` | Message subject (newer versions) | `subject` |
| `MsgId` | Mimecast message identifier (newer versions) | `message_id` |
| `senderIp` | Sender connecting IP | `src`, `src_ip` |
| `route` | Mail flow direction | `direction` |
| `Hld` | Held reason / spam disposition | `signature` |
| `splunkAccountCode` | Mimecast tenant identifier (added by the TA) | `vendor_account` |
| `SpamProcessingDetail` | Spam scoring detail (in receipt logs) | — |
| `acc` | Account code | `vendor_account` |

**TTP URL Protect specific:**

| Field | Meaning | CIM alias |
|---|---|---|
| `url` | Rewritten URL | `url` |
| `userClicked` | Whether user clicked | `action` |
| `actions` | Action taken | `action` |
| `category` | URL category | `category` |
| `urlCategory` | URL category (alt name) | `category` |
| `clickLogged` | Click recorded | — |

**TTP Attachment Protect specific:**

| Field | Meaning | CIM alias |
|---|---|---|
| `fileName` | Attachment filename | `file_name` |
| `fileType` | File MIME / extension | `file_type` |
| `fileHash` | File hash | `file_hash` |
| `result` | clean / malicious / etc. | `action`, `result` |

**TTP Impersonation specific:**

| Field | Meaning | CIM alias |
|---|---|---|
| `taggedExternal` | Sender tagged external | — |
| `taggedMalicious` | Sender tagged malicious | — |
| `policyName` | Matched policy | `policy`, `signature` |
| `definition` | Matched rule | `signature` |

**DLP specific:**

| Field | Meaning | CIM alias |
|---|---|---|
| `policy` | DLP policy | `signature` |
| `action` | block / notify / etc. | `action` |
| `senderDomain` | Sender domain | `src_domain` (TA-dependent) |
| `recipientDomain` | Recipient domain | `recipient_domain` (TA-dependent) |

---

### CIM mapping

| Sourcetype | CIM data model |
|---|---|
| `mimecast:siem` (Process / Receipt) | `Email` |
| `mimecast:ttp:url` | `Email`, `Web` (URL events) |
| `mimecast:ttp:ap` | `Email`, `Malware` |
| `mimecast:ttp:impersonation` | `Email`, `Alerts` |
| `mimecast:siem:av` | `Email`, `Malware` |
| `mimecast:dlp` | `Alerts`, `Email` |
| `mimecast:audit` | `Change` |

CIM mapping has improved over versions — the `Hld` → `signature` mapping is a notable addition for Email DM compliance.

---

### Use cases

- **Phishing investigations:** Pivot from a suspicious email subject/sender across `mimecast:siem`, `mimecast:ttp:url`, and `mimecast:ttp:impersonation` to see the full attack chain
- **Click-time URL analysis:** `mimecast:ttp:url` shows who clicked rewritten links and what the verdict was at click time (rather than send time)
- **BEC detection:** `mimecast:ttp:impersonation` for executive impersonation patterns, lookalike domains
- **Mail flow auditing:** `mimecast:siem` for delivery/rejection rates, top senders/recipients, queue analysis
- **Quarantine effectiveness:** Cross-reference held-then-released messages with later threat verdicts
- **DLP exfiltration:** `mimecast:dlp` for outbound data leakage attempts
- **Console admin auditing:** `mimecast:audit` for who changed which policies

---

### Gotchas

- **Multi-tenant deployments.** The `splunkAccountCode` field disambiguates events across multiple Mimecast tenants. Always scope queries by it in multi-tenant environments.
- **Subject and MsgId fields are version-dependent.** Older TA versions don't have `subject` or `MsgId` in SIEM Process / TTP URL / TTP AP events. If detections rely on these, ensure the TA is at a recent version.

---

## Splunk Stream — `Splunk_TA_stream`

### `stream:netflow`
**Format:** NetFlow v5/v9/IPFIX records collected by Stream

**Common fields:**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` | Source port | `src_port` |
| `dest_port` | Destination port | `dest_port` |
| `protocol` | IP protocol | `transport`, `protocol` |
| `bytes_in` | Inbound bytes | `bytes_in` |
| `bytes_out` | Outbound bytes | `bytes_out` |
| `packets_in` / `packets_out` | Packet counts | `packets_in` / `packets_out` |

**CIM mapping:** `Network_Traffic`

### Other Stream sourcetypes
| Sourcetype | Purpose | CIM |
|---|---|---|
| `stream:dns` | DNS queries/responses | `Network_Resolution` |
| `stream:http` | HTTP transactions | `Web` |
| `stream:tcp` | TCP session metadata | `Network_Sessions` |
| `stream:tls` | TLS handshake metadata | `Certificates` |
| `stream:smtp` | SMTP transactions | `Email` |

**Representative common fields (`stream:dns`):**
| Field | Meaning | CIM alias |
|---|---|---|
| `query` | DNS query name | `query` |
| `query_type` | Query type | `query_type`, `record_type` |
| `reply_code` | Response code | `reply_code` |
| `answer` | Resolved answer | `answer` |
| `src_ip` / `dest_ip` | Endpoints | `src` / `dest` |

**Gotcha:** Stream is bandwidth-intensive — independent collectors required at scale; not a drop-in for vendor flow data on busy networks.

---

## Zeek (Bro) — `TA-zeek-af_packet` / `TA-zeek_kafka` / similar

### Common sourcetypes
| Sourcetype | Provides | CIM |
|---|---|---|
| `zeek:conn` | Connection summaries | `Network_Traffic`, `Network_Sessions` |
| `zeek:dns` | DNS request/response | `Network_Resolution` |
| `zeek:http` | HTTP transactions | `Web` |
| `zeek:ssl` | TLS handshakes | `Certificates` |
| `zeek:x509` | X.509 certificates seen | `Certificates` |
| `zeek:files` | Files extracted from streams | `Endpoint` |
| `zeek:notice` | Zeek policy notices | `Intrusion_Detection` |
| `zeek:weird` | Protocol anomalies | `Intrusion_Detection` |

**Representative common fields (`zeek:conn`):**
| Field | Meaning | CIM alias |
|---|---|---|
| `id.orig_h` | Source IP | `src`, `src_ip` |
| `id.resp_h` | Destination IP | `dest`, `dest_ip` |
| `id.orig_p` | Source port | `src_port` |
| `id.resp_p` | Destination port | `dest_port` |
| `proto` | Transport protocol | `transport`, `protocol` |
| `service` | Application protocol | `app` |
| `orig_bytes` / `resp_bytes` | Directional bytes | `bytes_in` / `bytes_out` |
| `conn_state` | Connection state | `action` (mapped) |
| `uid` | Zeek connection UID | `session_id` |

**Use cases:** Rich network-level threat hunting — far more semantic than netflow. Strong for DNS analysis, TLS fingerprinting (JA3/JA4), file extraction.

---

## UniFi (custom syslog TA — `TA-unifi_syslog`)

> **Custom TA — field extractions are environment-specific.** These entries describe the typical shape but should be validated per-environment.

### `unifi:fw`
UniFi gateway firewall accept/deny events.

**Common fields (typical):**
| Field | Meaning | CIM alias |
|---|---|---|
| `src_ip` | Source IP | `src`, `src_ip` |
| `dest_ip` | Destination IP | `dest`, `dest_ip` |
| `src_port` / `dest_port` | Ports | `src_port` / `dest_port` |
| `protocol` | IP protocol | `transport`, `protocol` |
| `action` | accept / drop | `action` |
| `interface` | Egress/ingress interface | `interface` |

**CIM mapping:** `Network_Traffic` (when tagged correctly)

### `unifi:dns`
DNS request telemetry from UniFi gateway.

**Common fields (typical):**
| Field | Meaning | CIM alias |
|---|---|---|
| `query` | DNS query name | `query` |
| `query_type` | Query type | `query_type`, `record_type` |
| `src_ip` | Resolver / client IP | `src`, `src_ip` |
| `answer` | Resolved answer | `answer` |

**CIM mapping (intent):** `Network_Resolution` — tagging is often missing in custom TAs. Validate with `tstats`.

### `unifi`
UniFi traffic and operational events. **No fixed CIM mapping** — content varies.

### `unifi:cef`
CEF-formatted alerts from UniFi.

**Common fields:** standard CEF — `deviceVendor`, `deviceProduct`, `signatureId`, `name`, `severity`. CIM mapping (intent) `Alerts` / `Intrusion_Detection` depending on event content.

### `edge-sourceType` / `edge-fallback`
UniFi syslog default catch-all source. Indicates events that didn't match a more specific sourcetype rule. **No CIM mapping.**

**Common gotcha:** Custom TAs frequently lack the eventtype/tag chain required for CIM data model population. Always validate `tstats from datamodel=...` returns events before relying on DM-based detections.

---

## Splunk Internal

### `stash`
Summary index events written by scheduled searches via `collect` or `summary` modular alerts. Schema depends on the producing search — fields are entirely defined by the source.

### `json`
Generic JSON ingestion. Auto field extraction; specific fields depend on the producer.

### `splunkd` / `splunk_*`
Splunk's own logs in the `_internal` index. Use for platform troubleshooting, not security investigations.

---

## Conventions for adding entries

When extending this library, each sourcetype entry should include:

1. **Format** — text/JSON/XML/binary, parser source
2. **Source TA** — the Splunkbase or custom add-on that handles parsing
3. **Common fields** — the 5–15 most useful fields for queries, with CIM alias column
4. **CIM mapping** — which data model(s) it maps to (and whether mapping is automatic or requires extra tagging)
5. **Use cases** — typical investigations or detections it powers
6. **Gotchas** — known data-shape pitfalls, version-driven field changes, tag-chain dependencies

Keep entries to what's true across environments. Anything site-specific (which index, ingestion health, custom field extractions, ingest topology, app-selection conflicts) belongs in `splunk-environment-context.md` or `splunk-platform-admin-reference.md`.
