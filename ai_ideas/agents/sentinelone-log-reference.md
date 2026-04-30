# SentinelOne Log Reference

> Companion to `splunk-sourcetype-library.md`. The library covers the SentinelOne Splunk ecosystem broadly (which app does what, where to install it, sourcetype shape); this file goes deep on **per-channel field schemas, enumerated values, MITRE ATT&CK mappings, and detection patterns** for the Singularity platform.
>
> Scoped to events relevant to security detection, IR, and admin auditing across the three primary SentinelOne ingestion paths into Splunk. Does not duplicate sourcetype-library content on installation topology, app conflicts, or token storage.
>
> **Cross-references:**
> - For sourcetype shape, app ecosystem, and ingestion topology, see `splunk-sourcetype-library.md` (SentinelOne section).
> - For RBA field conventions, MITRE annotation shape, and risk-scoring grid, see `splunk-detection-patterns.md`.
> - For equivalent Sysmon EID coverage of process/file/network/registry telemetry, see `windows-event-log-reference.md` (Sysmon section).
>
> **Authoritative sources** (verify against installed app version where field availability is uncertain):
> - SentinelOne Singularity Platform documentation (vendor-hosted, account-gated)
> - `sentinelone_app_for_splunk` `props.conf` and field-extraction definitions on the installed search head
> - SentinelOne Cloud Funnel / Deep Visibility schema reference (vendor-supplied, version-specific)
> - MITRE ATT&CK technique catalogue at `attack.mitre.org`

---

## Overview

SentinelOne's **Singularity** platform is a unified EPP / EDR / XDR product. The Splunk integration surfaces three logically distinct telemetry streams:

| Stream | What it carries | Typical volume | Licensing |
|---|---|---|---|
| **Channel API** (REST polling) | Threat verdicts, agent inventory, console activity, software inventory, vulnerability findings, console structure | Moderate | Included with EPP/EDR |
| **Syslog (CEF or JSON)** | Threat / activity events, formatted for SIEM forwarding | Moderate | Included with EPP/EDR |
| **Cloud Funnel (XDR firehose)** | Full Deep Visibility telemetry — process / file / network / registry / DNS / image-load / cross-process / login | Very high | Separate XDR / Deep Visibility add-on |

The three streams overlap. Threats appear in **both** the channel API (`sentinelone:channel:threats`) and the CEF syslog feed; the same logical event has different field names in each. Cloud Funnel is the only path that carries full endpoint telemetry — channel API alone does not include process create / network connection / file modification per-event detail.

**Ingestion-path summary:**

```
            ┌────────────────────────────────────────────┐
            │  SentinelOne Management Console            │
            │  (Singularity platform — site / account /  │
            │   group hierarchy, agents, threats)        │
            └────────────────────────────────────────────┘
                  │                │                │
       REST API   │     Syslog     │   Cloud Funnel │
                  ▼                ▼                ▼
        sentinelone:channel:*   sentinelone:        sentinelone:
        (one per channel)       syslog:cef          cloud:funnel
                  │                │                │
                  ▼                ▼                ▼
            ────────────── Splunk indexers ──────────────
```

**Sourcetype recap** (shape detail in `splunk-sourcetype-library.md`):

| Sourcetype | Path | Content |
|---|---|---|
| `sentinelone:channel:agents` | Channel API | Endpoint inventory |
| `sentinelone:channel:threats` | Channel API | Threat detections |
| `sentinelone:channel:activities` | Channel API | Console / admin activity |
| `sentinelone:channel:applications` | Channel API | Installed software inventory |
| `sentinelone:channel:application_management:risks` | Channel API | Vulnerability findings |
| `sentinelone:channel:groups` | Channel API | Console group structure |
| `sentinelone:channel:policies` | Channel API | Policy configuration |
| `sentinelone:syslog:cef` | Syslog | CEF threat / activity events |
| `sentinelone:cloud:funnel` | Cloud Funnel | Deep Visibility telemetry (JSON) |
| `sentinelone:dv` | Deep Visibility API | Direct DV query results |

> **Field-name disclaimer:** Field names below match what `sentinelone_app_for_splunk` extracts in current versions. The app has gone through several schema revisions (notably between v4 and v5+); pre-v5 ingestion used flatter sourcetype names like `sourcetype=agent` and `sourcetype=group`. Where a field's existence depends on app version, it is marked `(verify against installed app version)`.

---

## Common envelope fields

Most channel events share a common envelope regardless of which channel they belong to. These are the fields used to scope queries in multi-tenant or multi-console environments and to correlate channel events with each other.

| Field | Meaning | Notes |
|---|---|---|
| `id` | Unique record identifier within the channel | Not unique across channels |
| `accountId` | SentinelOne account identifier | Top-level multi-tenant disambiguator |
| `siteId` | Site identifier within an account | Use for per-site scoping |
| `groupId` | Group identifier within a site | Used for policy targeting |
| `agentId` / `agent_uuid` | Agent UUID — stable per endpoint install | Use to join across channels |
| `console` | Console / management URL | Disambiguator across multi-console deployments |
| `subdomain` | Tenant subdomain | Identifies which SentinelOne tenant the event came from |
| `management` | Management server URL | Same as `console` in most deployments |
| `createdAt` | Record creation timestamp (ISO-8601) | Often differs from `_time` if `_time` reflects ingest time |
| `updatedAt` | Last update timestamp (ISO-8601) | Threat records mutate post-creation as analysts triage |
| `mitre.tactics[]` | Multi-value: ATT&CK tactic names | Populated on threats and some activities; **populated lazily** |
| `mitre.techniques[]` | Multi-value: ATT&CK technique IDs (e.g. `T1059`, `T1547.001`) | Populated lazily — see Gotchas |

**Scoping convention:**
```
sourcetype=sentinelone:channel:* console="acme.sentinelone.net" accountId="..." siteId="..."
```

Always scope multi-console searches by `console` (or `accountId`/`siteId`) — searches without scope return cross-tenant data, which produces inflated counts and misleading dashboards.

---

## Per-channel reference

### `sentinelone:channel:threats`

The headline channel for SOC investigation. Each event represents a threat detection: the verdict, the engine that fired, the file/process artefacts, the mitigation status, and the analyst disposition.

**What it covers:** static AI / behavioural AI / reputation / lateral-movement / exploit / engine-driven detections raised by SentinelOne agents. One threat record per detection; the record is updated (not duplicated) as the lifecycle progresses (mitigation, analyst verdict, incident status).

**Typical CIM mappings:** `Malware`, `Alerts`.

#### Field schema

**Identity / scope:**

| Field | Meaning |
|---|---|
| `threatId` / `id` | Unique threat record identifier |
| `threatName` | File name or behavioural detection name |
| `agentId` / `agent_uuid` | Agent that detected the threat |
| `computerName` / `endpointName` | Endpoint hostname (verify against installed app version — naming differs across releases) |

**Classification and confidence:**

| Field | Meaning | Common values |
|---|---|---|
| `classification` | High-level category | `Malware`, `Ransomware`, `PUA`, `Worm`, `Trojan`, `Backdoor`, `Exploit`, `Macro`, `Engine`, `Hacking Tool`, `Spyware`, `Generic.Suspicious` |
| `classificationSource` | Engine that classified | `Cloud`, `Engine`, `User` |
| `confidenceLevel` | Detection confidence | `suspicious`, `malicious` |
| `engines[]` | Multi-value list of engines that fired | `Static AI`, `Behavioral AI`, `Reputation`, `DFI` (Deep File Inspection), `Lateral Movement`, `Exploit Shield`, `Anti Exploit`, `Application Control`, `Pre Execution Suspicious`, `On-Write DFI` |

#### Engine reference

| Engine | Detects |
|---|---|
| `Static AI` | Pre-execution ML classifier on file contents (PE / Mach-O / script). Fires on file write or first-execution scan |
| `Behavioral AI` | Runtime behavioural detection — process tree pattern matching post-execution |
| `Reputation` | Cloud-fed file reputation (hash lookup against vendor IOC feed) |
| `DFI` (Deep File Inspection) | On-write deep static analysis — heuristic-rich, slower than `Static AI` |
| `Lateral Movement` | Process behaviour indicative of intra-network movement (SMB, WMI, remote service) |
| `Exploit Shield` / `Anti Exploit` | Memory-corruption / shellcode detection — exploit prevention engine |
| `Application Control` | Custom Application Control policy matched (allowlist / denylist enforcement) |
| `Pre Execution Suspicious` | Static analysis raised suspicion before execution |
| `On-Write DFI` | DFI fired during file creation rather than first-execution |

#### Mitigation and analyst lifecycle

| Field | Meaning | Values |
|---|---|---|
| `mitigationStatus` | What the agent did about it | `mitigated`, `not_mitigated`, `partially_mitigated`, `pending_user_action`, `marked_as_benign` |
| `mitigationStatusDescription` | Human-readable expansion | Free text |
| `analystVerdict` | Analyst-set disposition | `undefined`, `true_positive`, `false_positive`, `suspicious` |
| `incidentStatus` | Workflow state | `unresolved`, `in_progress`, `resolved` |
| `markedAsBenign` | Boolean — analyst overrode the detection | `true` / `false` |
| `containmentStatus` | Network containment state of the affected endpoint | `not_contained`, `contained`, `containment_pending`, `disconnected` (verify against installed app version) |

> **`mitigationStatus` ≠ resolution.** A threat can be `mitigated` and still have `incidentStatus=unresolved`. Triage workflow is independent of automatic mitigation.

> **`analystVerdict=undefined`** is the default state — the threat is awaiting analyst disposition. SOC content should treat `undefined` distinctly from `true_positive` / `false_positive`.

#### File / process artefacts

| Field | Meaning |
|---|---|
| `processName` | Initiating process name |
| `processCmd` / `commandline` | Full process command line at detection time |
| `processUser` | User context the process ran under |
| `filePath` | Path of the malicious file on disk |
| `fileExtensionType` | File classification (`Executable`, `Document`, `Script`, `Archive`, etc.) |
| `fileSize` | Size in bytes |
| `fileHash` / `sha1` | SHA1 hash (canonical hash field for SentinelOne) |
| `sha256` | SHA256 hash (verify against installed app version — not always populated) |
| `md5` | MD5 hash (verify against installed app version) |
| `fileVerificationType` | Code-signing state — `signed`, `unsigned`, `revoked`, `expired` |
| `publisher` / `signedBy` | Code-signing publisher identity if signed |
| `originatorProcess` | Parent process of the detected process |
| `initiatedBy` | What triggered the detection — `agent_policy`, `console_user`, `cloud`, `dvCommand`, `agent_static_engine` |

#### MITRE ATT&CK fields

| Field | Meaning |
|---|---|
| `mitre.tactics[]` | Multi-value tactic names |
| `mitre.techniques[]` | Multi-value technique IDs |
| `indicators[]` | SentinelOne indicator strings — semi-structured behavioural markers, e.g. `T1003 - OS Credential Dumping` |

Tactic and technique fields are populated **lazily**: initial threat events may have empty arrays, with later updates filling them in once cloud analysis completes. Detection content should either:
- accept that the first event lacks tactic/technique and key on `classification` / `engines` instead, or
- delay evaluation by joining recent threats against their latest update via `stats latest(...) by threatId`.

#### Common detection patterns

**Mitigation failure on a high-confidence threat — agent saw it, couldn't act.**
```
sourcetype=sentinelone:channel:threats
    confidenceLevel="malicious"
    mitigationStatus IN ("not_mitigated", "partially_mitigated", "pending_user_action")
| stats latest(_time) as last_seen
        latest(threatName) as threatName
        latest(classification) as classification
        latest(engines{}) as engines
        latest(filePath) as filePath
        by threatId, agent_uuid, computerName
| eval risk_score = case(
        classification="Ransomware", 90,
        confidenceLevel="malicious", 70,
        true(), 50)
| eval risk_object = lower(computerName), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_technique = mitre.techniques{}
```

**High-confidence ransomware on any endpoint — escalate immediately.**
```
sourcetype=sentinelone:channel:threats
    classification="Ransomware" confidenceLevel="malicious"
| stats values(threatName) values(filePath) values(processName)
        latest(mitigationStatus) latest(analystVerdict) latest(incidentStatus)
        by computerName, agent_uuid
```

**Post-mitigation persistence — same threat reappearing on the same endpoint within 24h.**
```
sourcetype=sentinelone:channel:threats earliest=-24h
| stats count dc(threatId) as threats values(threatName) by computerName, fileHash
| where threats > 1
```

**Lateral-movement engine fires — prioritise.**
```
sourcetype=sentinelone:channel:threats engines{}="Lateral Movement"
| stats values(threatName) values(processName) values(commandline)
        by computerName, processUser
```

#### Triage workflow and response actions

The main app exposes response actions that update threats from within Splunk via custom search commands (see `splunk-sourcetype-library.md` for setup):

- `sentinelonethreataction` — set `analystVerdict`, `incidentStatus`, `mitigationStatus`, mark threats as benign or true positive.
- `sentineloneagentaction` — agent-level actions: `disconnect` (network isolation), `connect`, `shutdown`, `initiate_scan`, `fetch_logs`.

Typical SOC flow:
1. Triage `sentinelone:channel:threats` events with `analystVerdict=undefined`.
2. Pivot into `sentinelone:cloud:funnel` (if licensed) on the affected endpoint and time window for context.
3. If TP and contained, set `analystVerdict=true_positive` + `incidentStatus=resolved`.
4. If TP and active, `sentineloneagentaction action_type=disconnect` to isolate, then continue investigation.
5. If FP, set `analystVerdict=false_positive` + `markedAsBenign=true` (auto-feeds the engine for future suppression).

---

### `sentinelone:channel:agents`

Endpoint device inventory. One record per managed endpoint. Use as the source of truth for "what hosts have a SentinelOne agent" and the basis for coverage gap analysis.

**What it covers:** all currently-managed endpoints — operational status, agent version, OS, last-active time, mitigation mode, network connectivity to the console.

**Typical CIM mapping:** `Inventory` (asset enrichment for ES Assets & Identities via `SA-SentinelOneDevices`).

#### Field schema

**Identity:**

| Field | Meaning |
|---|---|
| `agent_uuid` / `id` | Stable agent identifier |
| `computerName` | Endpoint hostname |
| `domain` | Domain / workgroup the endpoint is joined to |
| `externalIp` / `lastIpToMgmt` | Public-side IP last seen reaching the console |
| `lastLoggedInUserName` | Last interactively logged-in user (verify against installed app version) |
| `serialNumber` | Hardware serial (where exposed by the OS) |

**OS / agent metadata:**

| Field | Meaning | Common values |
|---|---|---|
| `osName` | Marketing OS name | `Windows 11`, `Windows Server 2022`, `Ubuntu 22.04`, `macOS 14`, etc. |
| `osType` | Family | `windows`, `linux`, `macos` |
| `osArch` | Architecture | `64 bit`, `32 bit` |
| `osVersion` | Kernel / build version | OS-specific |
| `agentVersion` | SentinelOne agent version | `23.x`, `24.x` etc. |
| `appsVulnerabilityStatus` | Vulnerability scan state | `up_to_date`, `patch_required`, `not_applicable` |
| `consoleMigrationStatus` | Console-migration in-progress flag | Mostly `N/A` |

**Operational state:**

| Field | Meaning | Values |
|---|---|---|
| `isActive` | Agent reporting recently | `true` / `false` |
| `isUpToDate` | Agent on latest version per policy | `true` / `false` |
| `isPendingUninstall` | Uninstall queued | `true` / `false` |
| `decommissioned` | Soft-deleted from console | `true` / `false` |
| `infected` | At least one unresolved threat present | `true` / `false` |
| `inRemoteShellSession` | Active remote-shell session in progress | `true` / `false` |
| `networkStatus` | Network reachability | `connected`, `disconnected`, `connecting`, `disconnecting` |
| `lastActiveDate` | Last check-in timestamp | ISO-8601 |
| `registeredAt` | First console enrolment timestamp | ISO-8601 |

**Mitigation policy state:**

| Field | Meaning | Values |
|---|---|---|
| `mitigationMode` | Policy response to malicious threats | `protect`, `detect` |
| `mitigationModeSuspicious` | Policy response to suspicious threats | `protect`, `detect`, `disabled` |
| `policy.*` | Per-feature policy state | Many sub-fields — agent UI password, scan schedule, remote-shell, deep-visibility on/off |

**Site / group:**

| Field | Meaning |
|---|---|
| `siteName` | Site the agent belongs to |
| `groupName` | Group the agent belongs to |
| `groupType` | `static` / `dynamic` |
| `accountName` | Top-level account |

#### Use cases

- **Coverage gap analysis** — join agent inventory against authoritative asset source (AD computer accounts, CMDB, Lansweeper) to find unmonitored endpoints.
- **Mitigation-mode auditing** — find endpoints where `mitigationMode != "protect"` (i.e. detect-only or disabled). High-criticality misconfiguration on production hosts.
- **Stale agent detection** — `lastActiveDate` older than threshold while `decommissioned=false` indicates broken agents.
- **Endpoint enrichment** — feed `computerName`, `osType`, `lastLoggedInUserName`, site, group into the ES Asset Database via `SA-SentinelOneDevices`. Downstream detections then enrich automatically (asset criticality on threat events, etc.).
- **Privileged-host coverage** — confirm DCs / Tier-0 hosts all have `agentVersion` at the latest and `mitigationMode=protect`.

#### Detection patterns

**Endpoints with degraded mitigation mode.**
```
sourcetype=sentinelone:channel:agents
| dedup agent_uuid sortby -_time
| where mitigationMode!="protect" OR mitigationModeSuspicious="disabled"
| stats values(computerName) values(siteName) values(groupName) by mitigationMode, mitigationModeSuspicious
```

**Stale agents (no check-in in 7 days, not decommissioned).**
```
sourcetype=sentinelone:channel:agents
| dedup agent_uuid sortby -_time
| eval days_stale = floor((now() - strptime(lastActiveDate, "%Y-%m-%dT%H:%M:%S.%QZ")) / 86400)
| where days_stale > 7 AND decommissioned="false"
| table computerName siteName groupName agentVersion days_stale
```

**Coverage gap (AD has it, SentinelOne does not).**
```
| inputlookup ad_computers
| eval cn = lower(name)
| join type=left cn [
    search sourcetype=sentinelone:channel:agents
    | dedup agent_uuid sortby -_time
    | eval cn = lower(computerName)
    | fields cn agent_uuid lastActiveDate ]
| where isnull(agent_uuid)
| table cn os_version dn
```

---

### `sentinelone:channel:activities`

Console activity stream — every administrative action, agent state transition, and policy change generates an activity. The numeric `activityType` field is the discriminator.

**What it covers:** admin logons to the console, policy modifications, agent state changes (uninstall, disable, enable), threat lifecycle changes, site / group / user lifecycle, scheduled and on-demand actions.

**Typical CIM mapping:** `Change`.

#### Field schema

| Field | Meaning |
|---|---|
| `activityType` | Numeric activity ID — see canonical list below |
| `activityUuid` / `id` | Unique activity identifier |
| `description` | Resolved human-readable description |
| `primaryDescription` | Primary description string template |
| `secondaryDescription` | Supplementary description string template |
| `data.*` | Per-activity payload — fields differ by activityType |
| `userId` | Console user who initiated the activity (where applicable) |
| `userEmail` | Email of console user |
| `agentId` / `agentUuid` | Agent the activity targeted (where applicable) |
| `siteName` / `accountName` | Scope of the activity |
| `osFamily` | Target OS family (where applicable) |

#### Canonical `activityType` reference

> **Version-sensitive.** SentinelOne reuses numeric `activityType` IDs across product evolution and adds new IDs over time. The list below covers high-detection-value IDs in long-stable use, but **verify the canonical list against the running app / console version** — IDs occasionally shift between major releases.

**Agent lifecycle (high-value for tampering / persistence detection):**

| ID | Meaning | Detection value |
|---|---|---|
| 27 | Agent uninstalled | T1562.001 — Disable / Modify Tools |
| 65 | Agent disabled | T1562.001 |
| 66 | Agent enabled | Pair with 65 to detect short-lived disable windows |
| 110 | Disconnected from network (manual containment) | Often legitimate IR; correlate with threats |
| 128 | Agent connected to network | |

**Console authentication / session:**

| ID | Meaning | Detection value |
|---|---|---|
| 71 | Console user login (success) | Source IP enrichment for unusual-location detection |
| 72 | Console user logout | |
| 73 | Console user login failed | Console-account brute force |
| 74 | Console user password changed | |
| 79 | Two-factor authentication failed | |
| 1001 | User invited | New console user lifecycle |
| 1003 | User deleted | |

**Threat lifecycle (mirror of channel:threats but action-oriented):**

| ID | Meaning |
|---|---|
| 78 | Threat resolved |
| 80 | Threat marked as benign |
| 81 | Threat marked as in-progress |
| 1701 | Threat verdict changed by user |

**Policy / configuration:**

| ID | Meaning | Detection value |
|---|---|---|
| 86 | Policy modified | T1562 — security configuration weakening |
| 87 | Group / site policy override | |
| 90 | Exclusion added | T1562.006 — Indicator Blocking — watch closely |
| 91 | Exclusion removed | |

**Site / group / account lifecycle:**

| ID | Meaning |
|---|---|
| 4001 | Site created |
| 4002 | Site deleted |
| 4003 | Site updated |
| 4004 | Group created |
| 4005 | Group deleted |
| 4007 | Group updated |

> The full enumerated list runs to several hundred IDs. The IDs above are the high-detection-value subset. For the complete current list, query SentinelOne API metadata or inspect `sentinelone_app_for_splunk` lookup files (`activity_types.csv` or equivalent — name varies by app version).

#### Detection patterns

**Agent disabled or uninstalled — likely T1562 (Impair Defenses).**
```
sourcetype=sentinelone:channel:activities activityType IN (27, 65)
| stats latest(_time) as last_seen
        values(description) as activity
        values(userEmail) as console_user
        by agentId computerName
| eval risk_score = if(activityType=27, 80, 60)
| eval risk_object = lower(computerName), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_tactic = "defense-evasion"
| eval annotations.mitre_attack.mitre_technique = "T1562.001"
```

**New exclusion added — defence evasion.**
```
sourcetype=sentinelone:channel:activities activityType=90
| stats values(data.exclusionPath) values(data.exclusionType)
        values(userEmail) by siteName accountName
```

**Console login from new geographic region (lookup-driven IP allowlist).**
```
sourcetype=sentinelone:channel:activities activityType=71
| iplocation src_ip
| lookup console_login_geos_allowlist Country OUTPUT allowed
| where allowed!="yes"
| stats latest(_time) values(src_ip) values(City) values(Country)
        by userEmail
```

**Policy weakening — sudden burst of policy modifications.**
```
sourcetype=sentinelone:channel:activities activityType IN (86, 90)
| bin _time span=10m
| stats count values(userEmail) by _time, siteName
| where count > 5
```

---

### `sentinelone:channel:applications`

Installed application inventory across all managed endpoints. One record per (endpoint, application) tuple.

**What it covers:** software discovery — name, version, publisher, install date, code-signing state, per endpoint.

#### Field schema

| Field | Meaning |
|---|---|
| `name` / `applicationName` | Application name |
| `version` / `applicationVersion` | Application version string |
| `publisher` / `vendor` | Publisher / vendor name |
| `installedDate` | First-seen install timestamp |
| `signed` | Code-signing state — `true` / `false` |
| `endpointName` / `computerName` | Host the app is installed on |
| `endpointId` / `agent_uuid` | Agent identifier |
| `osType` | OS family of the host |
| `installPath` | Install location (verify against installed app version — not always populated) |
| `size` | Installed size (verify against installed app version) |

#### Use cases

- **Software inventory baseline** — basis for "is X installed anywhere" queries.
- **Vulnerable software discovery** — pair with `application_management:risks` to prioritise patching.
- **Unauthorised software detection** — match against denylist of remote-access tools, hacking utilities, anonymisation software.
- **License compliance** — count installed instances of paid software.

#### Detection pattern

**Unauthorised remote-access tool detection.**
```
sourcetype=sentinelone:channel:applications
    name IN ("AnyDesk", "TeamViewer", "Splashtop", "ScreenConnect", "ConnectWise Control", "Remote Utilities", "Atera Networks")
| dedup endpointId name sortby -_time
| stats values(version) values(publisher) values(installedDate)
        by endpointName name
```

---

### `sentinelone:channel:application_management:risks`

Vulnerability findings on installed software. Driven by SentinelOne's vulnerability management (CVE-correlation) feature, which licks application inventory against the published CVE database.

**Typical CIM mapping:** `Vulnerabilities`.

#### Field schema

| Field | Meaning |
|---|---|
| `cveId` | CVE identifier (e.g. `CVE-2024-12345`) |
| `severity` | Severity bucket — `Critical`, `High`, `Medium`, `Low` |
| `cvssScore` | Numeric CVSS v3 base score |
| `cvssVector` | CVSS attack vector string |
| `applicationName` | Affected application |
| `applicationVersion` | Affected version |
| `endpointId` / `agent_uuid` | Agent on which the vulnerable app is installed |
| `endpointName` / `computerName` | Hostname |
| `riskLevel` | SentinelOne aggregated risk classification |
| `exploitability` | Exploit-availability indicator — `none`, `poc`, `weaponized`, `in_the_wild` (verify against installed app version — naming varies) |
| `patchAvailable` | Patch status — `true` / `false` |
| `patchVersion` | Version that fixes the CVE (where known) |
| `firstSeen` | First-seen timestamp for this finding |

#### Use cases

- **Vuln-management feed for ES** — populate the `Vulnerabilities` data model so that other detections can risk-weight by host vuln load.
- **Prioritisation by exploitability + asset criticality** — high-CVSS + weaponised + Tier-0 host = top of patch queue.
- **Patch-availability gap** — vulnerabilities where `patchAvailable=true` but the host has not received the patch within SLA window.

#### Detection pattern

**Critical CVE on a Tier-0 host with a known weaponised exploit.**
```
sourcetype=sentinelone:channel:application_management:risks
    severity="Critical" exploitability IN ("weaponized", "in_the_wild")
| lookup asset_lookup_by_str host AS computerName OUTPUT category, priority
| where priority="critical"
| stats values(cveId) values(applicationName) values(applicationVersion)
        by computerName
```

---

### `sentinelone:channel:groups` and `sentinelone:channel:policies`

Console structure and configuration. Briefer treatment — these channels are primarily for change auditing and dashboard population, not for real-time detection.

**`sentinelone:channel:groups`:** group hierarchy, dynamic group filters, member counts, parent site.

**`sentinelone:channel:policies`:** policy definitions per group/site — agent UI password, mitigation mode, deep-visibility config, exclusions.

**Key fields:** `name`, `siteName`, `groupType`, `policyMode`, `agentUiVisible`, `deepVisibilityEnabled`, `firewallControl`, `deviceControl`.

**Use cases:**
- Audit trail correlation — when `activities` shows a policy change, the new state can be retrieved from `policies`.
- Configuration drift detection — compare current policy fields against a known-good baseline.

---

## Deep Visibility / Cloud Funnel

Cloud Funnel (XDR firehose) carries SentinelOne's Deep Visibility telemetry — the rich endpoint event data analogous to Sysmon. Separate paid licensing tier from base EPP/EDR.

**Sourcetype:** `sentinelone:cloud:funnel` (JSON; one event per endpoint observation).

**Volume:** very high. Selectively enable categories rather than blanket-enable. Process-create alone on a moderately busy fleet exceeds Sysmon's volume by a meaningful margin because Cloud Funnel includes more metadata per event.

**Sysmon-equivalence note:** for each Cloud Funnel category below, the equivalent Sysmon EID is listed where one exists. Detection content authored against Sysmon is largely portable to Cloud Funnel with field renames; see `windows-event-log-reference.md` for the Sysmon side.

#### Common Cloud Funnel envelope

| Field | Meaning |
|---|---|
| `event.category` | Event category — `process`, `file`, `network`, `registry`, `dns`, `image_load`, `cross_process`, `login`, `scheduled_task` |
| `event.type` | Subtype — `creation`, `termination`, `modification`, `deletion`, `rename`, `query`, `response`, etc. |
| `event.time` | Event observation time |
| `agent.uuid` | Agent UUID — joins to channel events |
| `endpoint.name` | Hostname |
| `endpoint.os.name` | Operating system |
| `event.id` | Unique event identifier in Cloud Funnel |
| `trace.id` | Cross-event trace identifier (pivot key) |

> Cloud Funnel field names follow a dotted-namespace convention (`src_process.name`, `tgt_file.path`). Search-time field extraction in the TA flattens these to `src_process_name` / `tgt_file_path` style. **Both naming forms appear in saved searches; check the installed app/TA's field aliases.**

---

### Process events

**`event.category=process`** — process create, terminate, modify (image hollowing-like).

**Equivalent Sysmon EIDs:** 1 (process create), 5 (process terminate), 25 (process tampering).

#### Field schema

| Field | Meaning |
|---|---|
| `src_process_uid` / `src_process_pid` | Initiating process identifiers |
| `src_process_name` | Initiating process name |
| `src_process_cmdline` | Initiating process command line |
| `src_process_image_path` | Image path on disk |
| `src_process_image_sha1` / `src_process_image_sha256` | Hashes |
| `src_process_image_md5` | (verify against installed app version) |
| `src_process_signature_signed` | Signed flag |
| `src_process_signature_signer` | Signing identity |
| `src_process_integrity_level` | Integrity level — `low`, `medium`, `high`, `system` (friendly text, not SID — unlike Windows 4688) |
| `src_process_user` | Owning user |
| `src_process_session_id` | Logon session ID |
| `tgt_process_uid` / `tgt_process_pid` | New process identifiers |
| `tgt_process_name` | New process name |
| `tgt_process_cmdline` | New process command line |
| `tgt_process_image_path` | New process image path |
| `tgt_process_image_sha1` / `tgt_process_image_sha256` | New process hashes |
| `tgt_process_signature_signed` | Signed flag |
| `tgt_process_parent_uid` | Parent process UID — chains to parent's `src_process_uid` |

For process trees, `tgt_process_uid` / `src_process_uid` survive PID reuse (analogous to Sysmon's `ProcessGuid`) — prefer over PID for correlation.

#### Detection patterns

**Suspicious child of Office (T1566.001 / T1059).**
```
sourcetype=sentinelone:cloud:funnel
    event.category=process event.type=creation
    src_process_name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
    tgt_process_name IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| stats values(src_process_cmdline) values(tgt_process_cmdline)
        by endpoint.name, src_process_name, tgt_process_name
| eval risk_score = 60
| eval risk_object = lower('endpoint.name'), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_tactic = "execution"
| eval annotations.mitre_attack.mitre_technique = "T1059"
```

**LOLBin parent-child anomalies.**
```
sourcetype=sentinelone:cloud:funnel event.category=process event.type=creation
    tgt_process_name="rundll32.exe" tgt_process_cmdline="*javascript:*"
```

**Unsigned PE executing from user-writable path.**
```
sourcetype=sentinelone:cloud:funnel event.category=process event.type=creation
    tgt_process_signature_signed=false
    (tgt_process_image_path="*\\AppData\\Local\\Temp\\*"
     OR tgt_process_image_path="*\\AppData\\Roaming\\*"
     OR tgt_process_image_path="*\\Users\\Public\\*")
| stats values(tgt_process_cmdline) by endpoint.name, tgt_process_image_path
```

---

### File events

**`event.category=file`** — file_creation, file_modification, file_deletion, file_rename.

**Equivalent Sysmon EIDs:** 11 (file create), 23/26 (file delete with/without archival), 2 (file create-time changed), 15 (alternate data stream).

| Field | Meaning |
|---|---|
| `tgt_file_path` | Target file path |
| `tgt_file_name` | File name |
| `tgt_file_extension` | File extension |
| `tgt_file_size` | File size |
| `tgt_file_sha1` / `tgt_file_sha256` | Target file hashes |
| `tgt_file_md5` | (verify against installed app version) |
| `tgt_file_old_path` | Pre-rename path (for rename events) |
| `tgt_file_creation_time` | File creation time |
| `tgt_file_modification_time` | File modification time |
| `tgt_file_signature_signed` | Signed flag for PE files |
| `src_process_*` | Initiating process — same fields as process category, identifies *who* did the file operation |

#### Detection patterns

**Mass file modification (ransomware-like) from a single process.**
```
sourcetype=sentinelone:cloud:funnel event.category=file event.type=modification
| bin _time span=1m
| stats dc(tgt_file_path) as files
        values(tgt_file_extension) as extensions
        by _time, endpoint.name, src_process_uid, src_process_name
| where files > 200
| eval risk_score = 90
| eval risk_object = lower('endpoint.name'), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_tactic = "impact"
| eval annotations.mitre_attack.mitre_technique = "T1486"
```

**File written to startup folder (T1547.001).**
```
sourcetype=sentinelone:cloud:funnel event.category=file event.type=creation
    tgt_file_path IN ("*\\Startup\\*", "*\\Start Menu\\Programs\\Startup\\*")
| stats values(src_process_name) values(src_process_cmdline)
        by endpoint.name, tgt_file_path
```

**Unsigned executable persistence in user-writable path.**
```
sourcetype=sentinelone:cloud:funnel event.category=file event.type=creation
    tgt_file_extension IN ("exe", "dll", "scr")
    tgt_file_signature_signed=false
    (tgt_file_path="*\\AppData\\Roaming\\*" OR tgt_file_path="*\\Temp\\*")
| stats count by endpoint.name, src_process_name, tgt_file_path, tgt_file_sha256
```

---

### Network events

**`event.category=network`** — TCP / UDP connections in either direction.

**Equivalent Sysmon EID:** 3 (network connect).

| Field | Meaning |
|---|---|
| `src_ip` | Source IP |
| `src_port` | Source port |
| `dst_ip` | Destination IP |
| `dst_port` | Destination port |
| `protocol` | `tcp` / `udp` |
| `network_direction` | `outbound` / `inbound` (verify against installed app version — naming varies; some versions use `event.network.direction`) |
| `network_url` | DNS-resolved name where Cloud Funnel correlated DNS context (verify against installed app version) |
| `bytes_sent` / `bytes_received` | Octet counts (verify against installed app version) |
| `src_process_*` | Initiating process |

#### Detection patterns

**Outbound connection from a non-browser process to non-RFC1918 host.**
```
sourcetype=sentinelone:cloud:funnel event.category=network
    network_direction=outbound
    NOT src_process_name IN ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "outlook.exe")
    NOT cidrmatch("10.0.0.0/8", dst_ip)
    NOT cidrmatch("172.16.0.0/12", dst_ip)
    NOT cidrmatch("192.168.0.0/16", dst_ip)
| stats dc(dst_ip) as unique_dst values(dst_port) by endpoint.name, src_process_name
| where unique_dst > 1
```

**Beacon-like periodicity.**
```
sourcetype=sentinelone:cloud:funnel event.category=network network_direction=outbound
| stats list(_time) as times count by endpoint.name, src_process_uid, dst_ip, dst_port
| where count > 20
| eval intervals = mvmap(mvrange(1, mvcount(times)),
                         tonumber(mvindex(times, mvrange-0)) - tonumber(mvindex(times, mvrange-0-1)))
| eventstats stdev(intervals) as jitter avg(intervals) as period
| where jitter < 5 AND period > 30
```

---

### Registry events

**`event.category=registry`** — registry_creation, registry_modification, registry_deletion, registry_rename.

**Equivalent Sysmon EIDs:** 12 (key create/delete), 13 (value set), 14 (key/value rename).

| Field | Meaning |
|---|---|
| `registry_path` | Full path including hive (e.g. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\foo`) |
| `registry_key` | Key portion only |
| `registry_value_name` | Value name |
| `registry_value_type` | Value type — `REG_SZ`, `REG_DWORD`, `REG_BINARY`, etc. |
| `registry_value_data` | New value data |
| `registry_old_value_data` | Previous value data (for modification) |
| `registry_old_path` | Pre-rename path |
| `src_process_*` | Initiating process |

#### Detection patterns

**Run-key persistence (T1547.001).**
```
sourcetype=sentinelone:cloud:funnel event.category=registry event.type IN (creation, modification)
    registry_path IN (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")
| stats values(registry_value_data) values(src_process_name) values(src_process_cmdline)
        by endpoint.name, registry_path
```

**Defender tampering — disable real-time protection via registry.**
```
sourcetype=sentinelone:cloud:funnel event.category=registry event.type=modification
    registry_path="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\*"
    registry_value_name IN ("DisableAntiSpyware", "DisableRealtimeMonitoring")
    registry_value_data="1"
```

---

### DNS events

**`event.category=dns`** — DNS queries and responses (where Cloud Funnel observes them at the agent).

**Equivalent Sysmon EID:** 22 (DNS query).

| Field | Meaning |
|---|---|
| `dns_query_name` | Queried name |
| `dns_query_type` | Query type — `A`, `AAAA`, `TXT`, `MX`, `CNAME`, `PTR`, etc. |
| `dns_response_code` | Response code — `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED` |
| `dns_response_addresses{}` | Multi-value: resolved IP addresses |
| `src_process_*` | Process that issued the query |

#### Detection patterns

**TXT-record query (DNS exfil / C2 channel — T1071.004).**
```
sourcetype=sentinelone:cloud:funnel event.category=dns dns_query_type=TXT
| stats count dc(dns_query_name) as unique_queries by endpoint.name, src_process_name
| where unique_queries > 50
```

**DGA-like pattern — high entropy domain queries from a single process.**
```
sourcetype=sentinelone:cloud:funnel event.category=dns dns_query_type=A
| eval domain = mvindex(split(dns_query_name, "."), -2) . "." . mvindex(split(dns_query_name, "."), -1)
| eval entropy = ... [domain entropy calc]
| stats avg(entropy) as avg_entropy count by endpoint.name, src_process_name
| where avg_entropy > 4 AND count > 30
```

---

### Image load events

**`event.category=image_load`** — module loads (DLLs). Equivalent to Sysmon EID 7.

| Field | Meaning |
|---|---|
| `module_path` | Loaded module path |
| `module_sha1` / `module_sha256` | Module hashes |
| `module_signature_signed` | Signed flag |
| `module_signature_signer` | Signing identity |
| `src_process_*` | Process loading the module |

**Detection focus:** DLL sideloading (signed binary loading attacker DLL from same directory), suspicious DLL injected into trusted processes, unsigned modules in `lsass.exe` / `services.exe` etc.

#### Pattern: signed Windows process loading unsigned DLL from user-writable path.
```
sourcetype=sentinelone:cloud:funnel event.category=image_load
    src_process_signature_signed=true
    module_signature_signed=false
    module_path IN ("*\\AppData\\*", "*\\Temp\\*", "*\\Users\\Public\\*")
| stats values(module_path) values(module_sha256) by endpoint.name, src_process_image_path
```

---

### Cross-process events

**`event.category=cross_process`** — `open_process` and `thread_remote_creation` (process injection patterns). Equivalent to Sysmon EIDs 8 (CreateRemoteThread) and 10 (ProcessAccess).

| Field | Meaning |
|---|---|
| `src_process_*` | Initiating (caller) process |
| `tgt_process_*` | Target process |
| `granted_access` | Access mask (for open_process — bitmask of requested rights) |
| `call_trace` | Stack trace of the call (verify against installed app version — present in some configs) |

#### Detection patterns

**LSASS access (T1003.001 — credential dumping).**
```
sourcetype=sentinelone:cloud:funnel event.category=cross_process event.type=open_process
    tgt_process_name="lsass.exe"
| eval ga = tonumber(granted_access, 16)
| where (ga AND 0x10) > 0 OR (ga AND 0x400) > 0   /* PROCESS_VM_READ | PROCESS_QUERY_INFORMATION */
| stats values(src_process_image_path) values(src_process_cmdline) by endpoint.name
| eval risk_score = 80
| eval annotations.mitre_attack.mitre_technique = "T1003.001"
```

**Remote thread creation into a non-self process (T1055).**
```
sourcetype=sentinelone:cloud:funnel event.category=cross_process event.type=thread_remote_creation
    src_process_uid != tgt_process_uid
| stats count values(src_process_name) values(tgt_process_name) values(tgt_process_image_path)
        by endpoint.name, src_process_uid
```

---

### Login events

**`event.category=login`** — interactive, network, RDP, WinRM logons observed by the agent. Equivalent to Windows Security 4624 / 4625.

| Field | Meaning |
|---|---|
| `login_type` | `interactive`, `network`, `rdp`, `winrm`, `service`, `batch`, `cached` (verify against installed app version — exact strings vary) |
| `login_result` | `success`, `failure` |
| `target_user_name` | Logged-on user |
| `src_ip` | Source IP for network/RDP logons |
| `process_name` | Process handling the logon (e.g. `lsass.exe`, `svchost.exe`) |

Cross-reference: see `windows-event-log-reference.md` for full Windows logon-type semantics; the Cloud Funnel `login_type` values map closely to Windows `LogonType` numerics.

---

## CEF threat format

For environments ingesting via syslog rather than the channel API. SentinelOne forwards threat and activity events as CEF (Common Event Format) over syslog, typically via SC4S.

**Sourcetype:** `sentinelone:syslog:cef`.

#### CEF header

```
CEF:0|SentinelOne|Mgmt|<version>|<event_id>|<event_name>|<severity>|<extension>
```

| Header field | Meaning |
|---|---|
| Vendor | `SentinelOne` |
| Product | `Mgmt` (or similar — varies by deployment) |
| Version | Console version |
| Event Class ID | Numeric — corresponds to `activityType` for activities, internal threat IDs for threats |
| Name | Human-readable event name |
| Severity | Numeric 0–10 |

#### CEF-to-channel field mapping

The same logical event has different field names in CEF vs the channel API. Detection logic written against one needs translation to apply to the other.

| Channel API field | CEF extension | Notes |
|---|---|---|
| `threatName` | `fname` or `cs1` (threat name) | CEF custom-string mapping varies by version |
| `filePath` | `filePath` | |
| `fileHash` / `sha1` | `fileHash` | SHA1 only — CEF often drops MD5/SHA256 |
| `processName` | `dproc` | |
| `commandline` | `act` or `cs6` (verify) | |
| `computerName` | `dhost` | |
| `agent_uuid` | `dvchost` or custom-string mapping | |
| `classification` | `cat` | |
| `confidenceLevel` | `cs2` (verify) | Often coalesced into severity number |
| `mitigationStatus` | `act` | Typically encoded as action verb (`Quarantined`, `Killed`, `Blocked`) |
| `analystVerdict` | (not carried) | CEF feed lacks analyst-disposition lifecycle |
| `mitre.tactics[]` | (not carried in standard mapping) | Frequently absent in CEF |

#### What CEF loses

- Multi-value lifecycle data (`engines[]`, `mitre.techniques[]`, `indicators[]`) typically flattens or drops.
- `analystVerdict` / `incidentStatus` — CEF feeds the initial detection event only; analyst lifecycle updates do not always re-emit.
- `markedAsBenign` — same.
- Hash variety — CEF carries one hash field; channel API carries multiple.
- Activity payload — `data.*` sub-fields on activities collapse into a description string.

**Practical guidance:** if both ingestion paths are available, **prefer the channel API** for detection content. CEF is acceptable for environments where API polling is operationally undesirable, but accept reduced fidelity.

> **Eventtype abstraction.** If ingesting from both paths, define eventtypes that abstract field-name differences (e.g. `eventtype=sentinelone_threat` aliasing both `sourcetype=sentinelone:channel:threats` and `sourcetype=sentinelone:syslog:cef` plus their respective hash field names into a common alias). Saved searches then key on the eventtype rather than per-sourcetype branches.

---

## Detection-relevant patterns

High-value detections worked end-to-end. Risk-scoring grid follows `splunk-detection-patterns.md`; calibrate thresholds to environment baseline.

### 1. Mitigation failure on a high-confidence threat

**What:** Agent flagged the file as malicious but did not (or could not) mitigate. Indicates either policy in `detect-only` mode, agent-out-of-date, or the threat's mitigation action failed.

**Channel:** `sentinelone:channel:threats`.

```
sourcetype=sentinelone:channel:threats
    confidenceLevel="malicious"
    mitigationStatus IN ("not_mitigated", "partially_mitigated", "pending_user_action")
    analystVerdict!="false_positive"
| stats latest(_time) as last_seen
        latest(threatName) values(classification) values(engines{}) values(filePath)
        by threatId, agent_uuid, computerName
| eval risk_score = 80, risk_object = lower(computerName), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_tactic = "defense-evasion"
```

**MITRE:** TA0005 (Defense Evasion) at minimum; specific technique depends on threat family.
**FP context:** policy intentionally in `detect` mode (audit fleets, jump-box exclusions). Filter by `siteName` if known detect-only sites.

### 2. Agent disabled or uninstalled

**What:** Likely T1562.001 (Disable or Modify Tools). Pre-attack tampering signal.

**Channel:** `sentinelone:channel:activities`.

```
sourcetype=sentinelone:channel:activities activityType IN (27, 65)
| stats values(description) values(userEmail) by agentId, computerName
| eval risk_score = if(activityType=27, 80, 60)
| eval risk_object = lower(computerName), risk_object_type = "system"
| eval annotations.mitre_attack.mitre_technique = "T1562.001"
```

**FP context:** approved decommission via change ticket — correlate against ticketing-system lookup. Approved patch / OS upgrade workflow that re-images the host.

### 3. Console admin login from unusual IP

**What:** Console-level credential compromise indicator.

**Channel:** `sentinelone:channel:activities` activityType=71.

```
sourcetype=sentinelone:channel:activities activityType=71
| iplocation src_ip
| lookup console_admin_ip_allowlist src_ip OUTPUT allowed
| where allowed!="yes"
| stats latest(_time) values(City) values(Country) by userEmail, src_ip
| eval risk_score = 60, risk_object = userEmail, risk_object_type = "user"
| eval annotations.mitre_attack.mitre_technique = "T1078.004"
```

### 4. Endpoint coverage gap

**What:** Hosts in authoritative inventory (AD, CMDB) that lack a SentinelOne agent.

**Channel:** `sentinelone:channel:agents` joined against asset inventory.

See agents channel section for the SPL pattern. Output drives a saved-search reporting dashboard — typically not RBA-emitting since "missing host" is not bound to a time window.

### 5. Process injection chain via Cloud Funnel

**What:** Cross-process injection followed by network connection from the injected process — classic implant pattern.

**Channel:** `sentinelone:cloud:funnel`.

```
sourcetype=sentinelone:cloud:funnel earliest=-1h
    (event.category=cross_process event.type IN (open_process, thread_remote_creation))
    OR (event.category=network network_direction=outbound)
| eventstats values(eval(if(event.category="cross_process", tgt_process_uid, null()))) as injected_uids
            by endpoint.name
| where event.category="network" AND src_process_uid IN injected_uids
| stats values(src_process_name) values(dst_ip) values(dst_port) by endpoint.name, src_process_uid
| eval risk_score = 75
| eval annotations.mitre_attack.mitre_technique = "T1055"
```

### 6. LSASS access pattern (T1003.001)

**What:** Cross-process events targeting `lsass.exe` with credential-dump-relevant access rights.

**Channel:** `sentinelone:cloud:funnel`. See cross-process section above.

**FP context:** legitimate AV / EDR processes (the SentinelOne agent itself, Defender, etc.). Maintain an allowlist of expected `src_process_image_path` values.

### 7. Suspicious child of Office

**What:** Phishing payload execution chain — Word/Excel/Outlook spawning a script interpreter.

**Channel:** `sentinelone:cloud:funnel`. See process events section.

**MITRE:** T1566.001 (Spearphishing Attachment) into T1059 (Command and Scripting Interpreter).
**FP context:** legitimate Office macros in regulated environments — narrow to non-allowlisted parent SHA / signature.

### 8. Mass file modification (ransomware-like)

**What:** High-volume file_modification events from a single process within a short window — encryption or large-scale tampering signature.

**Channel:** `sentinelone:cloud:funnel`. See file events section.

**MITRE:** T1486 (Data Encrypted for Impact).
**FP context:** backup software (Veeam, CommVault), bulk-rename utilities, dev workflows compiling many files. Allowlist by `src_process_image_path` + signing publisher.

### 9. Unsigned executable persistence

**What:** Unsigned PE created in user-writable path that subsequently executes — staged payload pattern.

**Channel:** `sentinelone:cloud:funnel`. Two-stage join (file create → process create on same path).

```
sourcetype=sentinelone:cloud:funnel event.category=file event.type=creation
    tgt_file_extension="exe" tgt_file_signature_signed=false
    (tgt_file_path="*\\AppData\\Roaming\\*" OR tgt_file_path="*\\Temp\\*")
| rename tgt_file_path AS image_path
| join type=inner endpoint.name image_path [
    search sourcetype=sentinelone:cloud:funnel event.category=process event.type=creation
    | rename tgt_process_image_path AS image_path
    | fields endpoint.name, image_path, tgt_process_cmdline, _time ]
| stats values(tgt_process_cmdline) values(src_process_name) by endpoint.name, image_path
| eval risk_score = 70
| eval annotations.mitre_attack.mitre_technique = "T1547"
```

### 10. Defender exclusion added via console

**What:** Exclusion path / process / extension added to SentinelOne policy — defence evasion via legitimate config channel.

**Channel:** `sentinelone:channel:activities` activityType=90.

```
sourcetype=sentinelone:channel:activities activityType=90
| stats values(data.exclusionPath) values(data.exclusionType)
        values(userEmail) by siteName, accountName
| eval risk_score = 50, risk_object = userEmail, risk_object_type = "user"
| eval annotations.mitre_attack.mitre_technique = "T1562.006"
```

---

## Common gotchas

- **Multi-console / multi-tenant deployments.** Filter by `console`, `accountId`, or `siteId` in queries. Searches without scope return cross-tenant data and produce inflated counts and confusing dashboards. This is the single most common SentinelOne-Splunk pitfall in larger environments.

- **Channel input lag and silent stalls.** Channel inputs can fail silently (HTTPSConnectionPool errors, 500 responses) without producing visible error events in the main indexes. The signal is `index=_internal sourcetype=sentinelone_app_for_splunk:error`. Pre-v6.0.0 versions need manual restart; v6.0.0+ auto-restart after 25h of stalled state. Detection content does not see this; ingestion-health monitoring is a separate concern.

- **Channel API rate limiting.** Large environments hitting 429 (Too Many Requests) responses during initial backfill produce visible ingestion gaps. Channel inputs do not retry indefinitely; backfill may need to be staged across multiple inputs with offset polling intervals.

- **`mitigationStatus` ≠ threat resolution.** A threat can be `mitigated` (agent acted) but `incidentStatus=unresolved` (analyst has not yet dispositioned). Detection content keying on `mitigationStatus` alone misses the analyst-lifecycle dimension.

- **`analystVerdict` lifecycle.** `undefined` is the default state — the threat awaits review. `false_positive` indicates analyst-determined FP. SOC content should treat `undefined` as "needs review" and not as "not malicious".

- **Threat fields populated lazily.** Initial threat events frequently have empty `mitre.tactics[]` / `mitre.techniques[]` / `indicators[]` arrays; later updates populate them once cloud analysis completes. Detection content should account for both states (key on `classification` / `engines{}` for early-state events) or wait for stable state via `stats latest(...) by threatId`.

- **Cloud Funnel volume.** Deep Visibility produces enormous data volume — process create alone on a moderately busy fleet exceeds Sysmon's volume by a meaningful margin. Selectively enable categories rather than blanket-enable. Process / file / cross-process / network are the highest-value categories; image_load is the highest volume per detection-value ratio.

- **Field renames across app versions.** Pre-v5 of `sentinelone_app_for_splunk` used flatter sourcetypes (`sourcetype=agent`, `sourcetype=group`, etc.) without the `sentinelone:channel:` prefix. Old saved searches written against pre-v5 sourcetypes break silently after upgrade; the searches return zero results without throwing errors. Audit macro definitions and saved-search sourcetype clauses on every app upgrade.

- **Multi-host ingestion topology.** App, TA, and IA must not co-locate. Recommended placement is App on search head, TA on indexers (or heavy forwarders), IA on collection forwarders. Co-location duplicates modular inputs and produces double ingestion. See `splunk-sourcetype-library.md` SentinelOne section for the full topology.

- **CEF vs channel API field naming.** Same logical events have different field names across the two ingestion paths. Detection content needs to either pick one path canonically or use eventtype abstraction to bridge them. CEF feeds carry less detail (no analyst lifecycle, fewer hashes, no MITRE arrays).

- **Singularity Data Lake (SDL) integration is separate.** The `Singularity Data Lake Add-On` (Splunkbase 5435) provides federated search rather than ingestion — queries pass through to SDL rather than indexing the data into Splunk. This is a different sourcetype family and licensing model from the main App's ingestion path; do not conflate.

- **API token format quirk.** Some app input configurations require the API token prefixed with `ApiToken ` (literal string with trailing space). Easy to miss in initial setup — symptoms are 401 responses in `:error` sourcetype with no other indication.

- **`activityType` numeric IDs change between versions.** SentinelOne adds new activity types and occasionally re-purposes numeric IDs across major console releases. The canonical list above covers IDs in long-stable use, but **verify against the current console version** before relying on a specific numeric ID for detection. Inspect `sentinelone_app_for_splunk` lookup files (e.g. `activity_types.csv` — exact name varies by app version) for the installed mapping.

- **Hash field availability varies.** SHA1 is the canonical hash on most channel and Cloud Funnel events. SHA256 and MD5 are not always populated — depends on agent platform, file type, and config. Detections keying solely on `sha256` may miss events that only have `sha1`. Prefer `sha1` for cross-platform reliability or coalesce: `eval hash = coalesce(sha256, sha1, md5)`.

- **Cloud Funnel `network_direction` semantics differ from Sysmon.** Sysmon EID 3 is direction-implicit (initiated-by-process is always outbound from the agent's perspective). Cloud Funnel explicitly carries direction; inbound network events exist (server processes accepting connections). Direction-aware detections that worked against Sysmon need adjustment.

- **Process integrity level is friendly text, not SID.** Cloud Funnel's `src_process_integrity_level` is `low`/`medium`/`high`/`system`. Windows 4688's `MandatoryLabel` is a SID string (`S-1-16-12288` etc.). Cross-source detections need to normalise — see `windows-event-log-reference.md` for the SID mapping.

- **Cloud Funnel field-name dotted vs flat.** Some installs use dotted JSON paths (`src_process.name`); the TA flattens to underscore (`src_process_name`). Both forms appear in production saved searches. Always check the installed TA's field aliases before assuming a naming convention.

---

## Appendix: cross-reference quick map

Where to find supporting detail in the sibling docs:

| Topic | Doc |
|---|---|
| Sourcetype shape, app conflicts, install topology, token storage | `splunk-sourcetype-library.md` (SentinelOne section) |
| RBA field shape (`risk_score`, `risk_object`, `risk_object_type`, `threat_object`), MITRE annotation conventions | `splunk-detection-patterns.md` |
| Risk-scoring grid baseline | `splunk-detection-patterns.md` |
| Sysmon equivalents for Cloud Funnel categories | `windows-event-log-reference.md` (Sysmon section) |
| Windows logon-type semantics behind Cloud Funnel `login_type` | `windows-event-log-reference.md` (Logon types table) |
| Mandatory integrity-level SID-to-text mapping (cross-source detection) | `windows-event-log-reference.md` (`MandatoryLabel` SID values) |
| Process-tree reconstruction (Sysmon `ProcessGuid` analogue) | `windows-event-log-reference.md` (Sysmon correlation fields) |
