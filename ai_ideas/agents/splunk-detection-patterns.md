# Splunk Detection Patterns

> Generic reference for detection engineering on Splunk Enterprise Security: risk-based alerting (RBA) field shape and SPL patterns, MITRE ATT&CK annotation conventions, and a practical false-positive catalogue with tuning techniques.
>
> Companion to `splunk-sourcetype-library.md` — that document covers the **shape of the source data**; this one covers the **shape of detections built on top of it**. Where a topic depends on a specific sourcetype's fields (e.g. `EventCode`, `cs_uri_stem`, `eventName`), the library is the reference.

---

## 1. Risk-Based Alerting (RBA)

> RBA decouples low-confidence detection from high-confidence response. Individual atomic detections emit risk events into the `risk` index against an entity (a user, host, or identity). A separate threshold rule watches that index and fires a single notable when accumulated risk on one entity crosses a configured score over a configured window.
>
> The objective is fewer, higher-fidelity findings — instead of a SOC analyst chasing dozens of low-context alerts, they investigate one entity that has accumulated risk from many contributing signals.

### The `risk` index schema

Every event written to the `risk` index follows a consistent field shape regardless of which detection produced it. Detection content that uses the `risk` modular alert action populates these fields automatically; SPL-driven `collect` into `risk` should match the same shape.

| Field | Purpose |
|---|---|
| `risk_score` | Numeric risk contribution from this single detection event (0–100 typical) |
| `risk_object` | Identifier of the entity-being-defended (user samAccountName, host name, identity) |
| `risk_object_type` | Type of risk_object: `user`, `system`, `other` |
| `risk_message` | Free-text human-readable description of why the risk was scored — surfaces in Mission Control |
| `threat_object` | Identifier of an external entity-of-interest (file hash, IP, domain, URL, registry key) |
| `threat_object_type` | Type of threat_object: `file_hash`, `file_name`, `ip_address`, `domain`, `url`, `registry`, `process_name`, `email_address`, `signature`, `certificate_hash`, `other` |
| `annotations.mitre_attack.mitre_tactic` | One or more ATT&CK tactic short names (e.g. `credential-access`, `lateral-movement`) |
| `annotations.mitre_attack.mitre_technique` | Technique IDs (e.g. `T1078`, `T1003`) |
| `annotations.mitre_attack.mitre_subtechnique` | Sub-technique IDs (e.g. `T1003.006`, `T1059.001`) |
| `source` | Name of the detection / correlation search that produced the risk event |
| `search_name` | Same as `source` for ES-generated risk events |
| `_time` | Time of the underlying observable event (not the search execution time) |

Other fields commonly carried through for context: `user`, `src`, `dest`, `signature`, `host`, plus any drilldown fields useful in Mission Control.

### `risk_object` vs `threat_object` — get this right

This is the most common mistake in early RBA deployments. The two concepts are **not** interchangeable.

| | `risk_object` | `threat_object` |
|---|---|---|
| Represents | Entity-being-defended | Entity-of-interest |
| Examples | `alice.smith`, `WKSTN-042`, internal service account | `5d41402abc...` (hash), `185.220.101.5` (Tor exit), `evil.example` (C2 domain) |
| Typically internal? | Yes — it's something you own | No — usually external indicator |
| Risk accumulates against it? | Yes | No |
| Why it matters | These are the things the SOC investigates | These are IOCs that enrich the picture |

**Anti-pattern:** writing the source IP of a brute-force attempt as the `risk_object`. That puts external actor IPs into the risk pool and fires findings against them — useful only if you have an external-actor RBA pipeline, which most environments do not. The defended entity is the **target account** being brute-forced, not the attacker IP. The attacker IP belongs in `threat_object` with `threat_object_type=ip_address`.

**Multi-object events:** a single detection can legitimately emit two risk events from one observable — for example, an authentication anomaly affects both the user and the host. Emit two events with `risk_object` populated separately for each. Avoid combining them into one event with both populated.

### Risk score conventions

There is no enforced enumeration; the `risk_score` field is a free numeric value. A consistent grid across detections is what lets the threshold rule work meaningfully.

| Severity | Score range | Typical detection profile |
|---|---|---|
| Informational | 1–20 | Anomalous-but-benign signals; baseline drift; first-seen activity |
| Low | 21–40 | Suspicious patterns expected to occur in normal operations (e.g. a single failed logon, single PowerShell encoded command) |
| Medium | 41–60 | Suspicious patterns that warrant analyst attention but not isolation (e.g. multiple failures, scheduled task creation by non-admin) |
| High | 61–80 | High-confidence malicious or near-certain — single instance is investigation-worthy |
| Critical | 81–100 | Confirmed malicious or extremely high-confidence (e.g. successful DCSync, ransomware artefact write, known-bad hash execution) |

**Worked examples:**

- A single 4625 failed logon → score 5 (informational); the *first* failed logon of a possible spray pattern, not a finding by itself
- 4625 LogonType=3 from a non-corporate IP → score 25 (low); same event with context elevates it
- 50 failed logons from one source in 5 minutes → score 60 (medium); pattern-based, still not a finding
- DCSync replication request (4662 with replicating-directory-changes GUID) from non-DC → score 90 (critical); single occurrence warrants a finding

The threshold rule (next section) decides when accumulated score becomes a finding — typical defaults: 80 over 24 hours per `risk_object`, or 100 over a sliding 7 days.

### The `risk` modular alert action

ES ships a `risk` modular alert action that handles writing a detection's results into the `risk` index. Configure it on a saved search; it reads the search's output rows and writes one risk event per row.

Output columns the action recognises (when present in the SPL row):

| SPL column | Effect |
|---|---|
| `risk_object` | Mapped directly to `risk_object` field |
| `risk_object_type` | Mapped to `risk_object_type`; defaults to `system` if omitted |
| `risk_score` | Mapped to `risk_score`; if absent the action uses the per-search default configured in ES |
| `_risk_score` | Per-row override; takes precedence over `risk_score` if both present |
| `threat_object` / `threat_object_type` | Mapped through unchanged |
| `risk_message` | Mapped through; supports SPL token substitution from row fields |

The search's underlying `_time` is preserved so risk events line up with the original observable timeline, not the search execution time.

### Two-tier model: contributing detections and the threshold rule

A working RBA pipeline has two kinds of saved search:

1. **Contributing detections** — focused, intentionally noisy-tolerant SPL that emits risk events. These do **not** generate notables / findings on their own. They run frequently (e.g. every 5–15 minutes) and write to `risk` via the modular alert action.

2. **Risk threshold detection** — a single (or small number of) correlation search reads from `index=risk`, sums recent score per `risk_object`, and fires a notable when the sum crosses a threshold. This is the only search in the chain that becomes an investigation.

The benefit: an analyst opens **one** finding describing an entity that has crossed the threshold, with a populated `risk_message` history of every contributing signal. Lower volume; far more context.

### Risk-finding lifecycle in ES 8

```
Atomic detection                 Risk index           Threshold detection         Notable index               Mission Control
(saved search)        →    one event per                (correlation)         →    finding event         →    investigation
   risk action              contributing               summing risk              risk_object,
   populates fields         signal                     by risk_object              accumulated score,
   writes 1 event           (kept in risk              over window                contributing
   per matching row          for retention)            firing notable             detections
```

Key behaviours:

- The `risk` index is a normal Splunk index; data retention is configured the same way as any other. Common retention is 90 days hot/warm, longer cold for forensic re-walking.
- Threshold detections typically run on a sliding window — they are not statefully tracking accumulation, they are re-summing each schedule.
- The notable produced by the threshold detection lands in `notable` (or the ES 8 `findings` equivalent) and is investigated in Mission Control. The `risk_object` is the focal entity for the investigation.
- Mission Control presents the contributing risk events for the focal entity automatically — analysts can drill into the timeline of `risk_message` values to see what built the score.

### SPL templates

#### Atomic detection emitting a risk event

The detection produces rows shaped for the `risk` action — the action is configured separately on the saved search.

```spl
` Detection: PowerShell with encoded command (T1059.001) `
index=windows sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
    EventCode=4104
    ScriptBlockText="*-EncodedCommand*"
| eval risk_score = 35
| eval risk_object = lower(Computer)
| eval risk_object_type = "system"
| eval threat_object = ScriptBlockText
| eval threat_object_type = "other"
| eval risk_message = "Encoded PowerShell command observed on " . Computer . " by " . User
| eval annotations.mitre_attack.mitre_tactic = "execution"
| eval annotations.mitre_attack.mitre_technique = "T1059"
| eval annotations.mitre_attack.mitre_subtechnique = "T1059.001"
| table _time, risk_object, risk_object_type, risk_score, risk_message,
        threat_object, threat_object_type,
        annotations.mitre_attack.mitre_tactic,
        annotations.mitre_attack.mitre_technique,
        annotations.mitre_attack.mitre_subtechnique,
        user, host
```

For multi-object emission (one observable affecting both a user and a host), `mvexpand` after constructing a multi-value `risk_object`:

```spl
... base detection ...
| eval risk_object = mvappend(lower(user), lower(host))
| eval risk_object_type = mvappend("user", "system")
| eval risk_score = mvappend(40, 40)
| stats values(*) as * by _time
| eval combined = mvzip(mvzip(risk_object, risk_object_type, "|"), risk_score, "|")
| mvexpand combined
| eval risk_object = mvindex(split(combined, "|"), 0)
| eval risk_object_type = mvindex(split(combined, "|"), 1)
| eval risk_score = mvindex(split(combined, "|"), 2)
```

#### Threshold-based correlation reading from `index=risk`

```spl
index=risk earliest=-24h
| stats sum(risk_score) as total_risk
        values(source) as contributing_detections
        values(annotations.mitre_attack.mitre_technique) as techniques
        values(risk_message) as risk_messages
        dc(source) as distinct_detection_count
        by risk_object risk_object_type
| where total_risk >= 80 AND distinct_detection_count >= 3
| sort - total_risk
```

The `distinct_detection_count` clause is an important guardrail — a single very-noisy detection contributing 80 points alone is not a meaningful finding. Requiring contribution from multiple distinct detections forces the threshold rule to fire only on entities exhibiting a *pattern* rather than repeated single-source noise.

#### SOC-analyst pivot: contributing risk for one risk_object

This is the single most important search for a SOC analyst working an RBA finding:

```spl
index=risk risk_object="alice.smith" earliest=-7d
| table _time, source, risk_score, risk_message,
        threat_object, threat_object_type,
        annotations.mitre_attack.mitre_technique
| sort - _time
```

Variations: filter by `annotations.mitre_attack.mitre_tactic` to scope to a kill-chain phase, or `stats sum(risk_score) by source` to identify the top-contributing detections.

---

## 2. MITRE ATT&CK mapping

> ES uses a consistent annotation convention for ATT&CK tagging on detections. Tagging detections at authoring time (not retroactively) is what makes coverage measurement possible.

### Annotation fields

The standard fields on a detection (saved search definition) and on each risk event:

| Field | Values | Notes |
|---|---|---|
| `annotations.mitre_attack.mitre_tactic` | Short name from the ATT&CK tactic enumeration (see below) | Multi-valued where a technique spans multiple tactics |
| `annotations.mitre_attack.mitre_technique` | Technique ID (e.g. `T1078`) | Multi-valued where a detection covers multiple techniques |
| `annotations.mitre_attack.mitre_subtechnique` | Sub-technique ID (e.g. `T1078.004`) | Use the parent technique alone if no sub-technique applies |

A single detection can carry multiple values in each field — for example, a credential-access detection may also be evidence of lateral movement and so carry both tactic values.

### Tactic enumeration (Enterprise matrix)

| Short name | ID | Stage |
|---|---|---|
| `reconnaissance` | TA0043 | Pre-compromise |
| `resource-development` | TA0042 | Pre-compromise |
| `initial-access` | TA0001 | Compromise entry |
| `execution` | TA0002 | Code running |
| `persistence` | TA0003 | Surviving reboots / re-auth |
| `privilege-escalation` | TA0004 | Gaining higher rights |
| `defense-evasion` | TA0005 | Avoiding detection |
| `credential-access` | TA0006 | Stealing credentials |
| `discovery` | TA0007 | Internal recon |
| `lateral-movement` | TA0008 | Pivoting between systems |
| `collection` | TA0009 | Gathering data of interest |
| `command-and-control` | TA0011 | Operator communications |
| `exfiltration` | TA0010 | Data leaving the environment |
| `impact` | TA0040 | Destruction / encryption / DoS |

### Technique → typical sourcetype reference

This table is intentionally generic — what sourcetype detects a technique depends on the data the environment ingests. Refer to `splunk-sourcetype-library.md` for actual field shapes.

| Technique | Description | Typical detecting sourcetypes |
|---|---|---|
| **T1078** Valid Accounts | Use of compromised legitimate credentials | `XmlWinEventLog` (4624 LogonType 3/10), `azure:monitor:aad`, `o365:management:activity`, `linux_secure`, `aws:cloudtrail` (`ConsoleLogin`) |
| **T1110** Brute Force | Password guessing | `XmlWinEventLog` (4625, 4771), `azure:monitor:aad` (failed sign-ins), `linux_secure` (sshd failures), `pan:globalprotect` |
| **T1110.003** Password Spraying | Many users, few attempts each | Same as T1110, aggregated by source IP rather than target user |
| **T1110.004** Credential Stuffing | Credential lists from breach corpora | `azure:monitor:aad`, `o365:management:activity`, web auth logs (`ms:iis:auto`, app logs) |
| **T1059.001** PowerShell | PowerShell-based execution | `XmlWinEventLog` (4103 module logging, 4104 script block, 4688 process create with `powershell.exe`) |
| **T1059.003** Windows Command Shell | `cmd.exe` execution | `XmlWinEventLog` (4688), Sysmon EID 1 |
| **T1059.004** Unix Shell | bash/sh execution | `linux_secure`, `auditd`, EDR endpoint sourcetypes |
| **T1003** OS Credential Dumping | LSASS, SAM, etc. | `XmlWinEventLog` (10/4663 on lsass.exe, 4673), Sysmon EID 10, EDR |
| **T1003.001** LSASS Memory | LSASS process access | Sysmon EID 10 with `TargetImage=lsass.exe`, EDR alerts |
| **T1003.006** DCSync | Replicating Directory Changes | `XmlWinEventLog` (4662 on directory object with replicating-directory-changes GUID, from non-DC source) |
| **T1218** Signed Binary Proxy Execution | LOLBin abuse (rundll32, mshta, regsvr32, etc.) | `XmlWinEventLog` (4688), Sysmon EID 1 |
| **T1218.011** Rundll32 | rundll32 abuse | Process create with anomalous parents/cmdlines |
| **T1218.005** Mshta | mshta.exe HTA execution | Process create on `mshta.exe` |
| **T1543.003** Windows Service | New / modified Windows service for persistence | `XmlWinEventLog` (System channel 7045 service install, Security 4697) |
| **T1053.005** Scheduled Task | Persistence via task scheduler | `XmlWinEventLog` (Task Scheduler Operational 106/140/141, Security 4698/4702) |
| **T1053.003** Cron | Persistence via cron | `cron-too_small`, `linux_secure`, `auditd` |
| **T1021** Remote Services | Lateral movement via SMB/RDP/SSH/WMI | `XmlWinEventLog` (4624 LogonType 3/10), `pan:traffic`, `aws:cloudwatchlogs:vpcflow`, `linux_secure` |
| **T1021.001** RDP | Remote Desktop | 4624 LogonType=10, network telemetry on tcp/3389 |
| **T1021.002** SMB / Admin Shares | Lateral via SMB | 4624 LogonType=3, network on tcp/445, share access events 5140/5145 |
| **T1021.006** WinRM | Lateral via PowerShell remoting | `XmlWinEventLog` (Microsoft-Windows-WinRM, 4624 with logonprocess `WinRM`), tcp/5985-5986 |
| **T1098** Account Manipulation | Modifying existing accounts (group adds, password changes) | `XmlWinEventLog` (4720/4722/4724/4725/4738, 4728/4732/4756 group adds), `azure:monitor:aad`, `o365:management:activity`, `aws:cloudtrail` (`AttachUserPolicy`, `CreateAccessKey`) |
| **T1136** Create Account | New local/domain/cloud account | `XmlWinEventLog` (4720 local/domain), `azure:monitor:aad`, `aws:cloudtrail` (`CreateUser`) |
| **T1486** Data Encrypted for Impact | Ransomware encryption | `XmlWinEventLog` (Defender Operational), Sysmon EID 11 (file create), EDR ransomware verdicts |
| **T1562** Impair Defenses | Disabling AV / logging / firewall | `XmlWinEventLog` (Defender 5001/5004/5007, 1102 audit log cleared), `aws:cloudtrail` (`StopLogging`, `DeleteTrail`) |
| **T1562.001** Disable / Modify Tools | Defender / EDR tampering | Defender Operational, EDR self-protection events |
| **T1562.004** Disable / Modify System Firewall | netsh, registry firewall changes | `XmlWinEventLog` (4688 with `netsh`), Sysmon EID 13 (registry) |
| **T1070** Indicator Removal | Log clearing, file delete | `XmlWinEventLog` (1102 audit log cleared, 104 system log cleared), `aws:cloudtrail` (`DeleteTrail`) |
| **T1070.001** Clear Windows Event Logs | wevtutil / Clear-EventLog | `XmlWinEventLog` 1102/104 |
| **T1070.004** File Deletion | Defensive evidence destruction | Sysmon EID 23, `auditd` |
| **T1071** Application Layer Protocol | C2 over HTTP/HTTPS/DNS | `pan:traffic`, `pan:threat`, `aws:cloudwatchlogs:vpcflow`, `ms:iis:auto`, DNS query logs |
| **T1071.001** Web Protocols | C2 over HTTP/S | Web proxy logs, firewall traffic, `pan:url` |
| **T1071.004** DNS | C2 over DNS | DNS query logs, `pan:traffic` with DNS app, `aws:route53:resolver` |
| **T1090** Proxy | Internal/external proxying for C2 | `pan:traffic`, VPC flow logs, firewall logs |
| **T1090.003** Multi-hop Proxy | Tor / commercial anonymisers | Threat intel match against destination IP / domain |
| **T1133** External Remote Services | VPN / remote service abuse | `pan:globalprotect`, RDP gateway logs, `azure:monitor:aad` (legacy auth flows) |
| **T1499** Endpoint DoS | Application-level resource exhaustion | `ms:iis:auto` (high `time_taken`, anomalous request rates), application logs |
| **T1498** Network DoS | Volumetric DoS | `pan:traffic`, `aws:cloudwatchlogs:vpcflow`, DDoS appliance logs |

For each detection, populate **all three** annotation fields (tactic, technique, sub-technique) wherever possible — sub-technique is the most-specific category and is what coverage tools display by default.

### Coverage measurement: `mitre_attack_navigator`

Coverage is reported by exporting tagged detections from the ES content set, mapping each to its annotation values, and producing a Navigator JSON layer that paints the matrix. Common pattern:

```spl
| rest /services/saved/searches splunk_server=local
| search action.notable=1 OR action.risk=1
| eval techniques = 'action.notable.param.nes_fields' . 'action.risk.param._risk'
| eval techniques = 'annotations.mitre_attack.mitre_technique'
| eval subtechniques = 'annotations.mitre_attack.mitre_subtechnique'
| stats values(title) as detections by techniques subtechniques
| outputlookup mitre_attack_navigator
```

The lookup feeds a downstream export job that produces an ATT&CK Navigator layer (`*.json`) for visual coverage review. Re-run on a schedule to catch detection drift.

A blank cell on the Navigator matrix is not necessarily a coverage gap — it may be a technique that is not relevant to the environment (e.g. T1059.005 Visual Basic on a non-Windows estate). Document deliberate non-coverage rather than treating every blank cell as a backlog item.

---

## 3. False-positive catalogue and tuning

> Each detection family has a small set of recurring FP sources. Recognising them shaves hours off triage and prevents the death-by-FP-volume that kills RBA pipelines.

### Authentication FPs

| FP pattern | Why it happens | How to handle |
|---|---|---|
| Burst of `LogonType=3` from a vulnerability scanner / monitoring tool | Tools authenticate to many hosts in sequence to enumerate or check state | Allowlist source IP / source host in a lookup; exclude from brute-force aggregation |
| Service account with regular failed-logon noise | Stale credentials cached on a scheduled task or service that has not been updated | Allowlist by `TargetUserName` for known service accounts; alert separately if failure pattern *changes* |
| `4625 SubStatus=0xC0000234` (account locked) following a brute force | Lockout is the *consequence* of the brute force, not a separate event | Suppress 4625 events with this SubStatus in spray detection — they would inflate the count |
| Kerberos pre-auth failures (4771) from Mac clients pre-bind | macOS Kerberos client retries before successful binding to AD | Allowlist by client OS / source-IP subnet; tune to exclude `0x18` failures from non-bound hosts |
| Domain-controller-to-domain-controller replication noise | DCs constantly authenticate to one another for replication and FRS/DFSR | Exclude `TargetUserName` ending with `$` from DC-source IPs; use `Computer in dc_list` lookup |
| Local-system authentication (`SYSTEM`, `ANONYMOUS LOGON`) | Normal Windows internals | Exclude `TargetUserName` in (`SYSTEM`, `ANONYMOUS LOGON`, `LOCAL SERVICE`, `NETWORK SERVICE`) at detection-eventtype level |
| Self-service password reset flows generating 4625 spikes | User retrying password during reset wizard | Correlate with password-reset audit events; suppress when both present in window |

### Endpoint / Process FPs

| FP pattern | Why it happens | How to handle |
|---|---|---|
| Microsoft Defender / EDR PowerShell | Defender uses PowerShell extensively for telemetry collection | Allowlist parent process by signature / path (`MsMpEng.exe`, EDR agent) |
| Vulnerability scanners running PowerShell remotely | Tenable / Qualys / Rapid7 use WinRM with PowerShell | Allowlist by source IP and `User` matching scanner service account |
| RMM tools triggering Sysmon EID 1 / 8 / 10 in normal use | ConnectWise, Atera, NinjaOne, Kaseya inject into and create processes routinely | Allowlist by signed-binary publisher and known parent path |
| Software updaters (Squirrel, Chocolatey, MSIX, Adobe updaters) creating short-lived processes | Auto-updaters spawn many child processes briefly | Allowlist by binary publisher / file path; reduce score rather than suppress (legitimate auto-update is a real persistence vector) |
| Containerised workloads producing high process-create volume | Each container start fires `4688` / Sysmon EID 1 | Exclude container-host names from process-create-volume detections; instrument inside the container instead |
| Build agents / CI runners executing commands at scale | `pwsh`, `cmd`, `python` invocations are the agent's job | Allowlist by host name pattern (e.g. build-host naming convention) for command-line detections |
| Microsoft Office spawning PowerShell during legitimate macro use | Some line-of-business apps use Office automation | Reduce score for known-app parent-child chains; do not suppress entirely |
| Image-hash mismatch FPs after Windows updates | Hash baseline becomes stale post-patch | Re-baseline on patch-Tuesday cadence; do not score on hash mismatch alone |

### Network FPs

| FP pattern | Why it happens | How to handle |
|---|---|---|
| TLS-inspecting proxy showing as MITM | The proxy *is* a MITM — that is its function | Allowlist proxy certificate fingerprints; exclude proxy egress IPs from suspicious-cert detections |
| DNS load balancers / split-horizon causing query duplicates | Same query returns from both internal and forwarder paths | Deduplicate by `query_id`; aggregate per-query rather than per-event |
| IPv6 transition / Teredo traffic | Teredo, ISATAP, 6to4 generate traffic that looks like tunnelling | Allowlist by Teredo prefix / well-known transition addresses |
| Multicast / SSDP / mDNS noise | Normal LAN discovery (SSDP 239.255.255.250, mDNS 224.0.0.251) | Exclude multicast/link-local in network detections at eventtype level |
| Cloud storage egress for legitimate backup | Veeam, Commvault, native cloud backup pushing TBs | Allowlist by destination IP range (cloud provider) and source backup-server; alert on changes-of-destination instead |
| Outbound Tor connections from researchers / red team | Sanctioned Tor use exists in some environments | Lookup-driven exclusion of researcher hosts / accounts |

### Common tuning approaches

#### Allowlist via lookup

The most flexible technique. Maintain the allowlist as a CSV-backed lookup; join in the SPL.

```spl
` Authentication detection with service-account allowlist `
index=windows sourcetype=XmlWinEventLog EventCode=4625
| lookup identity_lookup_expanded identity AS TargetUserName OUTPUT category, bunit
| where NOT (category="service_account" OR isnull(category)=false AND match(category, "scanner|monitoring"))
| stats count by TargetUserName IpAddress
| where count > 10
```

`identity_lookup_expanded` is the ES asset/identity framework lookup; if not in use, a simple `service_account_allowlist.csv` works the same way.

#### Risk-score reduction (don't suppress, just down-weight)

When a pattern is suspicious-but-expected, lower the score rather than allowlist it outright. The signal still contributes to threshold accumulation if other signals also fire, but is not a finding by itself.

```spl
` Same detection, but reduce score for known auto-updaters `
... base detection ...
| lookup software_updater_allowlist process_name OUTPUT updater_category
| eval risk_score = case(
        isnotnull(updater_category), 5,           ` known updater — minimal score `
        match(parent_process, "(?i)defender|edr"), 0,  ` security tooling — drop entirely `
        true(), 35                                ` default `
    )
| where risk_score > 0
```

#### Throttling: `_throttle_field` and time window

In ES correlation searches, throttling is configured on the saved search (not the SPL), but the same effect can be achieved in SPL with a deduplication step:

```spl
` Detection with built-in throttling: one event per (user, src) per hour `
... base detection ...
| bin _time span=1h
| stats earliest(_time) as _time
        values(*) as *
        by user src _time
| fields - _time
| eval _time = relative_time(now(), "@h")
```

The ES correlation-search-level throttle (`_throttle_field` / `dispatch.earliest_time`) is preferable when available — it persists between schedule runs, where in-SPL throttling does not.

#### Suppression rules in ES

Configured on the correlation search definition: select a set of key fields (e.g. `user`, `src`) and a duration; ES will not emit a second notable for the same key-field combination within the window. Useful for noisy but unavoidable detections — e.g. periodic re-firing during an incident already under investigation.

#### Eventtype-level vs detection-level allowlists

| Approach | When to use | Trade-off |
|---|---|---|
| Eventtype-level (modify the eventtype definition or upstream `props`/`transforms`) | Pattern is universally noise across **every** detection consuming the data | Hides the data; if a future detection wants to see the events, harder to recover |
| Detection-level (filter inside the SPL) | Pattern is FP for **this** detection but legitimate for others | Repeated logic across detections; maintenance burden |
| Lookup-driven detection-level | FP set changes over time and must be operationally manageable | Lookup must be kept current; easy to introduce gaps |

Rule of thumb: if the same allowlist appears in three or more detections, promote it to a shared lookup. If it appears in every detection consuming a sourcetype, push it upstream to eventtype or transforms.

---

## Cross-references

- For source data field shapes (`EventCode`, `cs_uri_stem`, `eventName`, etc.), see `splunk-sourcetype-library.md`.
- For environment-specific knowledge (which indexes hold what, configured eventtypes, ingestion gaps, asset/identity coverage), see `splunk-environment-context.md`.
- For correlation-search configuration mechanics in ES (modular alert action setup, suppression UI, throttle fields), see ES-vendor documentation — the patterns above describe SPL/data-shape concerns that are stable across ES versions.
