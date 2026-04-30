# Windows Event Log Reference

> Companion to `splunk-sourcetype-library.md`. The library covers the `XmlWinEventLog` sourcetype broadly; this file goes deep on **which event IDs in which channels matter, what fields they populate, what they're useful for, and Microsoft's own monitoring recommendations**.
>
> Scoped to events relevant to security detection, IR, and admin auditing. Operational/diagnostic events are out of scope unless they're security-relevant.
>
> **Authoritative sources** (cited inline by URL fragment, full citations at end):
> - [Microsoft Learn: Windows Security audit events](https://learn.microsoft.com/windows/security/threat-protection/auditing/) — per-event-ID detail with monitoring recommendations
> - [Microsoft Learn: Appendix L — Events to monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) — master list with criticality ratings
> - [Microsoft Learn: Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) — current Sysmon documentation (Sysmon is now Microsoft-owned; v15.2 as of writing)
> - [Microsoft Learn: Understanding Sysmon events](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events) — detection-focused interpretation

---

## Microsoft criticality ratings

Microsoft's [Appendix L](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) classifies security events by criticality:

- **High** — A single occurrence should be investigated. These events should drive notable/finding generation in ES.
- **Medium / Medium-to-High** — Worth monitoring; alert when frequency exceeds expected baseline or events appear unexpectedly.
- **Low** — Informational; useful for forensic context, generally too noisy for direct alerting.

> "Every environment is different, and some of the events ranked with a potential criticality of High might occur due to other harmless events." — Microsoft

Criticality ratings are included in the event tables below where Microsoft has assigned one.

---

## How Windows event logs work in Splunk

**Channels** are Windows' name for log streams. Each channel has its own set of event IDs.

The TA splits ingestion by channel via the `source` field:
- `XmlWinEventLog:Security` → Security channel
- `XmlWinEventLog:System` → System channel
- `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` → PowerShell Operational
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` → Sysmon
- ...etc.

Event IDs are unique within a channel but not across channels — `EventCode=1` means "Sysmon process create" in the Sysmon channel and something completely different elsewhere. **Always scope queries by `source=` first**, then `EventCode=`.

### XML vs Classic format

Modern ingestion uses XML (`XmlWinEventLog`). Field names differ from the legacy `WinEventLog:*` format:
- XML: `TargetUserName`, `SubjectUserName`, `IpAddress`, `LogonType`
- Classic: `Account_Name`, `Source_Network_Address`, `Logon_Type`

Detections written for one format won't work on the other without rewriting.

### EventID + Qualifiers — the "double event ID" trap

Some events have a `Qualifiers` field in addition to `EventID`. Splunk's `EventCode` only contains the `EventID` portion. When `Qualifiers` is populated, the "true" 32-bit identifier shown by other tools is `(Qualifiers << 16) | EventID`.

**Why it exists:** Pre-Vista Windows used a single 32-bit DWORD event identifier. Vista's manifest-based event log split this into a 16-bit `EventID` plus an optional 16-bit `Qualifiers` field. Modern manifest-based providers (`Microsoft-Windows-Security-Auditing`, Sysmon, PowerShell, etc.) leave `Qualifiers` null. **Legacy providers** (Service Control Manager, MSI Installer, DCOM, lots of third-party stuff in Application/System channels) populate it. Reference: [`EventLogRecord.Qualifiers`](https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.eventlogrecord.qualifiers).

**The CIM lookup trap:** `EventCode` alone is **not unique across providers**. Two completely different events from different providers can share the same `EventCode` and a lookup keyed only on `EventCode` will return the wrong description. The qualifier (or, more reliably, the `SourceName` / provider name) is the disambiguator.

**The real-world collision problem (Application channel):**

The Application channel is the worst offender. Many providers all use overlapping event IDs:

| Provider | `EventCode` | Meaning |
|---|---|---|
| Application Error | 1000 | Faulting application (crash) |
| MsiInstaller | 1000 | Installer message |
| Application Hang | 1002 | Hung application |
| MsiInstaller | 1033 | Product installation started |
| Microsoft-Windows-Restart-Manager | 10000 | Restart attempt |
| ESENT | 100 | Various database engine events |

A `signature_id → signature` lookup keyed only on `EventCode=1000` will return whatever the lookup table author put first — not what's actually in the event. The fix is to key on `SourceName` + `EventCode`, where `SourceName` is the provider (e.g. `"Application Error"`, `"MsiInstaller"`).

**Worked example — combined 32-bit ID math:**

`EventCode=7036` (Service Control Manager, service state change) with `Qualifiers=0x8080`:
- `(0x8080 << 16) | 0x1B7C` = `0x80801B7C` = **2155879292** in decimal

That decimal value is what older tools and some third-party docs display. Splunk's `EventCode` field is just the `0x1B7C` (7036) low half. Common qualifier high-bytes correspond to legacy severity: `0x0000` Success, `0x4000` Informational, `0x8000` Warning, `0xC000` Error.

**Practical guidance for CIM mapping:**
- Don't key `signature_id → signature` lookups on `EventCode` alone for `XmlWinEventLog:System` and `XmlWinEventLog:Application`. Use `SourceName` + `EventCode` (or `Channel` + `SourceName` + `EventCode`) as the composite key.
- For `XmlWinEventLog:Security` and other manifest-based channels, `EventCode` alone is safe (Qualifiers is null and EventIDs are owned by the single Security-Auditing provider).
- If you see a third-party doc citing an event ID like "1073748860" or "2155874989" — that's the combined 32-bit form. Search Splunk for the low 16 bits.

---

## Channel reference

| Channel | Source field value | Where it's logged | Volume |
|---|---|---|---|
| Security | `XmlWinEventLog:Security` | All Windows hosts (when audit policy enables) | High |
| System | `XmlWinEventLog:System` | All Windows hosts | Medium |
| Application | `XmlWinEventLog:Application` | All Windows hosts | Medium |
| PowerShell Operational | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | All hosts running PS | Very high if 4104 enabled |
| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Hosts with Sysmon installed/enabled | Very high |
| Defender Operational | `XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational` | Hosts with Defender enabled | Low |
| Task Scheduler Operational | `XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational` | All Windows hosts | Medium |
| Directory Service | `XmlWinEventLog:Directory Service` | Domain Controllers only | Medium-high |
| DNS Server | `XmlWinEventLog:DNS Server` | DNS Servers (typically DCs) | Very high |
| DFS Replication | `XmlWinEventLog:DFS Replication` | DCs and DFS-R servers | Low |

---

## Security channel — `XmlWinEventLog:Security`

The single most important channel for security detection. Coverage requires the relevant audit policy categories to be enabled on the host (Default Domain Controllers Policy or local Audit Policy).

### Authentication

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 4624 | Low | **Successful logon** | Use `LogonType` to scope. `LogonGuid` correlates with 4769 on DCs. Filter for `ElevatedToken=Yes` to find admin logons |
| 4625 | Low | **Failed logon** | `Status` / `SubStatus` reveals reason. Bursts indicate password spray / brute force |
| 4634 | Low | Logoff | Pair with 4624 via `TargetLogonId` to compute session duration |
| 4647 | Low | User-initiated logoff | Interactive logoffs (clean Start menu sign-out) |
| 4648 | Low | **Logon with explicit credentials** | "RunAs" / pass-the-hash indicator. `SubjectUserName` is the actual user; `TargetUserName` is who they pretended to be |
| 4672 | Low | **Special privileges assigned to new logon** | Logon by an admin account. Pair with 4624 via `SubjectLogonId` |
| 4768 | Low | **Kerberos TGT requested** | DCs only. AS-REQ. `Status` = Kerberos result code |
| 4769 | Low | **Kerberos service ticket requested** | DCs only. TGS-REQ. **Kerberoasting indicator: anomalous `ServiceName` with `TicketEncryptionType=0x17`** |
| 4770 | Low | Kerberos service ticket renewed | DCs only |
| 4771 | Low | **Kerberos pre-authentication failed** | DCs only. AS-REQ failure. `Status=0x18` = bad password |
| 4772 | Low | Kerberos authentication ticket request failed | DCs only |
| 4774 | Low | An account was mapped for logon | |
| 4776 | Low | **NTLM authentication** | DCs (for domain accounts) and member servers (for local). `Status=0xC000006A` = bad password |
| 4777 | Low | The DC failed to validate credentials for an account | |
| 4778 | Low | A session was reconnected to a Window Station | RDP reconnect |
| 4779 | Low | A session was disconnected from a Window Station | RDP disconnect |
| **4964** | **High** | **Special groups assigned to a new logon** | Configurable group list via registry. Used to alert on Domain Admin logons to non-DC hosts |

#### `4624` field detail (verified via Microsoft Learn)
**Reference:** [Event 4624 documentation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)

**Common fields:** `TargetUserName`, `TargetUserSid`, `TargetDomainName`, `TargetLogonId`, `LogonType`, `IpAddress`, `IpPort`, `WorkstationName`, `LogonProcessName`, `AuthenticationPackageName`, `LogonGuid`

**Version 2 (Windows 10+) added:**
- `RestrictedAdminMode` — Yes/No (only populated for `LogonType=10`/RDP)
- `VirtualAccount` — Yes/No (managed service account / gMSA flag)
- `ElevatedToken` — Yes/No (admin session indicator)
- `TargetLinkedLogonId` — paired logon session ID
- `NetworkAccountName` / `NetworkAccountDomain` — only populated for `LogonType=9` (RunAs /netonly)
- `ImpersonationLevel` — `%%1832` (Anonymous), `%%1833` (Identification), `%%1840` (Impersonation), `%%1841` (Delegation)

**Microsoft's monitoring recommendations for 4624:**
- Anything where `Subject\Security ID` ≠ `SYSTEM` is worth reporting
- If `RestrictedAdminMode` must be used by certain accounts, alert on `LogonType=10` + `RestrictedAdminMode=No`
- Watch all logons with `ElevatedToken=Yes` on standard workstations
- Watch all logons where `VirtualAccount=Yes` to track managed service accounts
- Logon-type / account-type mismatch: e.g. `LogonType=4` (Batch) or `LogonType=5` (Service) used by a domain admin = high-priority
- If `AuthenticationPackage=NTLM`, check `Package Name (NTLM only)` ≠ `NTLM V2` (V1 / LM = legacy)
- If `Authentication Package=NTLM`, check `Key Length` ≠ 128

#### `4625` field detail (verified via Microsoft Learn)
**Reference:** [Event 4625 documentation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)

**Common fields:** all 4624 fields plus `Status`, `SubStatus`, `FailureReason`

**Microsoft's expanded SubStatus codes worth alerting on:**
| Code | Meaning |
|---|---|
| `0xC0000064` | User does not exist — **repeated occurrences = user enumeration attack** |
| `0xC000006A` | Bad password — bursts on critical/service accounts = brute force |
| `0xC000006D` | Bad username or auth info — generic auth failure |
| `0xC000006F` | Outside authorised hours |
| `0xC0000070` | Workstation restriction (logon from unauthorised host) |
| `0xC0000072` | Account disabled by administrator |
| `0xC0000234` | Account locked out |
| `0xC0000193` | Account expired |
| `0xC0000071` | Password expired |
| `0xC0000133` | Clock skew |
| `0xC0000224` | Password must change |
| `0xC000005E` | No logon servers available — *infrastructure issue, not security* |
| `0xC000015B` | Logon type not granted at this machine |
| `0xC0000192` | Netlogon service not started — *infrastructure issue* |
| `0xC0000413` | Authentication firewall blocked the logon |

#### `4768` / `4769` detail (verified via Microsoft Learn — significant 2025 update)
**References:** [Event 4768](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768) | [Event 4769](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769)

> **Important:** Windows Server 2016+ display an updated version of Events 4768/4769 after the **January 2025 Security Cumulative Update**. New fields added.

**Existing fields:** `TargetUserName`, `TargetDomainName`, `ServiceName`, `ServiceSid`, `TicketOptions`, `TicketEncryptionType`, `IpAddress`, `IpPort`, `Status`, `LogonGuid`

**New (2025 update) fields:**
- `AccountSupportedEncryptionTypes` — encryption types the user account supports (msds-SET)
- `AccountAvailableKeys` — available keys for the user account
- `ServiceSupportedEncryptionTypes` — encryption types the service supports
- `ServiceAvailableKeys` — available keys for the service
- `DCSupportedEncryptionTypes` — DC's supported encryption types
- `DCAvailableKeys` — DC's available keys
- `ClientAdvertizedEncryptionTypes` — list of encryption types the client advertised
- `RequestTicketHash` (4769) — hash of the request ticket
- `ResponseTicketHash` (4769) / `ResponseTicket` (4768) — hash of the response ticket
- `SessionKeyEncryptionType` — encryption type for the session key
- `PreAuthEncryptionType` (4768 only) — encryption type used in pre-auth flow

**The 2025 update is critical for Kerberoasting detection** — `RequestTicketHash` and `ResponseTicketHash` enable correlation and reduce reliance on weaker indicators. The encryption type fields make downgrade detection much more reliable.

**Microsoft's monitoring recommendations for 4769:**
- All `Client Address = ::1` means local TGS request (account logged on to a DC). Maintain an allowlist of accounts permitted to log on to DCs.
- All events with `Client Port` > 0 and < 1024 should be examined (well-known port used)
- `TicketEncryptionType=0x1` or `0x3` (DES) — should never happen on modern Windows
- `TicketEncryptionType ≠ 0x11` and `≠ 0x12` (not AES) — anomalous on Windows Server 2008+

**Microsoft's monitoring recommendations for 4768 (selected Result Codes):**
- `0x6` (KDC_ERR_C_PRINCIPAL_UNKNOWN) — repeated = account enumeration
- `0xC` (KDC_ERR_POLICY) — logon restriction violations (workstation, time, smart card)
- `0x12` (KDC_ERR_CLIENT_REVOKED) — repeated = brute force or compromised account
- `0x1F` (KRB_AP_ERR_BAD_INTEGRITY) — should not occur in standard AD
- `0x22` (KRB_AP_ERR_REPEAT) — replay detection
- `0x29` (KRB_AP_ERR_MODIFIED) — should not occur in standard AD
- `0x3E`/`0x3F`/`0x40`/`0x41` — smart card / PKI authentication problems

#### Logon types (verified via Microsoft Learn)
| Type | Name | Meaning |
|---|---|---|
| `0` | System | Used only by the System account, e.g. at system startup |
| `2` | Interactive | Local console / direct keyboard logon |
| `3` | Network | Network logon (SMB, IIS, etc.). Highest volume |
| `4` | Batch | Scheduled task running as a user |
| `5` | Service | Service starting under a user account |
| `7` | Unlock | Workstation unlock |
| `8` | NetworkCleartext | Cleartext password over network — IIS basic auth, telnet |
| `9` | NewCredentials | RunAs `/netonly` — alternate credentials for network resources |
| `10` | RemoteInteractive | RDP |
| `11` | CachedInteractive | Cached domain credentials (offline laptop) |
| `12` | CachedRemoteInteractive | Same as RemoteInteractive — internal auditing only |
| `13` | CachedUnlock | Workstation logon |

**Detection notes:**
- Type 2 / 10 are the highest-fidelity for "user logged in" — use these to find admin logons
- Type 3 is the noisy one — usually filter aggressively
- Type 9 is unusual and worth investigating — credential separation pattern
- Types 12/13 are rarely seen; their presence may indicate unusual auth flows

### Process / executable activity

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 4688 | Low | **Process create** | Sysmon Event ID 1 is richer if available. Requires audit policy + GPO for command line |
| 4689 | Low | Process terminate | Pair with 4688 by `NewProcessId` / `ProcessId` |
| 4696 | Low | Primary token assigned to process | Token-based execution context changes |

#### `4688` field detail (verified via Microsoft Learn)
**Reference:** [Event 4688 documentation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)

**Field names** (from XML):
- `NewProcessId`, `NewProcessName` — the new process
- `ProcessId` — the **parent** process ID (named `Creator Process ID` in display)
- `ParentProcessName` — parent process name
- `CommandLine` — only populated when GPO `Audit Process Creation: Include command line` is enabled
- `SubjectUserName`, `SubjectUserSid`, `SubjectDomainName`, `SubjectLogonId` — creator subject
- `TargetUserName`, `TargetUserSid`, `TargetDomainName`, `TargetLogonId` — **(version 2)** target subject (when token differs from creator)
- `TokenElevationType` — see values below
- `MandatoryLabel` — integrity level **as a SID** (not friendly text)

**`TokenElevationType` values:**
- `%%1936` = Type 1 — full token (UAC disabled OR built-in administrator)
- `%%1937` = Type 2 — elevated token (Run as admin / always-elevated app)
- `%%1938` = Type 3 — limited token (UAC enabled, normal user-mode execution)

**`MandatoryLabel` SID values (integrity level):**
| SID | Level |
|---|---|
| `S-1-16-0` | Untrusted |
| `S-1-16-4096` | Low |
| `S-1-16-8192` | Medium |
| `S-1-16-8448` | Medium High |
| `S-1-16-12288` | High |
| `S-1-16-16384` | System |
| `S-1-16-20480` | Protected Process |

**Microsoft's monitoring recommendations for 4688:**
- `TokenElevationType=%%1936` for non-`$` accounts → UAC is disabled for that account (anomalous)
- `TokenElevationType=%%1937` for real users on standard workstations → user ran a program with admin privileges
- Process running from non-standard folder (not System32, Program Files) or restricted folder (Temporary Internet Files)
- Substring matching on suspicious process names (`mimikatz`, `cain.exe`, etc.)
- `MandatoryLabel=S-1-16-20480` (Protected Process) — uncommon, worth investigating

### Account management

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 4720 | Low | **User account created** | Watch for off-hours / non-admin creation |
| 4722 | Low | User account enabled | |
| 4723 | Low | Password change attempt (by self) | |
| **4724** | **Medium** | **Password reset** (by admin) | Watch for service account password resets — common precursor to lateral movement |
| 4725 | Low | User account disabled | |
| 4726 | Low | User account deleted | |
| 4738 | Low | User account changed | Detail-level changes — watch for `userAccountControl` changes (DONT_REQUIRE_PREAUTH = ASREPRoasting setup) |
| 4740 | Low | Account locked out | `CallerComputerName` is the source of failed attempts. Often misconfigured services rather than attacks |
| 4741 | Low | Computer account created | Watch for non-admin users creating computer accounts (MachineAccountQuota abuse) |
| 4742 | Low | Computer account changed | |
| 4743 | Low | Computer account deleted | |
| 4767 | Low | User account unlocked | |
| **4765** | **High** | **SID History added to an account** | Cross-domain attack indicator (Golden Ticket / SID History injection) |
| **4766** | **High** | **Attempt to add SID History failed** | Same — failure is still suspicious |
| 4781 | Low | Account name changed | Persistence / evasion technique |
| **4794** | **High** | **DSRM password set attempt** | Directory Services Restore Mode — DC compromise indicator |

### Group membership

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **4727** | **Medium** | Security-enabled global group **created** | |
| 4728 | Low | **Member added to security-enabled global group** | Privilege escalation — watch for additions to Domain Admins, Enterprise Admins |
| 4729 | Low | Member removed from security-enabled global group | |
| 4730 | Low | Security-enabled global group deleted | |
| 4731 | Low | Security-enabled local group created | |
| 4732 | Low | **Member added to security-enabled local group** | Watch for additions to local Administrators on member servers |
| 4733 | Low | Member removed from security-enabled local group | |
| 4734 | Low | Security-enabled local group deleted | |
| **4735** | **Medium** | Security-enabled local group changed | |
| **4737** | **Medium** | Security-enabled global group changed | |
| **4754** | **Medium** | Security-enabled universal group **created** | |
| **4755** | **Medium** | Security-enabled universal group changed | |
| 4756 | Low | **Member added to security-enabled universal group** | |
| 4757 | Low | Member removed from security-enabled universal group | |
| 4758 | Low | Security-enabled universal group deleted | |
| **4780** | **Medium** | **ACL set on accounts which are members of administrators groups** | |

### Service / scheduled task

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 4697 | Low | **Service installed** | New services are persistence indicators. Cross-reference with System 7045 |
| 4698 | Low | **Scheduled task created** | XML in `TaskContent` includes command line and trigger. Persistence |
| 4699 | Low | Scheduled task deleted | Defence evasion when an attacker cleans up |
| 4700 | Low | Scheduled task enabled | |
| 4701 | Low | Scheduled task disabled | |
| 4702 | Low | Scheduled task updated | |

### Object access

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 4656 | Low | A handle to an object was requested | Only logged where SACL configured |
| 4657 | Low | A registry value was modified | |
| 4660 | Low | An object was deleted | |
| 4663 | Low | An attempt was made to access an object | File/registry/object access — only where SACL configured |
| 4670 | Low | Permissions on an object were changed | |
| **4715** | **Medium** | **The audit policy (SACL) on an object was changed** | |
| 5140 | Low | **Network share accessed** | Successful share access — `IpAddress`, `ShareName`, `SubjectUserName` |
| 5142 | Low | Network share added | New shares — possible exfiltration setup |
| 5143 | Low | Network share modified | |
| 5144 | Low | Network share deleted | |
| 5145 | Low | **Network share access — detail** | Per-file share access. Very high volume — useful for SYSVOL/NETLOGON / IPC$ enumeration detection |

### Audit policy / log management

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **1102** | **Medium-High** | **Audit log cleared** | High-priority alert — attackers clear logs to hide tracks. Microsoft says: "Typically you should not see this event. There is no need to manually clear the Security event log in most cases." |
| **4719** | **High** | **System audit policy changed** | Watch for audit being disabled. Typically logged by default even when other audit policies aren't configured |
| **4906** | **Medium** | The CrashOnAuditFail value has changed | |
| **4907** | **Medium** | Auditing settings on object changed | |
| **4912** | **Medium** | Per User Audit Policy was changed | |

#### `1102` and `4719` — Microsoft's monitoring recommendations
**References:** [Event 1102](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1102) | [Event 4719](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719)

These are among the most reliable High-criticality events. Microsoft's specific guidance:
- 1102: Investigate every occurrence — there's typically no legitimate reason to manually clear the Security log
- 4719: Watch for audit being disabled (`AuditPolicyChanges` showing "Failure removed" or "Success removed") on critical hosts

### Trust / domain configuration

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **4706** | **Medium** | A new trust was created to a domain | |
| 4707 | Low | A trust to a domain was removed | |
| **4713** | **Medium** | Kerberos policy was changed | |
| **4714** | **Medium** | Encrypted data recovery policy was changed | |
| **4716** | **Medium** | Trusted domain information was modified | |
| **4739** | **Medium** | Domain Policy was changed | |
| **4865** | **Medium** | Trusted forest information entry added | |
| **4866** | **Medium** | Trusted forest information entry removed | |
| **4867** | **Medium** | Trusted forest information entry modified | |

### Certificate Services / PKI

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **4868** | **Medium** | Certificate manager denied a pending certificate request | |
| **4870** | **Medium** | Certificate Services revoked a certificate | |
| **4882** | **Medium** | Security permissions for Certificate Services changed | |
| **4885** | **Medium** | Audit filter for Certificate Services changed | |
| **4890** | **Medium** | Certificate manager settings changed | |
| **4892** | **Medium** | A property of Certificate Services changed | |
| **4896** | **Medium** | One or more rows deleted from the certificate database | |
| **5124** | **High** | **A security setting was updated on the OCSP Responder Service** | OCSP tampering = revocation bypass |

### Special-monitoring events

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **4618** | **High** | A monitored security event pattern has occurred | Custom-defined pattern; depends on configuration |
| **4649** | **High** | A replay attack was detected | May be false positive due to misconfiguration |
| **4675** | **Medium** | SIDs were filtered | |
| **4692** | **Medium** | Backup of data protection master key attempted | |
| **4693** | **Medium** | Recovery of data protection master key attempted | |
| **4897** | **High** | Role separation enabled | |
| **4908** | **Medium** | Special Groups Logon table modified | |
| **4964** | **High** | **Special groups assigned to a new logon** | Custom-configured "important" group list. **Use this as the primary detection for Domain Admin logons to non-DC hosts** |

### Netlogon / ZeroLogon

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **5827** | **Medium** | **Netlogon service denied a vulnerable Netlogon secure channel from a machine account** | **ZeroLogon (CVE-2020-1472) detection** |
| **5828** | **Medium** | **Netlogon service denied a vulnerable Netlogon secure channel using a trust account** | **ZeroLogon (CVE-2020-1472) detection** |

These events appear once Microsoft's August 2020 patch is applied — they fire when a host attempts the vulnerable insecure RPC binding pattern that ZeroLogon exploits.

### Network Policy Server (RADIUS)

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| **6273** | **Medium** | NPS denied access to a user | |
| **6274** | **Medium** | NPS discarded the request for a user | |
| **6275** | **Medium** | NPS discarded accounting request | |
| **6276** | **Medium** | NPS quarantined a user | |
| **6277** | **Medium** | NPS granted access (probation, health policy not met) | |
| **6278** | **Medium** | NPS granted full access (host met health policy) | |
| **6279** | **Medium** | NPS locked the user account due to repeated failed authentication | |
| **6280** | **Medium** | NPS unlocked the user account | |

### Windows Filtering Platform (firewall)

| EventID | Crit | Meaning | Notes |
|---|---|---|---|
| 5152 | Low | WFP blocked a packet | |
| 5154 | Low | WFP permitted listen | |
| 5155 | Low | WFP blocked listen | |
| 5156 | Low | WFP connection allowed | Massive volume — use selectively |
| 5157 | Low | WFP connection blocked | Useful for detecting attempted C2 from blocked apps |
| 5158 | Low | WFP bind allowed | Listener detection |
| 5159 | Low | WFP bind blocked | |

---

## System channel — `XmlWinEventLog:System`

| EventID | Meaning | Notes |
|---|---|---|
| 7036 | Service state change | Volume scales with service activity |
| 7040 | Service start type changed | Manual → Auto changes can indicate persistence setup |
| 7045 | **Service installed** | New services. Cross-reference with Security 4697 — sometimes one fires when the other doesn't |
| 1074 | System shutdown initiated | IR context — who/what initiated a shutdown |
| 6005 | Event log service started | System uptime tracking — first event after boot |
| 6006 | Event log service stopped | Clean shutdown |
| 6008 | **Unexpected shutdown** | Crash / power loss — IR context |
| 6013 | System uptime | |
| 7022 | Service hung at startup | |
| 41 | Kernel-Power: system rebooted without clean shutdown | |

---

## PowerShell Operational — `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`

Requires PowerShell logging policies enabled. Without them, this channel is useless for detection.

| EventID | Meaning | Notes |
|---|---|---|
| 4103 | **Module logging** (pipeline execution) | Logs cmdlet pipelines. Less detailed than 4104 but lower volume |
| 4104 | **Script block logging** | The single most valuable PS event. Logs **deobfuscated** script content. Long scripts split across multiple events with `MessageTotal>1` — `transaction` or `stats` reassembly required |
| 4105 | Script block invocation start | Pair with 4106 for execution timing |
| 4106 | Script block invocation stop | |
| 400 | Engine state change (started) | PowerShell session start. Useful for detecting non-standard hosts (PSExec, custom runspaces) |
| 403 | Engine state change (stopped) | |
| 600 | Provider lifecycle | |

**Key fields in 4104:**
- `ScriptBlockText` — the actual code (deobfuscated)
- `Path` — script file path (blank for inline / interactive)
- `ScriptBlockId` — GUID, same across split messages — use this for reassembly
- `MessageNumber` / `MessageTotal` — for chunked long scripts

**Common detection patterns:**
- Encoded commands: `ScriptBlockText` containing `FromBase64String`, `-EncodedCommand`, `-enc`, `IEX(`, `Invoke-Expression`
- AMSI bypass attempts: `[Ref].Assembly.GetType`, `amsiInitFailed`, `AmsiUtils`
- Download cradles: `Net.WebClient`, `DownloadString`, `Invoke-WebRequest -Uri`
- Reflection / in-memory execution: `[Reflection.Assembly]::Load`, `GetMethod`

---

## Sysmon — `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

> **Sysmon ownership / installation update (verified via Microsoft Learn):**
> - **Current version:** v15.2 (March 2026)
> - **Built into Windows 11 / Windows Server 2025** as an optional feature starting February 2026 — can be enabled via Windows feature management without a separate download
> - **Older Windows versions** still need the standalone download from Sysinternals
> - **Sysmon for Linux** also exists (separate GitHub project)
> - References: [Sysmon overview](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview) | [Sysmon (Sysinternals)](https://learn.microsoft.com/sysinternals/downloads/sysmon)

**Coverage and volume depend entirely on the Sysmon config.** A wide-open config produces enormous volume; a tuned config (SwiftOnSecurity, Olaf Hartong sysmon-modular) focuses on high-value events.

> Microsoft on Sysmon: "Sysmon does not provide analysis of the events it generates, nor does it attempt to hide itself from attackers."

### Capabilities worth knowing

- Multi-hash logging: SHA1 (default), MD5, SHA256, IMPHASH (and combinations)
- **Process GUID** (`ProcessGuid`) survives PID reuse — preferred for process tree correlation over PID
- **Session GUID** allows correlation by logon session
- Driver / DLL signature and hash logging
- Configuration auto-reload on registry change
- Runs as a [protected process](https://learn.microsoft.com/windows/win32/services/protecting-anti-malware-services-) (resists user-mode tampering)

### Event ID reference (verified against Sysmon v15.2)

| EventID | Filter Tag | Meaning | Detection notes |
|---|---|---|---|
| 1 | ProcessCreate | **Process create** | Richer than 4688 — includes parent command line and hashes. The single most useful Sysmon event |
| 2 | FileCreateTime | File creation time changed | Timestomping detection |
| 3 | NetworkConnect | **Network connection** | Per-process network connections. Filter by `Image` to find unusual processes making connections |
| 4 | n/a (not filterable) | Sysmon service state changed | Tampering indicator — Sysmon stopped or started |
| 5 | ProcessTerminate | Process terminated | Pair with Event 1 for process lifetime |
| 6 | DriverLoad | **Driver loaded** | Watch for unsigned drivers — BYOVD attacks |
| 7 | ImageLoad | Image loaded (DLL) | Very high volume — typically only for specific Image filters. DLL injection / side-loading detection |
| 8 | CreateRemoteThread | **CreateRemoteThread** | Process injection technique |
| 9 | RawAccessRead | Raw disk access | Direct disk access — credential theft (NTDS.dit) indicator |
| 10 | ProcessAccess | **ProcessAccess** | Process opening another process — credential dumping detection. `lsass.exe` as `TargetImage` with high `GrantedAccess` is the classic Mimikatz pattern |
| 11 | FileCreate | **FileCreate** | New files. Filter by `TargetFilename` patterns (Startup folder, scheduled task XML, etc.) |
| 12 | RegistryEvent | Registry create/delete | |
| 13 | RegistryEvent | **Registry value set** | Persistence detection — Run keys, services, AppInit_DLLs |
| 14 | RegistryEvent | Registry rename | |
| 15 | FileCreateStreamHash | Alternate Data Streams + hash | Includes Zone.Identifier — detects internet-downloaded files |
| 16 | n/a (not filterable) | Sysmon configuration changed | Detection of Sysmon config tampering |
| 17 | PipeEvent | Named pipe created | Some C2 frameworks use named pipes |
| 18 | PipeEvent | Named pipe connected | |
| 19 | WmiEvent | WMI EventFilter | WMI persistence |
| 20 | WmiEvent | WMI EventConsumer | WMI persistence |
| 21 | WmiEvent | WMI EventConsumerToFilterBinding | WMI persistence — the binding that makes 19/20 active |
| 22 | DnsQuery | **DNS query** | Per-process DNS — DGA detection, suspicious TLDs |
| 23 | FileDelete | **FileDelete (with archival)** | Deleted file content saved to `ArchiveDirectory` (default `C:\Sysmon`). Anti-forensics resistance |
| 24 | ClipboardChange | Clipboard change | High volume — typically scoped narrowly |
| 25 | ProcessTampering | Process tampering | Process hollowing / herpaderping detection |
| 26 | FileDeleteDetected | FileDelete (without archival) | Like 23 without the archival — lower-impact alternative |
| 27 | FileBlockExecutable | **FileBlockExecutable** | Sysmon **blocked** PE file creation (requires `FileBlockExecutable` config) |
| 28 | FileBlockShredding | **FileBlockShredding** | Sysmon blocked file shredding tools (e.g. SDelete) |
| 29 | FileExecutableDetected | FileExecutableDetected | Detection-only version of 27 (logs PE creation without blocking) |
| 255 | n/a | Sysmon error | Internal errors — high system load, bugs, or integrity check failures |

### Key correlation fields

- `ProcessGuid` — survives PID reuse; use for process tree reconstruction
- `LogonId` — Windows logon session ID
- `IntegrityLevel` — Sysmon uses friendly text (`Low`, `Medium`, `High`, `System`) unlike 4688's SID-based `MandatoryLabel`

### Filtering rules (per Sysmon config)

- `include` rule: only matching events logged
- `exclude` rule: all events logged except matching ones
- Exclude takes precedence over include
- Same-field rules behave as OR; different-field rules behave as AND
- Conditions: `is`, `contains`, `begin with`, `end with`, `image`, `contains any`, `contains all`, `excludes`, `less than`, `more than`

---

## Windows Defender Operational — `XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational`

| EventID | Meaning | Notes |
|---|---|---|
| 1116 | **Malware detected** | Detection event — primary signal |
| 1117 | Malware action taken | `cleaned`, `quarantined`, `removed` |
| 1118 | Malware action failed | Manual investigation needed |
| 1119 | **Critical malware action failure** | Higher severity — Defender couldn't handle it |
| 1006 | Scan started | |
| 1007 | Scan completed | |
| 5001 | **Real-time protection disabled** | Tampering — high priority |
| 5004 | Real-time protection settings changed | |
| 5007 | **Defender configuration changed** | Watch for exclusions being added (`ExclusionPath`, `ExclusionExtension`, `ExclusionProcess`) — common defence evasion |
| 5010 | Anti-spyware scanning disabled | |
| 5012 | Anti-virus scanning disabled | |
| 5101 | Defender disabled | |
| 1015 | Behaviour-based detection | EDR-style behavioural detection (Defender for Endpoint feature) |

> **Note:** Some Defender for Endpoint behavioural events are logged to a separate channel (`Microsoft-Windows-Windows Defender/WHC` and others). For Defender for Endpoint detail, the unified `Microsoft 365 Defender` portal / Advanced Hunting tables are typically richer than the on-host event channels.

---

## Task Scheduler Operational — `XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational`

Lower-level than Security 4698 — covers tasks running, succeeding, failing.

| EventID | Meaning | Notes |
|---|---|---|
| 106 | **Task registered** | Task created/imported |
| 140 | Task updated | |
| 141 | **Task deleted** | Defence evasion — attackers cleaning up |
| 200 | Action started | Action (e.g. command) being executed |
| 201 | Action completed | |
| 129 | Task triggered by user | |
| 318 | Task engine started | |
| 102 | Task completed | |

---

## Directory Service — `XmlWinEventLog:Directory Service`

Domain Controllers only. Covers AD object changes when Directory Service Changes auditing is enabled.

| EventID | Meaning | Notes |
|---|---|---|
| 5136 | **Directory service object modified** | Granular AD changes. High value but high volume |
| 5137 | Directory service object created | New AD objects |
| 5138 | Directory service object undeleted | AD recycle bin restore |
| 5139 | Directory service object moved | |
| 5141 | **Directory service object deleted** | Detect deletion of privileged objects |

---

## DNS Server — `XmlWinEventLog:DNS Server`

DNS Servers only (typically DCs). Massive volume — typically not enabled or heavily filtered.

| EventID | Meaning | Notes |
|---|---|---|
| 256 | DNS query received | Per-query — extreme volume |
| 257 | DNS response sent | |
| 770 | Suspicious zone transfer | |

---

## Reference: Kerberos ticket encryption types

Field `TicketEncryptionType` in 4768/4769. Verified against Microsoft Learn.

| Code | Encryption | Status |
|---|---|---|
| `0x1` | DES-CBC-CRC | Disabled by default since Windows 7 / Server 2008 R2 |
| `0x3` | DES-CBC-MD5 | Disabled by default since Windows 7 / Server 2008 R2 |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | Modern, supported since Server 2008 / Vista |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | Modern, preferred |
| `0x17` | RC4-HMAC | Legacy — kerberoasting / RC4 downgrade indicator |
| `0x18` | RC4-HMAC-EXP | Export-grade RC4 |
| `0xFFFFFFFF` | (none) | Shows in Audit Failure events |

**Detection:** Kerberoasting requests `RC4` (`0x17`) for service tickets because the resulting hash is crackable. A user account with a service principal name suddenly receiving 4769 events with `TicketEncryptionType=0x17` from a non-standard host is suspicious.

The 2025 update to 4768/4769 adds `AccountSupportedEncryptionTypes`, `ServiceSupportedEncryptionTypes`, `DCSupportedEncryptionTypes`, and `ClientAdvertizedEncryptionTypes` fields — these enable much more reliable downgrade attack detection by comparing what was advertised vs what was used.

## Reference: Kerberos pre-authentication types

Field `PreAuthType` in 4768. Verified against Microsoft Learn.

| Type | Name | Description |
|---|---|---|
| `0` | (none) | Logon without pre-authentication — security risk |
| `2` | PA-ENC-TIMESTAMP | Standard password authentication |
| `11` | PA-ETYPE-INFO | Rare in MS AD environments |
| `15` | PA-PK-AS-REP_OLD | Smart card logon |
| `16` | PA-PK-AS-REQ | Smart card request |
| `17` | PA-PK-AS-REP | Smart card response |
| `19` | PA-ETYPE-INFO2 | Rare in MS AD environments |
| `20` | PA-SVR-REFERRAL-INFO | KDC referral tickets |
| `138` | PA-ENCRYPTED-CHALLENGE | Kerberos Armoring (FAST) — Server 2012+ DCs, Win8+ clients |

**Detection:** `PreAuthType=0` (no pre-auth) flags accounts configured with "Do not require Kerberos preauthentication" — required for AS-REP roasting.

---

## Common SPL patterns

### Failed logon analysis
```
source="XmlWinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| where count > 5
```

### User enumeration detection (4625 SubStatus 0xC0000064)
```
source="XmlWinEventLog:Security" EventCode=4625 SubStatus="0xC0000064"
| stats dc(TargetUserName) as unique_users count by IpAddress
| where unique_users > 10
```

### Process tree (Sysmon)
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats values(Image) values(CommandLine) by ProcessGuid, ParentProcessGuid
```

### PowerShell script block reassembly
```
source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| stats values(ScriptBlockText) as ScriptBlockText by ScriptBlockId, Computer
| eval FullScript=mvjoin(ScriptBlockText, "")
```

### Defender exclusion additions (defence evasion)
```
source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode=5007
| search "ExclusionPath" OR "ExclusionExtension" OR "ExclusionProcess"
```

### Service installation detection (combine 4697 + 7045)
```
(source="XmlWinEventLog:Security" EventCode=4697)
OR (source="XmlWinEventLog:System" EventCode=7045)
| eval service_name=coalesce(ServiceName, ServiceFileName)
| stats earliest(_time) as first_seen by service_name, host
| where first_seen > relative_time(now(), "-24h")
```

### Kerberoasting detection
```
source="XmlWinEventLog:Security" EventCode=4769 TicketEncryptionType=0x17
| where ServiceName!="krbtgt" AND ServiceName!="*$"
| stats count dc(ServiceName) as unique_services by TargetUserName, IpAddress
| where unique_services > 5
```

### Domain Admin logon to non-DC (using 4964)
```
source="XmlWinEventLog:Security" EventCode=4964
| eval is_dc=if(match(Computer, "(?i)dc\d+|domain.*controller"), "yes", "no")
| where is_dc="no"
| stats count by TargetUserName, Computer, _time
```

### ZeroLogon detection (5827/5828)
```
source="XmlWinEventLog:Security" (EventCode=5827 OR EventCode=5828)
| stats count by host, src
```

---

## Audit policy categories — what produces what

Without the right audit policy, events don't fire. Mapping audit subcategories to event IDs (verified against [Advanced Audit Policy Configuration](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)):

| Audit Subcategory | Events |
|---|---|
| Audit Logon | 4624, 4625, 4634, 4647, 4648 |
| Audit Account Lockout | 4740 |
| Audit Special Logon | 4672, **4964** |
| Audit Process Creation | 4688, 4696 |
| Audit Process Termination | 4689 |
| Audit User Account Management | 4720, 4722–4726, 4738, 4740, 4781 |
| Audit Security Group Management | 4727–4733, 4754–4758 |
| Audit Computer Account Management | 4741–4743 |
| Audit Kerberos Authentication Service | 4768, 4771, 4772 |
| Audit Kerberos Service Ticket Operations | 4769, 4770, 4773 |
| Audit Credential Validation | 4776, 4777 |
| Audit Security System Extension | 4697 |
| Audit Other Object Access Events | 4698–4702 (scheduled tasks) |
| Audit File Share | 5140, 5142–5145 |
| Audit Filtering Platform Connection | 5156, 5157 |
| Audit Audit Policy Change | 4719 |
| Audit System Integrity | 1102 |
| Audit Directory Service Changes | 5136–5141 |
| Audit Sensitive Privilege Use | 4673, 4674 |

For "Audit Process Creation", **also enable** "Include command line in process creation events" via Group Policy (`Computer Configuration → Administrative Templates → System → Audit Process Creation`) to populate the `CommandLine` field in 4688.

---

## Gotchas

- **No audit policy = no events.** Detection content assuming Security events 4624/4625/4688/etc. requires the corresponding subcategories enabled. Audit policy gaps are silent failures. Microsoft notes that **default audit policies vary by Windows version** — many subcategories are "Not Configured" by default, including some that capture High-criticality events.
- **DC-only events on member servers won't fire.** 4768/4769/4771 fire on DCs (where authentication actually happens), not on the workstation that initiated the logon. Don't search member-server data for them.
- **Sysmon now built-in on Win11 / Server 2025** (Feb 2026 onward) but still requires explicit enablement. Older Windows versions need the Sysinternals download.
- **Long PowerShell 4104 events are split.** Reassembly via `ScriptBlockId` is required for full script visibility on long scripts.
- **`source` field, not `Channel`.** When filtering by channel in Splunk, use `source="XmlWinEventLog:..."`. The `Channel` XML field also exists but isn't always extracted as expected.
- **XML vs Classic mixed environments.** If some hosts ingest via XML and others via classic `WinEventLog:*`, queries break across the fleet. Standardise on XML and migrate.
- **Event ID 4624 LogonType=3 is the noise floor.** Filtering it out without thinking is normal but can hide lateral movement (SMB-based) — instead filter to specific source IPs / accounts of interest.
- **Audit log clearing (1102) often *follows* an attack rather than preceding it.** Detection works, but the value is forensic — look at events leading up to the clear timestamp, knowing later events have been removed.
- **The 2025 Kerberos update.** Windows Server 2016+ post-January 2025 cumulative updates display new fields on 4768/4769. Detections written against pre-update field structures still work (those fields remain) but new high-value fields (`AccountSupportedEncryptionTypes`, `RequestTicketHash`, etc.) are only available post-update.
- **`MandatoryLabel` in 4688 is a SID, not friendly text** — unlike Sysmon's `IntegrityLevel` field which is human-readable. Easy to confuse when building cross-source detections.
- **`TokenElevationType` uses message resource codes.** `%%1936`, `%%1937`, `%%1938` are not literal strings in the raw event — they're resolved to "Type 1", "Type 2", "Type 3" at display time. Splunk may show one or the other depending on extraction config.

---

## Sources and further reading

All URLs verified at time of writing.

**Master references:**
- [Appendix L: Events to monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) — criticality ratings, event ID master list
- [Advanced Audit Policy Configuration](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration) — subcategory → event ID mapping
- [Monitoring Active Directory for Signs of Compromise](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise) — Microsoft's overall AD monitoring guidance

**Per-event references** (selected):
- [Event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624) — successful logon
- [Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625) — failed logon
- [Event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) — process create
- [Event 4768](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768) — Kerberos TGT request
- [Event 4769](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769) — Kerberos service ticket request
- [Event 4964](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4964) — special groups assigned to a new logon
- [Event 1102](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1102) — audit log cleared

The full per-event documentation set lives at `https://learn.microsoft.com/windows/security/threat-protection/auditing/event-NNNN` for any event ID NNNN.

**Sysmon:**
- [Sysinternals Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) — current standalone documentation (v15.2)
- [Sysmon overview (built-in)](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview) — Windows 11 / Server 2025 built-in feature
- [Understanding Sysmon events](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events) — detection-focused interpretation

**Caveats:**
- Microsoft's per-event pages are version-specific. Field availability varies by Windows version (each event page documents version history).
- Some content here (PowerShell logging detection patterns, SPL examples) is based on community-validated practice rather than Microsoft documentation. Microsoft's official guidance generally focuses on what events mean and when to investigate, not specific SIEM detection logic.
- Detection threshold values in SPL examples (e.g. `count > 5` for failed logon) are illustrative — calibrate to your environment's baseline.
