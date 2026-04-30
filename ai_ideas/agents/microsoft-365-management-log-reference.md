# Microsoft 365 Management Log Reference

> Companion to `splunk-sourcetype-library.md`. The library covers the `o365:management:activity` sourcetype broadly; this file goes deep on **which RecordTypes and Operations matter, what fields they populate, what they're useful for, and Microsoft's own audit schema**.
>
> Scoped to events relevant to security detection, IR, and admin auditing across Entra ID, Exchange Online, SharePoint Online, OneDrive for Business, Microsoft Teams, and the Security & Compliance Center.
>
> **Authoritative sources** (cited inline by URL fragment, full citations at end):
> - [Microsoft Learn: Office 365 Management Activity API schema](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema) — canonical envelope and per-workload field reference
> - [Microsoft Learn: Audited activities (Microsoft Purview)](https://learn.microsoft.com/purview/audit-log-activities) — Operation-name reference per workload
> - [Microsoft Learn: Search the audit log](https://learn.microsoft.com/purview/audit-search) — operational guidance for tenant-side audit
> - [Microsoft Learn: Auditing solutions in Microsoft Purview](https://learn.microsoft.com/purview/audit-solutions-overview) — licensing and retention tier detail (Standard vs Audit Premium)

---

## How the Management Activity API works

The Office 365 Management Activity API is Microsoft's tenant-wide audit feed. Workload services (Exchange, SharePoint, Entra ID, Teams, etc.) emit audit records into a per-tenant unified audit log. A subscriber registers per-workload subscriptions and pulls **content blobs** from `/api/v1.0/{tenant}/activity/feed/subscriptions/content`, where each blob holds a JSON array of audit records. Splunk's `splunk_ta_o365` add-on does this on the customer's behalf.

> "Office 365 customers can use the Management Activity API to retrieve information about user, admin, system, and policy actions and events from Office 365 and Microsoft Entra ID activity logs." — [Microsoft Learn](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-reference)

### Data flow

```
Workload service (Exchange/SP/Entra ID/Teams)
        │  emits audit records
        ▼
Unified audit pipeline (tenant-side, Microsoft-managed)
        │  aggregates, dedupes within workload, batches into content blobs
        ▼
Management Activity API content endpoint
        │  per-workload subscriptions
        ▼
splunk_ta_o365 modular input
        │  REST poll, normalisation, sourcetype assignment
        ▼
index=o365 (or wherever the input is configured)
   sourcetype=o365:management:activity
```

### Key constraints

- **Unified audit logging must be enabled tenant-side.** Many tenants ship with audit disabled or partially configured. Absence of expected events is most often a tenant configuration gap — verify via `Get-AdminAuditLogConfig` (`UnifiedAuditLogIngestionEnabled`) or the Purview compliance portal — not a Splunk problem.
- **Ingestion latency.** Most workloads land in the API within 30 minutes of the underlying activity. Some (notably Entra ID directory changes and Teams events) routinely take 60–90 minutes. Microsoft documents the target as "within 24 hours" worst-case. Never write detections that assume sub-30-minute freshness.
- **At-least-once delivery.** The same record (same `Id`) can appear in multiple content blobs, particularly across content-blob retries and TA checkpoint resets. Detections that count occurrences must dedupe by `Id` for correctness.
- **Licensing gates content depth.** `MailItemsAccessed`, `Send`, and other "Audit (Premium)" Exchange events require Microsoft 365 E5, Microsoft 365 E5 Compliance, or the standalone Audit Premium add-on. E3 tenants have a thinner Exchange feed and shorter retention.
- **Per-workload retention varies.** Audit (Standard) retains 180 days; Audit (Premium) one year by default with the option of ten years per record (additional licensing). The API itself only exposes the last 7 days of content blobs — historical search is via the Purview portal or Search-UnifiedAuditLog, not the management API.

### Subscription model

Subscriptions are created per workload via `POST /subscriptions/start?contentType=...` with content types:

| Content type | Workload coverage |
|---|---|
| `Audit.AzureActiveDirectory` | Entra ID sign-ins (legacy STS), directory changes, role assignments, app consent, conditional access, application audit |
| `Audit.Exchange` | Mailbox audit, admin cmdlets, transport rules |
| `Audit.SharePoint` | SharePoint Online and OneDrive for Business file/site activity |
| `Audit.General` | Everything else: Teams, Power Platform, Defender, Purview, Stream, Yammer, Forms, etc. |
| `DLP.All` | Data loss prevention rule matches across Exchange/SharePoint/Endpoint |

`splunk_ta_o365` exposes these as separate input checkboxes. Disabling one shrinks the data feed accordingly — a common first cause of "missing M365 events".

---

## Sourcetype mapping recap

> See `splunk-sourcetype-library.md` for the full sourcetype shape and CIM mapping. This file goes deeper on the schema **inside** `o365:management:activity`.

| Sourcetype | Source feed | Coverage |
|---|---|---|
| `o365:management:activity` | Management Activity API content blobs | All workloads — Entra ID, Exchange, SharePoint/OneDrive, Teams, SCC, DLP, Power Platform |
| `o365:graph:messagetrace` | Microsoft Graph Message Trace API | Mail flow envelope (sender, recipient, status, size). Not in the unified audit log |
| `o365:service:healthIssue` | Microsoft Graph Service Health API | Tenant service health incidents and advisories |
| `o365:service:message` | Microsoft Graph Service Communications API | Tenant service messages and announcements |
| `ms:o365:management` | Legacy `Splunk_TA_microsoft-cloudservices` modular input | Same envelope as `o365:management:activity`, retired path |

Detection content should target `o365:management:activity` for nearly all behavioural detections. `o365:graph:messagetrace` is for mail-flow questions ("did this message reach the recipient?") — different latency, different fidelity, no `Workload` field.

---

## Common envelope fields

Every record returned from the Management Activity API — regardless of workload — carries this base envelope. These are present at the top level of the JSON object and are reliably extracted by `splunk_ta_o365`.

| Field | Type | Meaning |
|---|---|---|
| `Id` | GUID | Unique audit record identifier. **Use for deduplication.** |
| `CreationTime` | ISO 8601 UTC | When the workload emitted the record. Maps to Splunk `_time` |
| `RecordType` | integer | Master discriminator. Numeric enum — see below |
| `Operation` | string | Workload-specific action name (e.g. `MailItemsAccessed`, `FileDownloaded`, `Add member to role.`) |
| `OrganizationId` | GUID | Tenant ID — useful only in MSP / multi-tenant scenarios |
| `UserType` | integer | Caller principal type — see enum below |
| `UserKey` | string | Immutable principal identifier (typically the AAD object ID or PUID). **Stable across UPN renames** |
| `UserId` | string | Display principal — usually the UPN. May be empty for system events |
| `Workload` | string | Friendly workload name (`Exchange`, `AzureActiveDirectory`, `SharePoint`, `OneDrive`, `MicrosoftTeams`, `SecurityComplianceCenter`, etc.) |
| `ResultStatus` | string | Workload-dependent — `Succeeded`/`Failed` (Exchange/SCC), `Success`/`Failure` (Entra ID), sometimes blank or numeric |
| `ObjectId` | string | The thing acted upon — file URL for SharePoint, mailbox SMTP for Exchange, target user UPN/ID for Entra ID, etc. |
| `ClientIP` | string | Caller's IP. **Often the proxy / front-door IP, not the true client.** Workload-specific fields (below) are more reliable |
| `UserAgent` | string | HTTP user agent. Rarely populated for non-web flows |
| `Scope` | string | `online`/`onprem` for hybrid Exchange — distinguishes Exchange Online vs on-prem mailbox audit |

### `UserType` enum

| Value | Name | Meaning |
|---|---|---|
| `0` | Regular | Standard user account |
| `1` | Reserved | (Not used) |
| `2` | Admin | Admin acting in administrative context |
| `3` | DcAdmin | Microsoft datacenter admin (cross-tenant operations) |
| `4` | System | System-initiated event — no human caller |
| `5` | Application | First-party Microsoft application |
| `6` | ServicePrincipal | Third-party service principal / app registration |
| `7` | CustomPolicy | Custom DLP / retention policy actor |
| `8` | SystemPolicy | System-managed policy actor |

`UserType=6` is the high-signal value for OAuth abuse — application principals acting in Entra ID and Exchange are increasingly the post-compromise persistence vector. `UserType=4`/`5` events are typically Microsoft's own telemetry and can be aggressively filtered.

### `RecordType` enum (master discriminator)

`RecordType` is the single most useful field for query scoping. Numeric in the raw event; the `splunk_ta_o365` add-on usually leaves it numeric, so detections must use the integer value. The symbolic name is what Microsoft uses in the schema documentation.

| Value | Symbolic name | Workload | Notes |
|---|---|---|---|
| `1` | `ExchangeAdmin` | Exchange | Admin cmdlets in Exchange Online |
| `2` | `ExchangeItem` | Exchange | Mailbox item operations (Send, Move, Delete) |
| `3` | `ExchangeItemGroup` | Exchange | Bulk item operations |
| `4` | `SharePoint` | SharePoint | Site / list / permission operations |
| `6` | `SharePointFileOperation` | SharePoint / OneDrive | File access, download, upload, sharing |
| `8` | `AzureActiveDirectory` | Entra ID | Generic AAD audit |
| `9` | `AzureActiveDirectoryAccountLogon` | Entra ID | Legacy account logon |
| `14` | `SharePointSharingOperation` | SharePoint | External sharing events |
| `15` | `AzureActiveDirectoryStsLogon` | Entra ID | STS sign-in events |
| `18` | `SecurityComplianceCenterEOPCmdlet` | SCC | Exchange Online Protection cmdlets |
| `20` | `PowerBIAudit` | Power BI | Report / dataset access |
| `22` | `ExchangeAggregatedOperation` | Exchange | Aggregated activity (e.g. `MailItemsAccessed` aggregate sets) |
| `23` | `PowerShell` | Multi | PowerShell-driven admin |
| `24` | `CRM` | Dynamics 365 | CRM audit |
| `25` | `Yammer` | Yammer | Now Viva Engage — events still appear |
| `28` | `ThreatIntelligence` | Defender for O365 | Phishing / malware verdicts |
| `30` | `MicrosoftTeams` | Teams | Teams activity |
| `35` | `ThreatIntelligenceUrl` | Defender for O365 | Safe Links time-of-click |
| `40` | `SecurityComplianceAlerts` | SCC | Audit alert policy hits |
| `41` | `ThreatIntelligenceAtpContent` | Defender for O365 | Safe Attachments verdicts |
| `42` | `Sway` | Sway | Sway document activity |
| `44` | `SecurityComplianceCenterEOPCmdlet` | SCC | (See 18 — both values seen in different tenants) |
| `47` | `ExchangeSearch` | Exchange | Search activity |
| `48` | `SharePointSearch` | SharePoint | Search activity |
| `49` | `PrivacyDataMinimization` | Purview | Data minimization actions |
| `50` | `LabelExplorer` | Purview | Sensitivity-label explorer |
| `52` | `MicrosoftFlow` | Power Automate | Flow create/run/delete |
| `54` | `AeD` | Advanced eDiscovery | eDiscovery case operations |
| `55` | `MicrosoftStream` | Stream | Video upload / share / delete |
| `61` | `MipAutoLabelSharePointItem` | Purview MIP | Auto-labelling on SharePoint |
| `63` | `DataLossPreventionEndpoint` | Defender for Endpoint | Endpoint DLP rule matches |
| `64` | `AirInvestigation` | Defender for O365 | Auto investigation |
| `65` | `Quarantine` | Exchange | Quarantine release / preview |
| `66` | `MicrosoftForms` | Forms | Form activity |
| `78` | `MicrosoftTeamsAdmin` | Teams | Teams admin actions |
| `82` | `HygieneEvent` | Exchange | Mail hygiene |
| `87` | `Campaign` | Defender for O365 | Phishing campaign correlation |
| `90` | `DataInsightsRestApiAudit` | Purview | Insights API access |
| `99` | `DataLossPreventionExchange` | Exchange | Exchange DLP rule matches |
| `109` | `MicrosoftTeamsShifts` | Teams | Shifts app activity |
| `147` | `CoreReportingSettings` | M365 | Reporting settings change |
| `148` | `ComplianceConnector` | Purview | Connector ingestion |
| `155` | `OWAAuditLogs` | Exchange | OWA-specific audit |
| `181` | `MicrosoftPurview` | Purview | Purview policy operations |

> Microsoft adds new RecordType values regularly. Treat unknown values as "filter in, investigate later" rather than dropping. The schema is documented in [Office 365 Management Activity API schema](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema).

### `ResultStatus` — workload-dependent values

| Workload | Common values |
|---|---|
| Exchange (`ExchangeAdmin`, `ExchangeItem`) | `Succeeded`, `PartiallySucceeded`, `Failed`, blank |
| Entra ID (`AzureActiveDirectoryStsLogon`, `AzureActiveDirectory`) | `Success`, `Failure`, blank |
| SharePoint / OneDrive | Usually blank — success is implicit, failures rarely emit |
| SCC | `Succeeded`, `Failed` |
| Teams | Often blank; some operations populate `Success`/`Failure` |

Detections that key on `ResultStatus="Failed"` must scope by workload — a cross-workload `Failed` filter misses Entra ID's `Failure` and the half of SharePoint events that are blank.

### `UserId` vs `UserKey`

- `UserId` is the human-readable principal — typically UPN (`alice@contoso.com`). Changes when UPN is renamed. Empty for system principals.
- `UserKey` is the immutable AAD object ID (or legacy PUID for some pre-AAD-cutover events). Stable across renames.
- Use `UserKey` as the join key for any analytic spanning more than 30 days — UPN renames during that window will silently break `UserId`-based correlation.

### Nested property patterns

Several workloads encode their detail in arrays of `{Name, Value}` objects. The TA extracts these as multi-value fields; access via `mvexpand` or `spath`.

| Field | Where it appears | Use |
|---|---|---|
| `ExtendedProperties{}` | Entra ID, Teams, SCC | Workload-specific metadata — e.g. `ResultStatusDetail`, `UserAgent`, `RequestType`, `ConditionalAccessStatus` |
| `Parameters{}` | Exchange admin cmdlets, SCC cmdlets | The cmdlet parameters as supplied (e.g. `Identity`, `ForwardingSmtpAddress`, `RoleAssignee`) |
| `ModifiedProperties{}` | Entra ID directory changes | `Name`, `OldValue`, `NewValue` for each changed attribute |
| `ActorContextId` / `Actor{}` | Entra ID | The acting principal identifiers, often duplicating `UserId`/`UserKey` |
| `Target{}` | Entra ID | The principal/object being acted upon |

To access a nested value reliably:

```spl
| spath input=_raw "ExtendedProperties{}.Name" output=ext_names
| spath input=_raw "ExtendedProperties{}.Value" output=ext_values
| eval cas_idx = mvfind(ext_names, "^ConditionalAccessStatus$")
| eval ConditionalAccessStatus = mvindex(ext_values, cas_idx)
```

Or using `mvzip`/`mvexpand` to pivot to one row per `{Name, Value}`:

```spl
| eval pair = mvzip(mvindex('ExtendedProperties{}.Name', 0, -1), mvindex('ExtendedProperties{}.Value', 0, -1), "=")
| mvexpand pair
| rex field=pair "^(?<prop_name>[^=]+)=(?<prop_value>.*)$"
```

---

## Entra ID — `Workload=AzureActiveDirectory`

RecordTypes: `AzureActiveDirectoryStsLogon (15)` for sign-ins, `AzureActiveDirectory (8)` for directory and admin operations, `AzureActiveDirectoryAccountLogon (9)` for legacy account logon (rarely seen on modern tenants).

> **Important:** The Management Activity API is **not** the primary Entra ID sign-in source. The richer feed is `Microsoft.Graph` audit / sign-in logs surfaced by `splunk_ta_microsoft-cloudservices` as `azure:monitor:aad`. The Management API's `AzureActiveDirectoryStsLogon` covers a subset and lacks risk scoring, conditional access detail, and authentication method richness. Use the Graph feed for sign-in detection where available; fall back to `o365:management:activity` only when it isn't ingested.

### Sign-in events — `RecordType=15` (`AzureActiveDirectoryStsLogon`)

Top-level fields specific to STS logon:

| Field | Meaning |
|---|---|
| `ApplicationId` | The AAD application the user signed into (GUID) |
| `Application` | Friendly app name |
| `ActorIpAddress` | True client IP — **prefer this over envelope `ClientIP`** |
| `LogonError` | Sign-in error code (when failed) |
| `ResultStatusDetail` | `Success`, `Redirect`, or one of several failure detail strings |
| `UserAuthenticationMethod` | Authentication method enum — see below |
| `ExtendedProperties[].UserAgent` | Caller user agent |
| `ExtendedProperties[].ResultStatusDetail` | Detailed result code |
| `ExtendedProperties[].UserAgent` | UA string |

`UserAuthenticationMethod` (Microsoft enum):

| Value | Method |
|---|---|
| `1` | Password |
| `2` | Hardware token / OTP |
| `3` | Phone call |
| `4` | SMS |
| `5` | Mobile app notification |
| `6` | Mobile app verification code |
| `7` | FIDO / WebAuthn |
| `8` | Other / federated assertion |

### Directory operations — `RecordType=8` (`AzureActiveDirectory`)

These are the high-signal admin operations. `Operation` names use sentence-case **with trailing period**, exactly as Microsoft emits them — punctuation matters.

| Operation | Meaning | MITRE |
|---|---|---|
| `Add user.` | New user account created | T1136.003 |
| `Delete user.` | User deleted | — |
| `Update user.` | User attribute change (`ModifiedProperties[]` shows what) | T1098 |
| `Reset user password.` | Admin password reset | T1098.001 |
| `Set force change user password.` | Admin forced password change at next sign-in | T1098.001 |
| `Add member to role.` | Privileged role assignment | T1098.003 / T1078.004 |
| `Remove member from role.` | Role removal | — |
| `Add eligible member to role in PIM completed (permanent).` | PIM eligible assignment | T1098.003 |
| `Add eligible member to role in PIM completed (timebound).` | Time-bound PIM eligible assignment | T1098.003 |
| `Activate role in PIM.` / `Activate role assignment in PIM.` | PIM activation — the JIT use of an eligible role | T1078.004 |
| `Add application.` | New app registration | T1098.001 / T1078.004 |
| `Update application.` | App registration modified — watch for redirect URI / certificate / secret changes | T1098 / T1556.007 |
| `Update application – Certificates and secrets management.` | Client secret added (the high-signal credential persistence path) | T1098.001 |
| `Add service principal.` | New SP — first-party or third-party | T1078.004 |
| `Add service principal credentials.` | Credential added to SP | T1098.001 |
| `Consent to application.` | User or admin granted OAuth consent | T1528 |
| `Add app role assignment to service principal.` | App granted a role on a resource | T1098.003 |
| `Add OAuth2PermissionGrant.` | Delegated permission granted | T1528 |
| `Add member to group.` | Group membership add — watch for privileged groups | T1098.003 |
| `Update policy.` | Conditional access / authentication / token-issuance policy modified | T1556 / T1562 |
| `Disable policy.` | CA policy disabled | T1562.007 / T1556 |
| `Update conditional access policy.` | Same — sometimes seen with this exact wording | T1556 |
| `Disable account.` / `Enable account.` | Account state change | T1531 / T1098 |
| `Add device.` / `Update device.` / `Delete device.` | Device registration changes | T1098.005 |
| `Add domain to company.` / `Verify domain.` | Domain federation — high-signal for tenant takeover | T1484.002 |
| `Set federation settings on domain.` | Federation realm change | T1484.002 |
| `Set company information.` | Tenant-wide branding / contact change | — |

### Conditional access fields

Conditional access status lives in `ExtendedProperties[]` under `ConditionalAccessStatus`:

| Value | Meaning |
|---|---|
| `0` | Success — CA evaluated and granted |
| `1` | Failure — CA blocked sign-in |
| `2` | NotApplied — no CA policy targeted this sign-in |
| `3` | Disabled — policy in report-only or disabled state |

For richer CA telemetry — including which policy fired and what controls were required — use `azure:monitor:aad` sign-in logs, which surface `conditionalAccessStatus`, `appliedConditionalAccessPolicies[]`, and `authenticationDetails[]` directly.

### Detection-relevant patterns

**Add member to a privileged Entra ID role:**

```spl
sourcetype=o365:management:activity Workload=AzureActiveDirectory
    Operation="Add member to role."
| spath input=_raw "ModifiedProperties{}.Name" output=mp_names
| spath input=_raw "ModifiedProperties{}.NewValue" output=mp_values
| eval role_idx = mvfind(mp_names, "Role.DisplayName")
| eval RoleName = mvindex(mp_values, role_idx)
| where RoleName IN ("\"Global Administrator\"", "\"Privileged Role Administrator\"",
                     "\"Application Administrator\"", "\"Cloud Application Administrator\"",
                     "\"Exchange Administrator\"", "\"SharePoint Administrator\"",
                     "\"User Access Administrator\"", "\"Security Administrator\"")
| table _time, UserId, ObjectId, RoleName, ClientIP
```

**OAuth consent to high-privilege scope:**

```spl
sourcetype=o365:management:activity Workload=AzureActiveDirectory
    Operation IN ("Consent to application.", "Add OAuth2PermissionGrant.",
                  "Add app role assignment to service principal.")
| spath input=_raw "ModifiedProperties{}.NewValue" output=new_values
| eval consent_text = mvjoin(new_values, " | ")
| where match(consent_text, "(?i)(Mail\.ReadWrite|Mail\.Send|Files\.ReadWrite\.All|Sites\.FullControl\.All|Directory\.ReadWrite\.All|Application\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory)")
| table _time, UserId, ObjectId, consent_text, ClientIP
```

**Conditional access policy disabled or weakened:**

```spl
sourcetype=o365:management:activity Workload=AzureActiveDirectory
    Operation IN ("Disable policy.", "Update policy.", "Update conditional access policy.")
    ObjectId="*ConditionalAccess*"
| stats values(UserId) as actor values(ObjectId) as policy values(ResultStatus) as status
        by Id _time
```

---

## Exchange Online — `Workload=Exchange`

RecordTypes: `ExchangeAdmin (1)` for cmdlet-driven admin, `ExchangeItem (2)` for mailbox item operations, `ExchangeItemGroup (3)` for bulk item events, `ExchangeAggregatedOperation (22)` for the aggregated form of `MailItemsAccessed`.

> **Licensing watch-out:** `MailItemsAccessed`, `Send`, and `SearchQueryInitiatedExchange` are **Audit (Premium)** events. They require Microsoft 365 E5, Microsoft 365 E5 Compliance, or the standalone Audit Premium add-on. E3-only tenants will not see these — `MailItemsAccessed`-based BEC investigations are **impossible** without the right SKU. This is the single most common gap when investigating M365 mailbox compromise.

### Mailbox audit — `RecordType=2` (`ExchangeItem`)

Top-level fields:

| Field | Meaning |
|---|---|
| `MailboxOwnerUPN` | UPN of the mailbox owner |
| `MailboxOwnerSid` | Owner SID |
| `MailboxGuid` | Mailbox GUID — stable across UPN changes |
| `LogonType` | `Owner`/`Delegate`/`Admin` — who accessed the mailbox |
| `LogonUserSid` | SID of the actually-logged-on user (may differ from owner for delegate access) |
| `ClientInfoString` | The MAPI client string (Outlook version, OWA, REST app name) |
| `ClientIPAddress` | True client IP for mailbox access — **prefer over envelope `ClientIP`** |
| `ClientProcessName` | Process name (e.g. `OUTLOOK.EXE`) for desktop clients |
| `Item.Id` / `Item.ParentFolder.Path` | Specific item/folder accessed |
| `Folder.Path` | Folder containing the item |
| `OperationCount` | For aggregated events, number of operations represented |

`LogonType` enum:

| Value | Name | Meaning |
|---|---|---|
| `0` | Owner | Mailbox owner accessed their own mailbox |
| `1` | Admin | Admin accessed someone's mailbox |
| `2` | Delegate | Delegate (with explicit permission) accessed mailbox |

Key Operations:

| Operation | Meaning | Detection use |
|---|---|---|
| `MailItemsAccessed` | Mail item read or sync (Audit Premium only) | **Post-compromise BEC investigation** — bulk read by attacker after takeover |
| `Send` | Outbound mail sent (Audit Premium only) | BEC outbound; lateral phishing |
| `SendAs` | Mail sent as another mailbox (delegated) | Delegate abuse |
| `SendOnBehalf` | Mail sent on behalf of another mailbox | Delegate abuse |
| `Create` | Item created in mailbox | Draft creation, calendar item planting |
| `Update` | Mail item modified | Stealth modification |
| `Move` / `MoveToDeletedItems` / `SoftDelete` / `HardDelete` | Item movement / deletion | Anti-forensics — attacker hiding evidence after BEC |
| `FolderBind` | Folder opened | Mailbox enumeration |
| `Copy` | Item copied | Data staging |
| `MailboxLogin` | Mailbox session start | Session-level audit |
| `SearchQueryInitiatedExchange` | User-initiated search (Audit Premium) | Insider data search |

### Exchange admin cmdlets — `RecordType=1` (`ExchangeAdmin`)

The `Parameters[]` array carries the cmdlet's named parameters. Several specific cmdlets are high-signal.

| Operation (cmdlet) | Detection use | MITRE |
|---|---|---|
| `New-InboxRule` / `Set-InboxRule` | **BEC headline indicator.** Attackers create rules to forward, delete, or hide reply chains | T1564.008 / T1114.003 |
| `Enable-InboxRule` / `Disable-InboxRule` | Same — toggling existing rules | T1564.008 |
| `Set-Mailbox` (with `ForwardingSmtpAddress` or `ForwardingAddress`) | Mailbox-level forwarding. Persistent even if user changes password | T1114.003 |
| `Set-Mailbox` (with `DeliverToMailboxAndForward`) | Forwarding flag — pair with the address parameter | T1114.003 |
| `Add-MailboxPermission` | Granting mailbox access to another principal | T1098.002 |
| `Add-RecipientPermission` (with `SendAs`) | Granting SendAs rights | T1098.002 |
| `New-TransportRule` / `Set-TransportRule` | Tenant-wide mail-flow rule — can intercept, copy, or redirect | T1114 / T1556.006 |
| `Set-OrganizationConfig` (with `OAuth2ClientProfileEnabled`) | Tenant-level setting changes | T1556 |
| `Set-AdminAuditLogConfig` (with `UnifiedAuditLogIngestionEnabled=$false`) | Audit disablement — high-priority | T1562.008 |
| `Set-MailboxAuditBypassAssociation` | Bypass mailbox audit for a principal | T1562.008 |
| `New-ManagementRoleAssignment` | RBAC role grant — Exchange admin escalation | T1098.003 |
| `Disable-Mailbox` / `Remove-Mailbox` | Mailbox removal — destructive | T1485 / T1531 |
| `New-App` / `Enable-App` (Exchange Add-In) | Add-in install — OAuth-style mailbox persistence | T1176 |
| `Set-CASMailbox` (with `OWAMailboxPolicy` or protocol toggles) | Protocol enablement (POP, IMAP, EWS) — legacy auth re-enablement | T1556.007 |

### Detection-relevant patterns

**Suspicious inbox rule creation (BEC):**

```spl
sourcetype=o365:management:activity Workload=Exchange
    Operation IN ("New-InboxRule", "Set-InboxRule")
| spath input=_raw "Parameters{}.Name" output=p_names
| spath input=_raw "Parameters{}.Value" output=p_values
| eval idx_fwd = mvfind(p_names, "(?i)^ForwardTo$")
| eval idx_rdr = mvfind(p_names, "(?i)^RedirectTo$")
| eval idx_del = mvfind(p_names, "(?i)^DeleteMessage$")
| eval idx_mov = mvfind(p_names, "(?i)^MoveToFolder$")
| eval idx_sub = mvfind(p_names, "(?i)^SubjectContainsWords$")
| eval ForwardTo = mvindex(p_values, idx_fwd)
| eval RedirectTo = mvindex(p_values, idx_rdr)
| eval DeleteMessage = mvindex(p_values, idx_del)
| eval MoveToFolder = mvindex(p_values, idx_mov)
| eval SubjectFilter = mvindex(p_values, idx_sub)
| where isnotnull(ForwardTo) OR isnotnull(RedirectTo) OR DeleteMessage="True"
        OR MoveToFolder IN ("RSS Subscriptions","RSS Feeds","Conversation History","Notes","Junk Email")
| table _time, UserId, MailboxOwnerUPN, ForwardTo, RedirectTo, DeleteMessage, MoveToFolder, SubjectFilter, ClientIPAddress
```

> **FP context:** Legitimate users do create forwarding rules, particularly to personal addresses for mobile access. The high-signal patterns are: rules that **delete** matched mail, rules that move mail to obscure folders (RSS Subscriptions is the classic), rules whose subject filter includes finance/wire/invoice keywords, and rules created shortly after a sign-in from a new IP.

**Mailbox-level forwarding to external address:**

```spl
sourcetype=o365:management:activity Workload=Exchange Operation="Set-Mailbox"
| spath input=_raw "Parameters{}.Name" output=p_names
| spath input=_raw "Parameters{}.Value" output=p_values
| eval idx = mvfind(p_names, "(?i)^ForwardingSmtpAddress$")
| eval ForwardingSmtpAddress = mvindex(p_values, idx)
| where isnotnull(ForwardingSmtpAddress) AND ForwardingSmtpAddress != ""
| eval external = if(match(ForwardingSmtpAddress, "(?i)@(contoso\.com|fabrikam\.com)$"), "internal", "external")
| where external = "external"
| table _time, UserId, ObjectId, ForwardingSmtpAddress, ClientIP
```

Replace the internal-domain regex with the tenant's own primary SMTP suffix at deployment time. (This file is environment-agnostic; the deploying team scopes it.)

**Mass mailbox access (post-compromise discovery):**

```spl
sourcetype=o365:management:activity Workload=Exchange Operation=MailItemsAccessed
    LogonType=0
| stats sum(OperationCount) as items
        dc(ClientIPAddress) as src_ips
        values(ClientInfoString) as clients
        by MailboxOwnerUPN, bin(_time, 1h)
| where items > 500
```

**Audit disablement:**

```spl
sourcetype=o365:management:activity Workload=Exchange
    Operation IN ("Set-AdminAuditLogConfig", "Set-MailboxAuditBypassAssociation", "Set-Mailbox")
| spath input=_raw "Parameters{}.Name" output=p_names
| spath input=_raw "Parameters{}.Value" output=p_values
| eval pair = mvzip(p_names, p_values, "=")
| mvexpand pair
| where match(pair, "(?i)(UnifiedAuditLogIngestionEnabled=False|AuditEnabled=False|AuditBypassEnabled=True)")
| table _time, UserId, ObjectId, Operation, pair
```

---

## SharePoint Online and OneDrive — `Workload=SharePoint` / `OneDrive`

RecordTypes: `SharePoint (4)` for site / list / permission events, `SharePointFileOperation (6)` for file-level activity, `SharePointSharingOperation (14)` for external-sharing operations.

> **OneDrive shares the schema.** `Workload=OneDrive` uses the same RecordTypes and Operations as `Workload=SharePoint` — only the site URL pattern differs (`-my.sharepoint.com` for OneDrive personal sites). Detections targeting both can use `Workload IN ("SharePoint","OneDrive")`. SharePoint terminology applies to OneDrive throughout.

### File operations — `RecordType=6` (`SharePointFileOperation`)

| Field | Meaning |
|---|---|
| `Site` / `SiteUrl` | Site collection URL |
| `SourceFileName` / `ObjectId` | File path/URL |
| `SourceFileExtension` | File type |
| `SourceRelativeUrl` | Path within the site |
| `EventSource` | `SharePoint` or `ObjectModel` |
| `ItemType` | `File`, `Folder`, `Web`, `List`, `ListItem` |
| `UserAgent` | Client UA string |
| `MachineDomainInfo` / `MachineId` | Sync client device identifiers |
| `ClientIP` | Caller IP |

Key Operations:

| Operation | Meaning | Detection use |
|---|---|---|
| `FileAccessed` | File opened (browser preview, Office viewer) | High volume — baseline expected |
| `FileDownloaded` | File downloaded to client | **Exfiltration headline event** |
| `FileUploaded` | File added to site | Data staging, malware delivery |
| `FileModified` | File contents changed | Stealth tampering |
| `FileDeleted` / `FileRecycled` | File deletion | Anti-forensics, ransomware impact |
| `FilePreviewed` | Preview pane render | Lower-fidelity than `FileAccessed` |
| `FileSyncDownloadedFull` | OneDrive sync client downloaded full file | Sync-based exfiltration via personal endpoint |
| `FileSyncUploadedFull` | OneDrive sync client uploaded a file | Stage-then-sync pattern |
| `FileCopied` | File copied within tenant | |
| `FileMoved` | File moved | |
| `FileRestored` | Restored from recycle bin | Reversal of attacker delete |
| `FileMalwareDetected` | Defender flagged the file | High-priority |

### Sharing operations — `RecordType=14` (`SharePointSharingOperation`)

The high-signal events for accidental and malicious data exposure.

| Operation | Meaning | Detection use |
|---|---|---|
| `SharingSet` | Item-level sharing configured | Internal sharing |
| `SharingRevoked` | Sharing removed | |
| `SharingPolicyChanged` | Tenant sharing policy modified | T1562 |
| `AnonymousLinkCreated` | "Anyone with the link" link generated | **External exposure headline event** |
| `AnonymousLinkUpdated` / `AnonymousLinkRemoved` | Anon link lifecycle | |
| `AnonymousLinkUsed` | Anon link consumed by a recipient | Exfiltration confirmation |
| `SecureLinkCreated` | Restricted-access link generated | |
| `SecureLinkUpdated` / `SecureLinkRemoved` | Secure link lifecycle | |
| `AddedToSecureLink` | Recipient added to existing secure link — including external recipients | T1567.002 / T1052 (cloud) |
| `SharingInvitationCreated` | Sharing invite issued to specific principal | |
| `SharingInvitationAccepted` | Recipient accepted (`TargetUserOrGroupName` populated) | |
| `SharingInvitationBlocked` / `SharingInvitationExpired` / `SharingInvitationRevoked` | Lifecycle | |
| `CompanyLinkCreated` / `CompanyLinkUsed` | "People in your organization" link | Internal-only — lower priority |

`SharingSet`-family events carry additional fields:

- `TargetUserOrGroupName` — recipient (UPN, group, or `"AnonymousUser"` literal for anonymous links)
- `TargetUserOrGroupType` — `Member`, `Guest`, `SharePointGroup`, `SecurityGroup`, `Partner`
- `EventData` — XML-encoded sharing detail (permissions granted, link type)

### Site / list operations — `RecordType=4` (`SharePoint`)

| Operation | Meaning |
|---|---|
| `SiteCollectionCreated` / `SiteCollectionDeleted` | Site lifecycle |
| `SitePermissionsModified` | Permission set changed |
| `SiteAdminChangeRequest` | Site collection admin change |
| `PermissionLevelAdded` / `PermissionLevelRemoved` | Permission level definition change |
| `GroupAdded` / `GroupRemoved` | SharePoint group lifecycle |
| `AddedUserToGroup` / `RemovedUserFromGroup` | Group membership changes |
| `ListAccessed` / `ListItemAccessed` | Granular access — high volume |

### Detection-relevant patterns

**Anonymous sharing link creation:**

```spl
sourcetype=o365:management:activity Workload IN (SharePoint, OneDrive)
    Operation=AnonymousLinkCreated
| stats count values(ObjectId) as files dc(ObjectId) as file_count
        by UserId, bin(_time, 1h)
| where file_count > 5
```

**External user added to a secure link:**

```spl
sourcetype=o365:management:activity Workload IN (SharePoint, OneDrive)
    Operation=AddedToSecureLink
| where TargetUserOrGroupType IN ("Guest","Partner")
        OR (NOT match(TargetUserOrGroupName, "(?i)@(contoso\.com|fabrikam\.com)$"))
| table _time, UserId, ObjectId, TargetUserOrGroupName, TargetUserOrGroupType, ClientIP
```

**Bulk download / sync exfiltration:**

```spl
sourcetype=o365:management:activity Workload IN (SharePoint, OneDrive)
    Operation IN (FileDownloaded, FileSyncDownloadedFull)
| stats count dc(ObjectId) as unique_files
        sum(eval(coalesce('SourceFileSize',0))) as bytes_total
        values(SourceFileExtension) as extensions
        by UserId, bin(_time, 1h)
| where unique_files > 50
```

**Sharing policy weakened:**

```spl
sourcetype=o365:management:activity Workload IN (SharePoint, OneDrive)
    Operation=SharingPolicyChanged
| spath input=_raw "ModifiedProperties{}.Name" output=mp_names
| spath input=_raw "ModifiedProperties{}.OldValue" output=old_values
| spath input=_raw "ModifiedProperties{}.NewValue" output=new_values
| eval changes = mvzip(mvzip(mp_names, old_values, " "), new_values, " -> ")
| mvexpand changes
| table _time, UserId, ObjectId, changes
```

---

## Microsoft Teams — `Workload=MicrosoftTeams`

RecordTypes: `MicrosoftTeams (30)`, `MicrosoftTeamsAdmin (78)`, `MicrosoftTeamsShifts (109)`. Tenant audit for Teams must be enabled — older tenants have it off by default and the events simply don't appear.

| Operation | Meaning | Detection use |
|---|---|---|
| `TeamCreated` / `TeamDeleted` | Team lifecycle | |
| `MemberAdded` / `MemberRemoved` | Membership change | T1098 / T1078 (especially with `MemberType=Guest`) |
| `MemberRoleChanged` | Owner ↔ member promotion/demotion | T1098 |
| `ChannelAdded` / `ChannelDeleted` | Channel lifecycle | |
| `ChannelSettingChanged` | Channel-level setting changes | |
| `BotAddedToTeam` | Bot installed | T1176 (browser/cloud add-in equivalent) |
| `AppInstalled` / `AppRemoved` | Teams app installed in scope | T1176 |
| `MessageEditedHasLink` / `MessageDeleted` | Message lifecycle — content tampering | T1070 |
| `MessageHostedContentsListed` | Bulk read of message attachments | T1213 |
| `MeetingDetail` / `MeetingParticipantDetail` | Meeting events | |
| `TeamSettingChanged` | Team configuration change |  |
| `FedTenantChanged` / `TenantFederationChanged` | External federation change | T1199 / T1078.004 |
| `EnabledExternalAccessToTenant` | External federation toggled | T1199 |

Top-level Teams fields:

| Field | Meaning |
|---|---|
| `TeamName` | Display name of the Team |
| `TeamGuid` | Stable GUID |
| `ChannelName` | Channel involved |
| `Members[]` | Array of `{UPN, Role, MemberType}` for membership-change events |
| `MemberType` | `Member`, `Guest`, `Bot`, `Federated` |
| `AddOnName` / `AddOnType` | App / bot identifier for `AppInstalled` / `BotAddedToTeam` |
| `CommunicationType` | For meeting events |
| `MessageId` | For message events |
| `MessageURLs[]` | URLs in messages — phishing pivot |

### Detection-relevant patterns

**Guest user added to a Team:**

```spl
sourcetype=o365:management:activity Workload=MicrosoftTeams Operation=MemberAdded
| spath input=_raw "Members{}.UPN" output=member_upns
| spath input=_raw "Members{}.MemberType" output=member_types
| eval pair = mvzip(member_upns, member_types, "|")
| mvexpand pair
| rex field=pair "^(?<member_upn>[^|]+)\|(?<member_type>.+)$"
| where member_type IN ("Guest","Federated")
| table _time, UserId, TeamName, ChannelName, member_upn, member_type
```

**Bot or external app installed:**

```spl
sourcetype=o365:management:activity Workload=MicrosoftTeams
    Operation IN (AppInstalled, BotAddedToTeam)
| stats count by UserId, TeamName, AddOnName, AddOnType, _time
```

**External federation enabled:**

```spl
sourcetype=o365:management:activity Workload=MicrosoftTeams
    Operation IN (FedTenantChanged, TenantFederationChanged, EnabledExternalAccessToTenant)
| table _time, UserId, ObjectId, ModifiedProperties{}.Name, ModifiedProperties{}.NewValue
```

---

## Security & Compliance Center — `Workload=SecurityComplianceCenter`

RecordTypes: `SecurityComplianceCenterEOPCmdlet (18)` (and `44` in some tenants), `SecurityComplianceAlerts (40)`, `AeD (54)` for Advanced eDiscovery. Operations are PowerShell cmdlet names — same `Parameters[]` shape as Exchange admin.

| Operation (cmdlet) | Meaning | Detection use |
|---|---|---|
| `New-ComplianceSearch` / `Start-ComplianceSearch` | eDiscovery search created/started | T1213 (insider data search) |
| `New-ComplianceSearchAction` (with `Export`) | Export action — pulls matched mail/files | T1530 / T1567 |
| `New-ComplianceCase` | New eDiscovery case | |
| `Add-eDiscoveryCaseAdmin` | Adds case admin | T1098.003 |
| `Set-DlpComplianceRule` / `Remove-DlpComplianceRule` | DLP rule lifecycle | T1562 |
| `Disable-DlpComplianceRule` | DLP rule disabled | T1562.008 |
| `New-RetentionCompliancePolicy` / `Remove-RetentionCompliancePolicy` | Retention policy lifecycle | T1485 (when destructive) |
| `Set-LabelPolicy` | Sensitivity label policy change | |
| `Set-AuditConfig` | Tenant-wide audit setting change | T1562.008 |
| `New-RoleGroupMember` / `Add-RoleGroupMember` | Adds member to compliance role group (e.g. `eDiscovery Manager`) | T1098.003 |
| `Search-UnifiedAuditLog` (rare in API; mostly via portal) | Audit search | |

> **Detection caveat:** eDiscovery and audit search are themselves auditable. A defender running a search creates events; an insider abusing eDiscovery to exfiltrate also creates events. The discriminator is the **role of the actor** (`UserId`) — eDiscovery activity by accounts not in the `eDiscovery Manager` / `eDiscovery Administrator` role groups is suspicious.

### Detection-relevant patterns

**eDiscovery search created by non-admin:**

```spl
sourcetype=o365:management:activity Workload=SecurityComplianceCenter
    Operation IN ("New-ComplianceSearch", "Start-ComplianceSearch", "New-ComplianceSearchAction")
| lookup ediscovery_admins.csv UserId OUTPUT is_ediscovery_admin
| where isnull(is_ediscovery_admin) OR is_ediscovery_admin != "true"
| table _time, UserId, Operation, ObjectId, ClientIP
```

**DLP policy disabled:**

```spl
sourcetype=o365:management:activity Workload=SecurityComplianceCenter
    Operation IN ("Disable-DlpComplianceRule", "Remove-DlpComplianceRule",
                  "Set-DlpComplianceRule", "Disable-DlpCompliancePolicy")
| spath input=_raw "Parameters{}.Name" output=p_names
| spath input=_raw "Parameters{}.Value" output=p_values
| eval pair = mvzip(p_names, p_values, "=")
| where match(mvjoin(pair," "), "(?i)Mode=(Audit|Disable|Off)")
| table _time, UserId, Operation, ObjectId, pair
```

---

## DLP — `Workload=DataLossPreventionEndpoint` / `DataLossPreventionExchange` / `DataLossPreventionSharePoint`

RecordTypes: `63` (Endpoint), `99` (Exchange), and per-surface SharePoint/OneDrive variants. These events represent **rule matches** — a piece of content that triggered a DLP policy.

Common fields:

| Field | Meaning |
|---|---|
| `PolicyDetails[]` | The matching policies, each with rule name, action, severity |
| `SensitiveInfoDetectionIsIncluded` | Whether sensitive-info-type detection contributed |
| `ExceptionInfo` | Whether the user provided business justification (override) |
| `OverrideTime` / `OverrideJustification` | User override metadata |
| `RuleMode` | `Enable`, `TestWithNotifications`, `TestWithoutNotifications` — the policy's mode |
| `RuleSeverity` | `Low`, `Medium`, `High`, `Informational` |

For Exchange DLP, the event also references the message — `Subject`, `From`, `To{}`, `MessageId`. For SharePoint DLP, the file URL via `ObjectId`. For Endpoint DLP, the device and user context.

### Detection-relevant patterns

**DLP override / business justification:**

```spl
sourcetype=o365:management:activity
    (Workload="DataLossPreventionEndpoint" OR Workload="DataLossPreventionExchange"
     OR Workload="DataLossPreventionSharePoint")
| where isnotnull(OverrideJustification) OR ExceptionInfo!=""
| stats count values(OverrideJustification) as justifications values(ObjectId) as objects
        by UserId, RuleSeverity
| where count > 5 OR RuleSeverity="High"
```

---

## Power Automate / Power Apps — `Workload=MicrosoftFlow` / `PowerApps`

RecordType `MicrosoftFlow (52)`. Power Automate is an increasingly common persistence vector — flows can run as a service principal, with delegated mailbox / SharePoint permissions, on schedule or event triggers.

| Operation | Meaning |
|---|---|
| `CreateFlow` | New flow created |
| `EditFlow` | Flow definition modified |
| `DeleteFlow` | Flow removed |
| `EnableFlow` / `DisableFlow` | Flow state change |
| `RunFlow` / `MachineRunFlow` | Flow execution (volume — usually filtered) |
| `CreateConnection` | New connector authorised — same OAuth-consent risk profile as `Consent to application.` |
| `DeleteConnection` | Connector removed |
| `ShareFlow` | Flow shared with another principal |

### Detection-relevant patterns

**Flow creation with high-privilege connector:**

```spl
sourcetype=o365:management:activity Workload=MicrosoftFlow
    Operation IN (CreateFlow, EditFlow)
| spath input=_raw "ExtendedProperties{}.Value" output=ext_values
| eval flow_def = mvjoin(ext_values, " ")
| where match(flow_def, "(?i)(office365|sharepoint|onedrive|exchange|teams|azuread)")
        AND match(flow_def, "(?i)(send|forward|export|copy|share|create_item|update_item)")
| table _time, UserId, ObjectId, flow_def
```

---

## Microsoft Stream — `Workload=MicrosoftStream`

RecordType `55`. Lower-volume than the headline workloads but useful for sensitive-meeting recording exposure.

| Operation | Meaning |
|---|---|
| `StreamInvokeUpload` | Video uploaded |
| `StreamInvokeDelete` | Video deleted |
| `StreamInvokeChangeVideoPermissions` | Permission change |
| `StreamInvokeShareVideo` | Video shared |
| `StreamInvokeViewVideo` | Video played (high volume) |
| `StreamInvokeDownloadVideo` | Video downloaded |
| `StreamInvokeChannelCreated` / `StreamInvokeChannelDeleted` | Channel lifecycle |

Stream-on-SharePoint (the current Stream architecture) emits SharePoint events for the underlying media files — `Workload=SharePoint` with `SourceFileExtension="mp4"`/`"webm"` is often a more reliable signal than the legacy Stream events.

---

## Yammer / Viva Engage — `Workload=Yammer`

RecordType `Yammer (25)`. Legacy events; Microsoft has rebranded Yammer as Viva Engage but the audit RecordType name remains `Yammer`. Tenants that have migrated to Viva Engage Communities still emit these.

| Operation | Meaning |
|---|---|
| `MessageCreated` / `MessageDeleted` | Yammer post lifecycle |
| `FileCreated` / `FileShared` / `FileUpdateDescription` | File operations |
| `NetworkExternalConfigUpdated` | External network policy change |
| `SoftDeleteGroup` / `HardDeleteGroup` | Group / community deletion |
| `SuspendedUser` / `ActivatedUser` | User lifecycle within Yammer |

Lower priority for security detection unless the tenant uses Yammer / Viva Engage as a first-class collaboration surface.

---

## Detection-relevant patterns — consolidated

A high-value detection content set across Management Activity API workloads. Each maps to a specific RecordType / Operation combination and a MITRE technique.

### Suspicious mailbox rule creation (BEC indicator)

- **Workload:** `Exchange`
- **Operation:** `New-InboxRule`, `Set-InboxRule`
- **Key fields:** `Parameters[].ForwardTo`, `Parameters[].RedirectTo`, `Parameters[].DeleteMessage`, `Parameters[].MoveToFolder`, `Parameters[].SubjectContainsWords`
- **MITRE:** T1564.008 (Hide Artifacts: Email Hiding Rules), T1114.003 (Email Forwarding Rule)
- **FP context:** Legitimate forwarding to mobile / personal addresses; Outlook-managed rules created during inbox cleanup
- See SPL above.

### Mass mailbox access (post-compromise discovery)

- **Workload:** `Exchange`
- **Operation:** `MailItemsAccessed`
- **Key fields:** `MailboxOwnerUPN`, `OperationCount`, `ClientIPAddress`, `ClientInfoString`, `LogonType`
- **MITRE:** T1114.002 (Email Collection: Remote Email Collection), T1213
- **Licensing:** Audit Premium required
- **FP context:** Migration tools (e.g. third-party archivers), Outlook bulk sync after long offline period

### Anonymous sharing link creation

- **Workload:** `SharePoint`, `OneDrive`
- **Operation:** `AnonymousLinkCreated`
- **Key fields:** `ObjectId`, `SourceFileExtension`, `EventData`
- **MITRE:** T1567.002 (Exfiltration to Cloud Storage)
- **FP context:** Marketing/comms teams legitimately creating public-share links — allowlist by user/group

### External user added to Team

- **Workload:** `MicrosoftTeams`
- **Operation:** `MemberAdded`
- **Key fields:** `Members[].UPN`, `Members[].MemberType`, `TeamName`
- **MITRE:** T1078.004 (Cloud Accounts), T1199 (Trusted Relationship)
- **FP context:** Active partner-engagement projects; legitimate guest collaboration

### Admin consent grant for application

- **Workload:** `AzureActiveDirectory`
- **Operation:** `Consent to application.`, `Add OAuth2PermissionGrant.`, `Add app role assignment to service principal.`
- **Key fields:** `ModifiedProperties[].NewValue` (contains scopes), `ObjectId` (target SP), `Target[].ID`
- **MITRE:** T1528 (Steal Application Access Token), T1098.001 (Additional Cloud Credentials)
- **FP context:** Legitimate first-time enterprise app rollouts — correlate with change management

### Conditional access policy disabled

- **Workload:** `AzureActiveDirectory`
- **Operation:** `Update policy.`, `Disable policy.`, `Update conditional access policy.`
- **Key fields:** `ObjectId`, `ModifiedProperties[]`
- **MITRE:** T1556 (Modify Authentication Process), T1562.007 (Disable or Modify Cloud Firewall — analogue)
- **FP context:** Genuine policy lifecycle, especially during MFA rollout phases

### Mailbox forwarding to external address

- **Workload:** `Exchange`
- **Operation:** `Set-Mailbox` with `ForwardingSmtpAddress` parameter
- **Key fields:** `Parameters[].ForwardingSmtpAddress`, `Parameters[].DeliverToMailboxAndForward`
- **MITRE:** T1114.003 (Email Forwarding Rule — mailbox-level variant)
- **FP context:** Vacation auto-forward to colleague; minimal legitimate external-domain use

### eDiscovery search by non-admin

- **Workload:** `SecurityComplianceCenter`
- **Operation:** `New-ComplianceSearch`, `Start-ComplianceSearch`, `New-ComplianceSearchAction`
- **Key fields:** `Parameters[].ContentMatchQuery`, `ObjectId`, `UserId`
- **MITRE:** T1213 (Data from Information Repositories)
- **FP context:** Newly delegated compliance staff; legitimate HR investigations

### Persistence via Power Automate

- **Workload:** `MicrosoftFlow`
- **Operation:** `CreateFlow`, `CreateConnection`, `EditFlow`
- **Key fields:** `ObjectId`, `ExtendedProperties[].FlowDefinition` (when populated)
- **MITRE:** T1546 (Event Triggered Execution — cloud analogue), T1098 (when persistence)
- **FP context:** Citizen-developer workloads in tenants where Power Platform is encouraged

### Audit disablement

- **Workload:** `Exchange` or `SecurityComplianceCenter`
- **Operation:** `Set-AdminAuditLogConfig`, `Set-MailboxAuditBypassAssociation`, `Set-AuditConfig`, `Disable-DlpComplianceRule`
- **Key fields:** `Parameters[]` (look for `UnifiedAuditLogIngestionEnabled=False`, `AuditBypassEnabled=True`)
- **MITRE:** T1562.008 (Disable or Modify Cloud Logs)
- **FP context:** None benign — this should always alert. Genuine admin testing should be coordinated and tagged.

### RBA emission

> See `splunk-detection-patterns.md` for the full RBA schema. M365 detections use the same `risk_object` / `threat_object` / `annotations.mitre_attack.*` conventions.

For M365 detections, `risk_object` is typically the user (`risk_object_type="user"`) — the subject of the malicious activity. `threat_object` may be the target file / mailbox / SP / app being acted on (`threat_object_type` in `email_address`, `url`, `other`). When the actor is itself an external party (e.g. anonymous link consumer), emit two risk events — one for the originating user (lower score, `risk_object_type=user`) and one for the file (`risk_object_type=other`).

```spl
` Detection: Mailbox forwarding to external address (T1114.003) `
sourcetype=o365:management:activity Workload=Exchange Operation="Set-Mailbox"
| spath input=_raw "Parameters{}.Name" output=p_names
| spath input=_raw "Parameters{}.Value" output=p_values
| eval idx = mvfind(p_names, "(?i)^ForwardingSmtpAddress$")
| eval ForwardingSmtpAddress = mvindex(p_values, idx)
| where isnotnull(ForwardingSmtpAddress) AND ForwardingSmtpAddress != ""
| eval risk_score = 60
| eval risk_object = lower(coalesce(ObjectId, UserId))
| eval risk_object_type = "user"
| eval threat_object = ForwardingSmtpAddress
| eval threat_object_type = "email_address"
| eval risk_message = "Mailbox forwarding configured on " . ObjectId . " by " . UserId . " to external address " . ForwardingSmtpAddress
| eval annotations.mitre_attack.mitre_tactic = "collection"
| eval annotations.mitre_attack.mitre_technique = "T1114"
| eval annotations.mitre_attack.mitre_subtechnique = "T1114.003"
| table _time, risk_object, risk_object_type, risk_score, risk_message,
        threat_object, threat_object_type,
        annotations.mitre_attack.mitre_tactic,
        annotations.mitre_attack.mitre_technique,
        annotations.mitre_attack.mitre_subtechnique
```

---

## Common gotchas

- **Latency.** Events typically appear 30+ minutes after the underlying activity, sometimes 60–90 minutes for Entra ID and Teams. Detections that depend on near-real-time response (e.g. session termination) cannot rely on this feed alone — use Defender / sign-in risk APIs for that. The Management Activity API is for audit and post-event detection.
- **Duplicates are the default.** The API guarantees at-least-once delivery. The same `Id` will appear in multiple content blobs across retries, especially after add-on upgrades or checkpoint resets. Detections that count occurrences must `dedup Id`. Aggregations should use `dc(Id)` instead of `count`.
- **`ClientIP` is not the user's IP.** The envelope `ClientIP` field is often the front-door / proxy IP — useful for grouping but not for geolocation or threat-intel matching. Workload-specific fields are more accurate:
  - Entra ID: `ActorIpAddress`
  - Exchange mailbox: `ClientIPAddress`
  - SharePoint / OneDrive: `ClientIP` is closer to true client but still subject to load-balancer rewriting in tenant-scoped scenarios
- **`UserId` vs `UserKey`.** `UserId` is the UPN and changes with renames; `UserKey` is the immutable AAD object ID. Use `UserKey` for joins spanning more than 30 days.
- **Unified audit must be enabled tenant-side.** Many tenants discover absence-of-events is a config gap — verify `Get-AdminAuditLogConfig` on the tenant or the Purview audit search portal before debugging the Splunk pipeline.
- **`MailItemsAccessed` and `Send` need Audit Premium.** E5 / E5 Compliance licensed users emit these; E3-only tenants don't. Mailbox compromise investigations on E3 tenants are materially worse off — flag this on initial tenant triage.
- **Some events appear in `o365:management:activity` AND `o365:graph:messagetrace`.** Mail flow events have different fidelity in the two feeds: messagetrace has envelope and delivery, management API has the content-action audit. Don't double-count for volume metrics.
- **SharePoint terminology applies to OneDrive.** OneDrive events carry SharePoint terms — `SiteUrl` is always populated, `ItemType` differs between `File`/`Folder`/`Web`. Don't write OneDrive-specific detections that exclude SharePoint terminology.
- **`ResultStatus` is workload-dependent.** `Succeeded`/`Failed` for Exchange/SCC; `Success`/`Failure` for Entra ID; sometimes blank or numeric for SharePoint/Teams. Cross-workload result filters need workload-specific branches.
- **`ExtendedProperties[]`, `Parameters[]`, `ModifiedProperties[]` are arrays of `{Name, Value}` pairs.** Splunk extracts these as multi-value fields. Use `spath` with `{}` array indexing or `mvfind` / `mvindex` to access specific entries, or `mvexpand` to pivot to one row per entry.
- **`ConditionalAccessStatus` lives in `ExtendedProperties[]`.** Values: `0`=Success, `1`=Failure, `2`=NotApplied, `3`=Disabled. The richer CA detail (which policy, which controls) is in `azure:monitor:aad`, not here.
- **Operation names include trailing periods on Entra ID.** `Add member to role.` (with the period) is the canonical form. Detections searching for `Add member to role` (no period) miss every event. Microsoft is consistent about this within Entra ID; other workloads use cmdlet-style names without trailing punctuation.
- **`RecordType` is numeric in raw events.** The TA usually leaves it numeric. Detections using symbolic names (`AzureActiveDirectoryStsLogon`) need to convert via lookup or use the integer.
- **Add-on v4.1.0 upgrade hazard.** Changed checkpoint logic in `splunk_ta_o365` v4.1.0 can replay up to 7 days of duplicates after upgrade. Coordinate with the platform team during upgrade windows; deduplication on `Id` mitigates.
- **Microsoft adds new Operations and RecordTypes regularly.** The schema is not closed — new workload features ship audit events ad hoc. Treat unknown values as "ingest, then triage" rather than dropping; a periodic review of `stats count by Workload, RecordType, Operation | where count < 100` surfaces new emergence.
- **Schema docs and portal docs sometimes disagree.** The [Office 365 Management Activity API schema](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema) page is the authoritative source for the API shape; the [Audited activities in Purview](https://learn.microsoft.com/purview/audit-log-activities) page is friendlier for Operation-name lookup but is sometimes behind the API. When they conflict, the API schema page wins.

---

## Cross-reference

- `splunk-sourcetype-library.md` — sourcetype shape, CIM mapping, ingest pipeline detail for `o365:management:activity` and siblings
- `windows-event-log-reference.md` — companion reference for on-prem Windows audit
- `splunk-detection-patterns.md` — RBA, MITRE annotation conventions, and the false-positive catalogue (which contains M365-specific FP patterns)

---

## Sources and further reading

All URLs verified at time of writing.

**Schema and API:**
- [Office 365 Management Activity API reference](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-reference) — content blob retrieval, subscription model
- [Office 365 Management Activity API schema](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema) — common envelope and per-workload schemas
- [Get started with Office 365 Management APIs](https://learn.microsoft.com/office/office-365-management-api/get-started-with-office-365-management-apis) — authentication and onboarding

**Operation reference (per-workload friendly form):**
- [Audited activities (Microsoft Purview)](https://learn.microsoft.com/purview/audit-log-activities) — friendly Operation-name lookup
- [Search the audit log](https://learn.microsoft.com/purview/audit-search) — operational search guidance
- [Exchange Online auditing](https://learn.microsoft.com/purview/audit-mailboxes) — mailbox audit semantics, `MailItemsAccessed` detail
- [Entra ID audit log schema](https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs) — the Graph-side equivalent

**Licensing and retention:**
- [Auditing solutions in Microsoft Purview](https://learn.microsoft.com/purview/audit-solutions-overview) — Standard vs Premium, retention tiers
- [Microsoft Purview Audit (Premium)](https://learn.microsoft.com/purview/audit-premium) — `MailItemsAccessed` and other premium events

**Splunk add-on:**
- Splunkbase: [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055)

**Caveats:**
- Microsoft's per-workload Operation lists are version-specific and routinely expanded. The audit log "ships" new Operations whenever a workload feature ships — schema additions are not announced in advance.
- Detection threshold values in SPL examples are illustrative — calibrate to the tenant's baseline. M365 audit volume varies enormously between tenants by user count, SKU mix, and hybrid posture.
- Examples assume `splunk_ta_o365` v3.0+ field extraction. Older add-on versions or the legacy `Splunk_TA_microsoft-cloudservices` `ms:o365:management` sourcetype will require minor field-name adjustments.
