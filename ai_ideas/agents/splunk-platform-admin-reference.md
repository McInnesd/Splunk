# Splunk Platform Admin Reference

> Generic, environment-agnostic reference for troubleshooting, optimising, and maintaining Splunk Enterprise and Splunk Cloud deployments.
> Covers search performance, search head and indexer tier health, data model accelerations, workload management, ingest pipeline diagnostics, knowledge object hygiene, and Monitoring Console interpretation.
>
> Environment-specific values (pool names, indexes, role names, retention policies) live in `splunk-environment-context.md`. Sourcetype shape and CIM mapping live in `splunk-sourcetype-library.md`.

---

## 1. Diagnosing search performance and skipped searches

### Where to look first

| Surface | What it tells you | Path |
|---|---|---|
| Monitoring Console — Search Activity | Real-time search load by search head, user, app | MC > Search > Search Activity |
| Monitoring Console — Scheduler Activity | Scheduled-search throughput, skip ratio, lag | MC > Search > Scheduler Activity: Instance / Deployment |
| Job Inspector | Per-search execution profile, command costs, dispatch overhead | Activity > Jobs > inspect (or `/app/search/job_inspector?sid=<sid>`) |
| Audit log | Per-search lifecycle, who ran what, completion status | `index=_audit action=search` |
| Scheduler log | Skip reasons, concurrency limits hit, dispatch errors | `index=_internal source=*scheduler.log*` |
| Search log | Per-job warnings/errors, command-level diagnostics | `index=_internal source=*search.log* sid=<sid>` |

### Common skip reasons and what they mean

| Reason in `scheduler.log` | Meaning | First fix to try |
|---|---|---|
| `skipped because the maximum number of concurrent historical scheduled searches on this instance has been reached` | Per-instance scheduled-search concurrency cap hit | Raise `max_searches_perc` or stagger schedules |
| `skipped because the maximum number of concurrent historical searches on this instance has been reached` | Total search concurrency cap hit (ad-hoc + scheduled) | Raise `max_concurrent` (or CPU-derived `base_max_searches`) or move heavy users off the SH |
| `The maximum number of concurrent auto-summarization searches on this instance has been reached` | DMA/report acceleration concurrency cap hit | Raise `auto_summary_perc`, stagger DMA cron |
| `skipped because the search head is not ready` | SHC replication/init not complete | Check SHC health before tuning |
| `delegated remote searches are over the limit` | Search-head bundle replication or remote search limit | Check `distributed_search.log`, bundle sync |
| `cannot dispatch search because dispatch directory has too many entries` | Dispatch dir bloat | Clean dispatch dir, raise `max_lock_files` if appropriate |
| `cannot lock the configuration file` | Lock contention on `savedsearches.conf` | Reduce churn, raise `max_lock_files` |
| `the search was skipped because the previous instance is still running` | Long-running search exceeded its schedule interval | Tune the search or extend the schedule |

Splunk reference: [Configure the priority of scheduled reports](https://docs.splunk.com/Documentation/Splunk/latest/Report/Configurethepriorityofscheduledreports), [About jobs and job management](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutjobsandjobmanagement).

### Key tunables — `limits.conf [scheduler]`

| Setting | Default | Meaning | Notes |
|---|---|---|---|
| `max_searches_perc` | `50` | Percent of `base_max_searches` (or derived limit) reserved for scheduled searches | Raise to allow more scheduled concurrency; trade-off is fewer slots for ad-hoc |
| `auto_summary_perc` | `50` | Percent of scheduled-search budget reserved for auto-summarisation (DMA, report acceleration, summary indexing) | Raise if DMAs are starving; lower if scheduled alerts are starving |
| `max_searches_perc.1` / `.2` | unset | Time-windowed overrides for `max_searches_perc` | Use to give nights/weekends more budget |
| `allow_skew` | `0` | Allowed schedule skew window (e.g. `10m` or `100%`) | Spreads aligned cron firings (top-of-hour spikes) |
| `max_lock_files` | `1000` | Cap on dispatch lock files per dispatch dir | Raise if dispatch dir is enormous and lock errors appear |
| `max_per_result_alerts` | `500` | Per-result alerts emitted per scheduled search | Affects alert storm behaviour, not skip rate |
| `dispatch_dir_warning_size` | `5000` | Warning threshold for dispatch dir entry count | Tune monitoring alerting, not behaviour |

### Key tunables — `limits.conf [search]`

| Setting | Default | Meaning |
|---|---|---|
| `base_max_searches` | `6` | Floor for total search concurrency |
| `max_searches_per_cpu` | `1` | Per-CPU concurrency multiplier — total cap = `base_max_searches + (cpu_cores * max_searches_per_cpu)` |
| `max_rt_search_multiplier` | `1` | Real-time-search concurrency multiplier |
| `dispatch_dir_warning_size` | `5000` | Dispatch dir size warning |
| `default_save_ttl` | `600` | Default dispatch directory TTL (seconds) for ad-hoc results |

Increasing concurrency on a CPU-saturated search head fixes nothing — verify CPU/memory headroom in the MC before raising caps.

### Dispatch dir cleanup playbook

Symptoms: scheduler skips with `dispatch directory has too many entries`, slow Splunk web, slow login, high `splunkd` CPU on a search head.

1. Inspect entry count:
   ```
   ls $SPLUNK_HOME/var/run/splunk/dispatch | wc -l
   ```
2. Identify offending owners/apps:
   ```
   ls -la $SPLUNK_HOME/var/run/splunk/dispatch | awk '{print $9}' | cut -d_ -f1 | sort | uniq -c | sort -rn | head
   ```
3. Confirm orphans (dispatch entries with no live search):
   ```
   index=_audit action=search info=completed earliest=-24h | stats count by search_id
   ```
4. Adjust TTL for offending searches in `savedsearches.conf` (`dispatch.ttl`, `dispatch.auto_cancel`).
5. Use `splunk clean dispatch` (cautious — interrupts running searches) or remove specific aged entries via filesystem with Splunk stopped on that SH only.
6. After cleanup, raise `dispatch.ttl` defaults or shorten alert retention windows so it doesn't recur.

### SPL templates for performance triage

#### Skipped searches by app and reason — last 24h
```
index=_internal source=*scheduler.log* (status=skipped OR reason=*)
| stats count by app, savedsearch_name, reason
| sort - count
```

#### Concurrency utilisation by search head — last 24h
```
index=_internal source=*scheduler.log* component=SavedSplunker
    ("concurrency_category" OR "max_searches" OR "concurrency_context")
| timechart span=5m max(concurrency_limit) as limit max(concurrency_used) as used by host
```

#### Long-running ad-hoc searches — last 7 days
```
index=_audit action=search info=completed user!=splunk-system-user
| eval runtime=total_run_time
| stats count avg(runtime) as avg_runtime max(runtime) as max_runtime sum(runtime) as cpu_seconds by user, search
| sort - cpu_seconds
| head 50
```

#### Top searches by CPU seconds — last 24h
```
index=_audit action=search info=completed
| stats sum(total_run_time) as cpu_seconds count by search_id, user, savedsearch_name, app
| sort - cpu_seconds
| head 25
```

#### Selectivity — `event_count` vs `result_count`
```
index=_audit action=search info=completed
    NOT [|search index=_audit action=search info=granted | fields search_id]
| eval selectivity = if(event_count>0, round(result_count*100.0/event_count,2), null())
| stats count avg(selectivity) as avg_selectivity sum(event_count) as scanned sum(result_count) as returned by savedsearch_name
| where scanned > 1000000 AND avg_selectivity < 1
| sort - scanned
```
Low selectivity (<1%) on high-scan searches indicates filtering should move earlier (index/sourcetype/host filters before stats).

#### Searches with most disk reads (IOPS-heavy)
```
index=_internal source=*metrics.log* group=searchscheduler
| stats sum(disk_read_bytes) as bytes by savedsearch_name, app
| eval gb=round(bytes/1024/1024/1024,2)
| sort - gb
```

#### Real-time searches still running
```
| rest /services/search/jobs splunk_server=*
| where isRealTimeSearch="1"
| table sid, author, label, searchEarliestTime, searchLatestTime, runDuration
```

### Quick wins

- Replace `index=*` and `sourcetype=*` with explicit values; both expand bundle replication and scan unnecessary buckets.
- Move filtering before `stats`/`eval` chains; aggregations are expensive over wide rowsets.
- Convert raw-event searches to `tstats` against an accelerated DM where possible.
- Use `summariesonly=true` against accelerated DMs whenever the search window is fully covered by the acceleration.
- Avoid unbounded `earliest=0` / `earliest=-30y` ad-hoc searches; force time bounds via macro defaults.

---

## 2. Data model acceleration troubleshooting

### How acceleration works

Splunk DMA generates per-bucket TSIDX summary files (`<bucket>/datamodel_summary/<dm>/`) on a cron schedule. Each acceleration job runs as a `summarize` search against buckets that are still within the DMA backfill window and have not yet been summarised.

- `summariesonly=true` — `tstats` reads only the summary; events outside the acceleration window are invisible.
- `summariesonly=false` — `tstats` falls back to raw events for buckets without summaries (slower, but complete).
- The acceleration cron (`acceleration.cron_schedule`, default `*/5 * * * *`) controls how often Splunk dispatches new summary jobs; the backfill window (`acceleration.earliest_time`, e.g. `-3mon`) controls how far back to summarise.

Splunk reference: [Accelerate data models](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Acceleratedatamodels).

### Diagnostic SPL

#### Acceleration completion percentage per data model
```
| rest /servicesNS/-/-/admin/summarization splunk_server=*
| search summary.is_inprogress=* eai:acl.app=*
| eval dm = replace(summary.id, "^DM_.+?_", "")
| stats max(summary.complete) as complete_pct
        max(summary.size) as size_bytes
        max(summary.buckets_size) as buckets_size_bytes
        sum(summary.buckets) as buckets
        by dm, eai:acl.app, splunk_server
| eval complete_pct = round(complete_pct*100,2)
| eval size_gb = round(size_bytes/1024/1024/1024,2)
| sort complete_pct
```
DMAs stuck below 100% indicate either a cron scheduling problem, an under-provisioned auto-summary concurrency budget, or buckets being added faster than they can be summarised.

#### Buckets pending summarisation
```
| rest /servicesNS/-/-/admin/summarization splunk_server=*
| eval dm = replace(summary.id, "^DM_.+?_", "")
| stats sum(summary.buckets) as total_buckets sum(summary.buckets_size) as size_bytes max(summary.complete) as pct by dm, splunk_server
| eval pending_estimate = round(total_buckets * (1 - pct), 0)
| where pending_estimate > 0
| sort - pending_estimate
```

#### Acceleration size — estimated vs actual
```
| rest /servicesNS/-/-/admin/summarization
| eval dm = replace(summary.id, "^DM_.+?_", "")
| eval size_gb = round(summary.size/1024/1024/1024, 2)
| eval estimate_gb = round('summary.buckets_size'/1024/1024/1024, 2)
| table dm, size_gb, estimate_gb, summary.complete, summary.last_error
```
Large gap between estimate and actual usually means the constraint search is broader than expected — review the DM root constraint.

#### Lock contention on summary searches
```
index=_internal source=*scheduler.log* component=SavedSplunker
    ("savedsearch_name=_ACCELERATE_DM_*" OR savedsearch_name="*acceleration*")
    (status=skipped OR error=*)
| stats count by savedsearch_name, reason
| sort - count
```

#### Verify DM constraint and tag chain
```
| tstats summariesonly=false count from datamodel=<DataModelName> by index, sourcetype
```
If the count is zero in `summariesonly=false`, the issue is upstream — the events don't match the constraint or aren't tagged correctly. If it returns events but `summariesonly=true` returns none, the acceleration is incomplete or broken for those buckets.

### Don't use `index=*` in DMA root constraints

Root constraints like `(index=* OR index=_*) sourcetype=...` force the acceleration to scan every index on every indexer for every bucket within the backfill window — including indexes that contain none of the relevant data. Always anchor to the smallest set of indexes that legitimately holds the sourcetype.

For CIM-aligned DMs, Splunk provides `cim_<dm>_indexes` macros (e.g. `cim_Authentication_indexes`, `cim_Network_Traffic_indexes`). These are normally defined in `Splunk_SA_CIM/macros.conf` to expand to the indexes in scope. Override them in a local app to add or restrict indexes — never edit the SA app directly.

```
[cim_Authentication_indexes]
definition = (index=wineventlog OR index=linux OR index=o365)
iseval = 0
```

### Backfill vs rebuild

| Action | When to use | How |
|---|---|---|
| Wait | Acceleration is below 100% but progressing | Watch buckets-pending count fall over time |
| Rebuild | Constraint or tag chain changed; existing summaries are wrong | UI: Settings > Data Models > Edit > Rebuild. CLI: `splunk rebuild-datamodel-acceleration <dm>` |
| Backfill | Backfill window extended (e.g. `-3mon` to `-12mon`) | Splunk schedules backfill automatically; tune `auto_summary_perc` if it doesn't catch up |
| Disable + reenable | Severe corruption; summaries on disk are inconsistent | Last resort — full rebuild from scratch |

### Common DMA failure modes

| Symptom | Cause | Fix |
|---|---|---|
| DM returns zero events with `summariesonly=true` but plenty with `false` | Acceleration not built or backfill window too narrow | Check completion %, extend `acceleration.earliest_time` |
| Some sourcetypes missing from DM | Eventtype/tag chain broken (eventtype not matching, tag missing on eventtype) | `| tstats from datamodel=X by sourcetype` then drill in; check `eventtypes.conf` and `tags.conf` |
| Field returns null in DM but is present in raw search | Field extracted at search time but not aliased into the DM, or `EXTRACT-` runs after DM constraint evaluation | Use `FIELDALIAS-` / `EVAL-` in props, or move extraction to index time |
| DM size exploding | Constraint matches too much data; `index=*` in root | Tighten constraint, use `cim_*_indexes` macro |
| Acceleration stuck at <100% | `auto_summary_perc` starvation, or summary-search skip storm | Raise `auto_summary_perc`, check scheduler.log for skip reasons |
| Recent events present but old events missing | Backfill not complete | Check progress; extending `earliest_time` triggers backfill |
| Inconsistent counts across SH cluster | Bucket replication uneven, or local-acceleration mismatch | Verify on each SH; rebuild if isolated to one node |

### `props.conf` / `transforms.conf` ordering

Search-time field extractions process in this order:

1. `TRANSFORMS-` (index time — already applied)
2. `REPORT-` (search-time transforms)
3. `EXTRACT-` (search-time regex)
4. `LOOKUP-`
5. `FIELDALIAS-`
6. `EVAL-`
7. `Calculated fields`

Acceleration sees fields produced by all of the above for search-time DMs, but a frequent failure is a `FIELDALIAS-` defined in a different app/scope than the DM, so the alias isn't visible at acceleration time. Use `btool` to verify (see Section 6).

---

## 3. Workload management

> Workload Management is a Splunk Enterprise feature that maps searches to resource pools with CPU and memory weightings, enforced via Linux cgroups (v1 or v2). Splunk Cloud customers see a managed equivalent.
> For actual configured pool names in your environment, see `splunk-environment-context.md`.

Splunk reference: [Workload management overview](https://docs.splunk.com/Documentation/Splunk/latest/Workloads/AboutWorkloadManagement).

### Concepts

- **Pool** — a CPU/memory share of the host. Pools are arranged into a tree under the root pool.
- **Category** — `search` or `ingest` (cgroup tier).
- **Admission rule** — applied at search submission, before the search runs. Decides which pool the search lands in. Misclassification here means the search runs in the wrong pool for its entire life.
- **Runtime rule** — applied during execution to running searches. Triggers actions: move pool, pause, abort. Used for runaway-search containment.
- **Filter** — predicate language: `app`, `user`, `role`, `index`, `search_type` (`adhoc`/`scheduled`/`summary_indexing`/`acceleration`/`datamodel_acceleration`/`report_acceleration`), `search_mode` (`smart`/`fast`/`verbose`), `runtime`, `cpu_time`, `memory`, `search_command` etc.

### Starter pool design

A reasonable default for a search head with 16 CPUs and 64 GB RAM, at least until measured behaviour suggests otherwise:

| Pool | CPU weight | Memory weight | Purpose |
|---|---|---|---|
| `default` | 10 | 10 | Catch-all — anything without a matching rule |
| `interactive` | 35 | 30 | Ad-hoc user searches (Splunk Web) |
| `scheduled` | 30 | 30 | Scheduled alerts and reports |
| `batch` | 10 | 15 | Long-running scheduled searches, summary indexing |
| `tstats` / `acceleration` | 15 | 15 | DMA, report acceleration, `_ACCELERATE_DM_*` |

Sum to ~100 in each column; weights are relative shares, not hard caps unless configured as such.

### Rule patterns

| Goal | Filter |
|---|---|
| Route ad-hoc Splunk Web searches to `interactive` | `search_type=adhoc AND app=search` |
| Route scheduled alerts to `scheduled` | `search_type=scheduled` |
| Route DMAs to acceleration pool | `search_type=datamodel_acceleration OR search_type=report_acceleration` |
| Cap any single user's resource share | `user=<user>` (or per-role via `role=`) |
| Containment for runaway searches | runtime rule: `runtime > 600 AND search_type=adhoc` -> action=move to `batch` |
| Abort searches above hard CPU/memory ceiling | runtime rule: `cpu_time > 1800 OR memory > 4GB` -> action=abort |
| Force `summary_indexing` searches off `interactive` | `search_type=summary_indexing` -> `batch` |

### Config files

`workload_pools.conf` (`$SPLUNK_HOME/etc/system/local/` or app-local):

```
[general]
enabled = true
default_pool = default
default_category = search

[workload_pool:default]
parent = root
cpu_weight = 10
mem_weight = 10
category = search

[workload_pool:interactive]
parent = root
cpu_weight = 35
mem_weight = 30
category = search

[workload_pool:scheduled]
parent = root
cpu_weight = 30
mem_weight = 30
category = search

[workload_pool:batch]
parent = root
cpu_weight = 10
mem_weight = 15
category = search

[workload_pool:acceleration]
parent = root
cpu_weight = 15
mem_weight = 15
category = search
```

`workload_rules.conf`:

```
[workload_rule:adhoc_to_interactive]
predicate = search_type=adhoc AND app=search
schedule_type = admission
pool = interactive
order = 10

[workload_rule:scheduled_to_scheduled]
predicate = search_type=scheduled
schedule_type = admission
pool = scheduled
order = 20

[workload_rule:dma_to_acceleration]
predicate = search_type=datamodel_acceleration OR search_type=report_acceleration OR search_type=summary_indexing
schedule_type = admission
pool = acceleration
order = 30

[workload_rule:longrunning_adhoc]
predicate = runtime > 600 AND search_type=adhoc
schedule_type = runtime
action = move
pool = batch
order = 40

[workload_rule:runaway_kill]
predicate = cpu_time > 1800 OR memory > 4294967296
schedule_type = runtime
action = abort
order = 50
```

Lower `order` values evaluate first. The first matching rule wins for admission; runtime rules can re-evaluate continuously.

### MC dashboards for WLM

| Dashboard | What it shows |
|---|---|
| MC > Workloads > Workload Management: Instance | Per-pool CPU/memory utilisation, admitted vs running counts |
| MC > Workloads > Workload Management: Deployment | Aggregate pool utilisation across the cluster |
| MC > Workloads > Workload Rules Audit | Rule-match counts, recent rule decisions |

### Diagnosing common WLM problems

| Symptom | Likely cause | Fix |
|---|---|---|
| All searches in `default` pool | No admission rules matched, or rules disabled | Check `workload_rules.conf` is enabled and `order` doesn't shadow rules. Audit via `index=_audit action=search workload_pool=*` |
| `interactive` pool starved | `scheduled` or `acceleration` pool overweighted | Rebalance weights, watch CPU/memory share in MC |
| Runaway search killed legitimate work | Runtime abort threshold too low | Tune `cpu_time` / `runtime` thresholds; consider `move` before `abort` |
| Pool weights ignored | cgroup not configured, or running on unsupported OS | Verify `workload_management` is enabled; check `splunkd.log` for cgroup warnings on startup |
| Search head freezes under heavy ad-hoc load | No memory-based runtime rule | Add `memory > <threshold>` runtime rule with `move` action |

### WLM vs scheduler tuning trade-offs

WLM controls *resource share at runtime*. Scheduler limits (`max_searches_perc`, `auto_summary_perc`) control *concurrency at admission*. They solve different problems:

- Use scheduler limits when the issue is "too many things trying to run at once".
- Use WLM when the issue is "the right things are running but they're getting starved".

Tuning WLM weights without raising scheduler concurrency caps is pointless if searches are skipped before they reach a pool. Tuning scheduler caps without WLM lets concurrent searches fight for CPU unmediated.

---

## 4. Indexer / ingest pipeline health

### Ingest pipeline stages

Data flows through these stages in order; each has its own queue:

| Queue | Stage | Notes |
|---|---|---|
| `parsingQueue` | Initial line breaking, sourcetype assignment | Slow on large events without `LINE_BREAKER` |
| `aggQueue` | Multi-line aggregation, timestamp extraction | Slow on bad `TIME_FORMAT` / `DATETIME_CONFIG` |
| `typingQueue` | Punct, transforms, regex extractions | Slow on heavy index-time `TRANSFORMS-` |
| `indexQueue` | Bucket write to disk | Slow on saturated I/O |

### Where to find queue metrics

```
index=_internal source=*metrics.log* group=queue
| eval fill_perc = round(current_size_kb*100.0/max_size_kb, 1)
| timechart span=1m max(fill_perc) by name
```

### Fill-pattern interpretation

| Pattern | Meaning |
|---|---|
| All four queues at low fill | Pipeline healthy |
| `parsingQueue` fills first, others empty | Forwarder/HEC throughput high; CPU-bound on parsing — usually missing `LINE_BREAKER` or `SHOULD_LINEMERGE=true` on huge events |
| `aggQueue` fills | Timestamp extraction is slow — bad `TIME_FORMAT`, `DATETIME_CONFIG=CURRENT` is faster but loses event time |
| `typingQueue` fills | Heavy index-time `TRANSFORMS-`, large regexes |
| `indexQueue` fills | Disk I/O saturated — slow disks, full bucket roll, replication lag |
| All queues full and back-pressuring | Index-stack-wide issue — disk, replication, or shutdown in progress |

Splunk reference: [About metrics.log](https://docs.splunk.com/Documentation/Splunk/latest/Troubleshooting/Aboutmetricslog).

### Bucket lifecycle and retention

| State | Location | Roll trigger |
|---|---|---|
| `hot` | `homePath` | Active write — rolls when `maxDataSize` reached or `maxHotIdleSecs` elapsed |
| `warm` | `homePath` | Read-only — rolls to cold when `maxWarmDBCount` exceeded |
| `cold` | `coldPath` | Read-only — rolls to frozen when `frozenTimePeriodInSecs` exceeded or `maxTotalDataSizeMB` exceeded |
| `frozen` | `frozenTimePeriodInSecs` exceeded — deleted unless `coldToFrozenScript` / `coldToFrozenDir` configured | Out of Splunk |
| `thawed` | `thawedPath` | Manually restored from frozen |

Key `indexes.conf` settings:

```
[<index>]
homePath          = $SPLUNK_DB/<index>/db
coldPath          = $SPLUNK_DB/<index>/colddb
thawedPath        = $SPLUNK_DB/<index>/thaweddb
maxDataSize       = auto              # 750 MB hot/warm bucket
                  = auto_high_volume  # 10 GB — use for indexes >10 GB/day
maxTotalDataSizeMB = 500000           # Total index size cap (MB)
frozenTimePeriodInSecs = 7776000      # 90 days
maxWarmDBCount    = 300
maxHotIdleSecs    = 86400
homePath.maxDataSizeMB = 0            # Hot+warm cap; 0 = unlimited
```

Bucket sizing rule of thumb: indexes ingesting >10 GB/day should use `maxDataSize = auto_high_volume`. Smaller buckets for low-volume indexes mean more bucket overhead per byte; oversized buckets for high-volume indexes mean slower roll and lock contention.

### License diagnostics

```
index=_internal source=*license_usage.log* type=Usage
| eval gb = b/1024/1024/1024
| timechart span=1d sum(gb) by pool
```

Daily volume by sourcetype (last 30 days):
```
index=_internal source=*license_usage.log* type=Usage
| eval gb = b/1024/1024/1024
| timechart span=1d sum(gb) by st useother=false limit=20
```

Pool-level violations:
```
index=_internal source=*license_usage.log* type=RolloverSummary OR type=Usage
| stats sum(b) as bytes by pool, _time
| eval gb = round(bytes/1024/1024/1024,2)
```

`type=Usage` = ongoing, `type=RolloverSummary` = end-of-day reconciliation.

License violation handling:

- 5 warnings in a 30-day rolling window triggers search disable on Enterprise (Splunk 8.x+; 9.x relaxed this — check version).
- Recovery: stay under licensed volume for 30 days, or contact Splunk Sales for a temporary increase.
- Exempt internal indexes (`_internal`, `_audit`, `_introspection`) don't count against license.

### Forwarder health

```
index=_internal source=*splunkd_access* component=HttpInputDataHandler
| stats count by host
```

Phone-home freshness:
```
| metadata type=hosts
| eval lastSeen = strftime(lastTime, "%F %T")
| eval ageHours = round((now() - lastTime)/3600, 1)
| where ageHours > 1
| sort - ageHours
```

Missing forwarders (compared to expected inventory — replace `<expected_lookup>` with environment-specific source):
```
| inputlookup <expected_lookup>
| join type=left host [
    | metadata type=hosts | fields host, lastTime
]
| where isnull(lastTime) OR lastTime < relative_time(now(), "-1h")
```

Splunk reference: [Common forwarder issues](https://docs.splunk.com/Documentation/Splunk/latest/Forwarding/Commonforwarderissues).

### Data onboarding pitfalls

| Setting | Default | Pitfall |
|---|---|---|
| `MAX_DAYS_AGO` | 2000 | Events older than this are silently rejected — common with bulk imports of historic data |
| `MAX_DAYS_HENCE` | 2 | Future-dated events rejected — clock-skewed forwarders drop data |
| `DATETIME_CONFIG` | `/etc/datetime.xml` | Use `CURRENT` to skip timestamp extraction (uses ingest time) — fast but loses true event time |
| `TIME_PREFIX` | unset | Anchor regex for timestamp position — speeds extraction massively on large events |
| `MAX_TIMESTAMP_LOOKAHEAD` | 128 | Bytes scanned for timestamp; too small misses, too large is slow |
| `LINE_BREAKER` | `([\r\n]+)` | Regex for event boundaries — set explicitly for multi-line events; faster than `SHOULD_LINEMERGE=true` |
| `SHOULD_LINEMERGE` | `true` | Old-style merging; set to `false` and use `LINE_BREAKER` for new sources |
| `TRUNCATE` | 10000 | Truncates events at this many bytes — long JSON often hits this silently |
| `EVENT_BREAKER_ENABLE` | `false` (UF) | Set to `true` on universal forwarders for parallel pipelines; without it, all events from one source serialize through one pipeline |

### Sourcetype routing precedence

Routing happens in this order (later wins for sourcetype assignment):

1. `inputs.conf` `sourcetype = X` (input-time, lowest precedence)
2. `props.conf` `[source::...]` with `sourcetype = X`
3. `props.conf` `[host::...]` with `sourcetype = X`
4. CLONE_SOURCETYPE in `transforms.conf` (clones the event)

For *event* routing to a different index or destination, see `props.conf` `TRANSFORMS-route = ...` referencing a `transforms.conf` stanza with `DEST_KEY = _MetaData:Index` or `_TCP_ROUTING`.

A common pitfall is setting both `inputs.conf sourcetype = ms:iis:auto` and a `[source::...iis...]` props stanza assigning a different sourcetype — the props stanza wins and silently overrides the input config.

---

## 5. Ingest architecture patterns

> How data gets into Splunk shapes everything downstream — sourcetype assignment, field extraction, CIM mapping, and the SPL contract that detection content is written against. The pattern that's appropriate for a given source depends on volume, vendor parsing complexity, and whether the source pushes or has to be polled. This section is a vendor-agnostic synthesis of the canonical ingest paths and the trade-offs between them.
>
> For the actual sourcetype shape, fields, and CIM mapping produced by any given pattern, see the corresponding vendor section in `splunk-sourcetype-library.md`.

### Canonical ingest paths

| Path | Typical use | Pros | Cons | Practical scale ceiling |
|---|---|---|---|---|
| Direct syslog (UDP/TCP) | Network devices, legacy appliances, low-volume vendor sources | Simple, no extra components, native Splunk inputs | UDP loses data under load; single-input parsing bottleneck; no per-vendor normalisation | <1–2 GB/day per indexer input before SC4S becomes the better answer |
| SC4S (Splunk Connect for Syslog) | Any non-trivial syslog volume; multi-vendor syslog aggregation | Vendor-aware filtering and routing; sourcetype/index assignment at collection; HEC delivery so no UDP loss; horizontally scalable | Extra component to operate; container/host to manage; learning curve on filter packs | Tens of GB/day per SC4S host; scales horizontally with load balancing |
| HEC (HTTP Event Collector) | Anything that can emit HTTPS+JSON: cloud services, custom apps, Telemetry Streaming, push-based vendor agents | High throughput; reliable; per-token routing; no forwarder needed; load balancers in front scale linearly | Token sprawl if poorly managed; sources must be HEC-aware; HEC input dies silently if the receiver is down without retry on the source side | Limited primarily by indexer tier and load-balancer capacity |
| Modular inputs (pull from API) | Cloud APIs that don't push, vendor management consoles, REST-only sources | Simple to deploy on a heavy forwarder; resilient to short-term Splunk outages (the API holds events) | Single-instance-per-input constraint; throttling can lag ingest; per-account state is local | Low-to-moderate volume; single-account or small multi-account scenarios |
| File monitoring (universal forwarder) | On-host log files (IIS, custom apps, OS logs) | Mature, universal, well-understood | Filesystem dependency; rotation/permissioning quirks; UF must reach indexers | Effectively unlimited per host, but per-input parallelism limited without `EVENT_BREAKER_ENABLE` |
| Cloud-native push (AWS Firehose, Azure Event Hub, GCP Pub/Sub) | High-volume cloud telemetry, multi-account org-level collection | Native to the cloud platform; scales to platform limits; multi-account aggregation built in | Embedded-envelope parsing requires HEC source overrides (see below); cost on the cloud side; transform/Lambda complexity for some payloads | Effectively unlimited; bound by HEC tier and downstream indexers |

Splunk reference: [About Splunk Connect for Syslog](https://splunk.github.io/splunk-connect-for-syslog/main/), [Set up and use HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector).

### SC4S (Splunk Connect for Syslog) in depth

SC4S is a containerised syslog-NG-based collector with Splunk-aware filter packs that perform sourcetype assignment, index routing, and source classification before events ever reach a Splunk indexer. It sits between the syslog source and Splunk's HEC endpoint.

#### What SC4S solves

- **Parsing and routing at collection.** Filter packs match incoming syslog by host, message content, RFC 5424 structured-data, or regex, and assign the correct `sourcetype`, `source`, and `index`. Splunk's built-in UDP/TCP syslog inputs do none of this — everything lands as a generic syslog sourcetype unless props/transforms reshape it after the fact.
- **Vendor normalisation at scale.** Filter packs ship for hundreds of vendors (Cisco ASA/FTD, Palo Alto, Check Point, F5, Fortinet, Juniper, etc.). The TA on the indexer side then handles search-time enrichment, but indexing and routing are already correct.
- **UDP without loss.** Native syslog-NG buffers and back-pressures. UDP into a Splunk syslog input drops silently under load; SC4S buffers locally and delivers via HEC with retry.
- **Source classification.** Distinguishing two devices that both emit `cisco:asa`-shaped logs into different indexes (e.g. by site, environment, business unit) — trivial in SC4S filter packs, painful in props/transforms.

#### When to choose SC4S over direct syslog

- Aggregate syslog volume above ~1–2 GB/day across all sources.
- More than two or three vendors emitting syslog to the same collector.
- Any vendor with non-trivial parsing rules or per-version format changes (Cisco ASA, Palo Alto, Check Point, F5).
- UDP delivery cannot be lost (security devices where dropped events are a compliance issue).

#### When *not* to use SC4S

- Single low-volume source where direct syslog is operationally simpler.
- Source can speak HEC natively (push it directly — SC4S adds a hop with no benefit).
- Source has a first-party modular input that handles auth, checkpointing, and pagination (e.g. AWS modular inputs, Microsoft Graph) — SC4S has nothing to add.

#### Filter packs and vendor support

SC4S ships with filter packs in the Splunk Connect for Syslog GitHub repo. Verify a vendor is supported before designing around SC4S — `splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/<vendor>/` documents whether a vendor pack exists and what filter conditions it uses. Custom filter packs are straightforward to write but become an environment-specific maintenance burden.

#### Common SC4S deployment topologies

| Topology | When to use |
|---|---|
| Single SC4S host, one Splunk HEC endpoint | Small environments, single site, low aggregate volume |
| Multiple SC4S hosts behind a UDP/TCP load balancer, multiple HEC endpoints behind a separate load balancer | Most production deployments — horizontal scale on both ingress and egress |
| SC4S per region/site, regional HEC endpoints | Multi-region with per-region indexers; reduces WAN traffic |
| SC4S on the same host as a heavy forwarder (HEC-to-S2S) | Legacy environments where HEC isn't available end-to-end; not recommended for new builds |

### Push vs pull architectures

Almost every cloud-native source can be ingested either by polling (modular input pulls events from the vendor API) or by configuring the vendor to push (Firehose, Event Hub, Pub/Sub, native HEC). The choice has real operational consequences.

| Concern | Pull (modular input) | Push (Firehose / Event Hub / HEC) |
|---|---|---|
| Setup complexity | Splunk-side config only | Requires cloud-side config — IAM, delivery streams, transforms |
| Multi-account | One input per account; doesn't scale | Org-level delivery streams aggregate naturally |
| Volume ceiling | Bound by API rate limits and modular-input parallelism | Bound by HEC tier and indexer capacity |
| Failure mode | Splunk outage = backlog at the API; recover by catching up | Splunk outage = events buffered cloud-side (Firehose retry, Event Hub retention); may also fail to S3/blob fallback |
| Latency | Polling-interval bound (seconds to minutes) | Near-real-time (seconds) |
| Cost | Splunk-side compute for polling | Cloud-side delivery and transform charges |

**Rule-of-thumb thresholds for switching pull → push:**

- Aggregate source volume above ~50 GB/day for a single vendor source.
- More than ~5 cloud accounts feeding the same data type.
- Latency requirement under 5 minutes.
- Existing modular input is hitting API rate limits or showing checkpoint lag in `_internal`.

A common starting topology is pull-based for the first cloud account and a single low-volume source, then migrate to push-based once volume or account count grows. Detection content written against the data is portable — sourcetypes generally don't change between pull and push for the same data — but HEC source overrides (below) often do.

### HEC source overrides for embedded events

When events are delivered via Firehose (or any cloud-native push that wraps payloads in an envelope), the actual security event is buried inside a CloudWatch / EventBridge / native cloud envelope. Downstream search-time field extractions in the TA are anchored on the `source` value, not the sourcetype — they need to know what kind of payload to look inside the envelope for. If the HEC `source` is wrong, the sourcetype lands correctly but extractions don't fire and the data appears empty even though events are present.

This is operationally invisible until someone tries to write a detection and finds none of the documented fields are extracted. Always verify HEC source override values during onboarding — the symptom is "events are being indexed but fields documented in the TA are not being extracted."

#### Canonical HEC source overrides — AWS Firehose-delivered services

| Vendor data | Sourcetype | Required HEC `source` |
|---|---|---|
| CloudTrail (Firehose-embedded in CloudWatch events) | `aws:cloudtrail` | `aws_firehose_cloudtrail` |
| GuardDuty (Firehose push) | `aws:cloudwatch:guardduty` | `aws_cloudwatchevents_guardduty` |
| Security Hub findings (ASFF via Firehose) | `aws:securityhub:finding` | `aws_cloudwatchevents_securityhub` |
| IAM Access Analyzer findings (EventBridge → HEC) | `aws:accessanalyzer:finding` | `aws_eventbridgeevents_iam_aa` |
| Generic CloudWatch events via Firehose | `aws:firehose:cloudwatchevents` | (use specific override above for embedded service events) |

For Firehose-delivered VPC Flow logs, additional Lambda buffering (1 MB) and a transform to strip the CloudWatch JSON wrapper are required before reaching Splunk. For library-level vendor specifics — sourcetype field shapes, CIM mappings, eventtype chains — see the AWS section of `splunk-sourcetype-library.md`.

### Heavy-forwarder placement and modular-input topology

Modular inputs (Python-based scripted inputs that poll vendor APIs) typically run on heavy forwarders rather than search heads or indexers, because:

- Modular inputs spawn long-running Python processes that compete with search workload on a search head.
- Indexers shouldn't run modular inputs at all — they need their CPU for parsing/indexing.
- Heavy forwarders are sized for ingest, expose the necessary network egress to vendor APIs, and isolate input failures from the search tier.

#### The single-instance-per-input constraint

Most modular inputs maintain checkpoint state locally (last-poll timestamp, pagination cursor, watermark token). Running the same input on two heavy forwarders typically produces:

- Duplicate events (both instances poll the same window and ingest both copies), or
- Lost events (one instance moves the checkpoint forward; the other never sees the window in between), or
- API rate-limit exhaustion (both instances burn the vendor's rate-limit budget).

This makes most modular inputs effectively single-instance — a high-availability concern that affects design.

#### When clustering or load-balancing modular inputs is necessary

Less rare than commonly assumed:

- Volume per input exceeds what one HF can poll within the polling interval (e.g. CloudTrail in a large org, MDE advanced hunting).
- Multiple accounts/tenants each need their own input scope (multi-tenant SaaS).
- HF failover requirement is tighter than the time to manually re-enable inputs on a standby.

Most TAs are not designed for this. Patterns that work in practice:

| Pattern | Notes |
|---|---|
| Active/passive HF pair, manual failover | Acceptable for MTTR measured in hours; checkpoint state must be replicated or re-derived from event timestamps after failover |
| Active/passive with shared checkpoint storage | Some TAs (AWS, MDE recent versions) support pointing checkpoint storage at a shared KV store or external state — verify per-TA |
| Per-account input sharding across multiple HFs | Each HF runs a disjoint subset of inputs; failure is partial, not total |
| TA-supported clustering | Rare — explicit support in the TA's docs is required; do not assume from generic Splunk HA patterns |

If the TA doesn't document multi-instance support, assume single-instance — and design around it.

### Multi-TA / app conflict topology

A common operational hazard: two add-ons claim parsing responsibility for the same data. Symptoms include duplicate events, inconsistent CIM mapping, conflicting eventtypes, broken detections after upgrades, and "the same SPL works for one user and not another."

Common conflict patterns from the field (see `splunk-sourcetype-library.md` for the vendor specifics):

| Conflict | Typical cause | Resolution direction |
|---|---|---|
| Check Point (Splunk-built TA `Splunk_TA_checkpoint_log_exporter` vs vendor-built `Check Point App for Splunk`) | Both ship eventtypes/tags claiming `cp_log` | Splunk-built TA for extractions; vendor app for dashboards only, with its eventtypes/tags disabled |
| SentinelOne (App + TA installed on the same host) | App's modular inputs and TA's inputs both register | App on search head, TA on indexer/heavy forwarder, IA on forwarder — never colocate |
| Check Point OPSEC LEA legacy alongside Log Exporter | Both deliver the same firewall data via different transports | Disable OPSEC LEA inputs entirely once Log Exporter is producing data |
| Microsoft Defender / Graph Security overlap (`Splunk_TA_MS_Security` vs newer Graph Security TA vs MDE TA) | All three can pull alerts from overlapping Graph endpoints | Pick one path for Graph Security data; MDE TA scoped to MDE-specific advanced hunting only |
| O365 collected by both `Splunk_TA_microsoft-cloudservices` (legacy) and `splunk_ta_o365` | Both register Management Activity API inputs | Use `splunk_ta_o365` only; disable the cloudservices O365 inputs |
| IIS data with both `ms:iis:auto` (index-time) and `ms:iis:default` (search-time) sourcetypes assigned | A `[source::...iis...]` props stanza shadows the `inputs.conf` sourcetype | Pick one sourcetype, remove the other's props — see Section 4 sourcetype routing precedence |

#### Detecting duplicate ingestion

The fastest way to spot duplicate ingestion is to look for the same data under multiple sourcetypes or the same events appearing twice:

```
| tstats count where index=* by index, sourcetype, source
| sort - count
```

Look for sourcetype pairs that should be mutually exclusive — e.g. `cp_log` and `cp_log:syslog` both populated, `ms:iis:auto` and `ms:iis:default` both populated, `o365:management:activity` and `ms:o365:management` both populated.

For a more direct duplicate check, hash a stable identifier and look for repeats:

```
index=<index> sourcetype=<sourcetype> earliest=-1h
| stats count values(sourcetype) as sourcetypes by <unique_event_id>
| where count > 1
```

For Office 365 specifically, at-least-once delivery means real duplicates exist by design — but the count should be small and the *sourcetype* should be the same. Multiple sourcetypes for the same unique ID indicate competing TAs.

#### Resolution

Identify the canonical TA for the data (Splunkbase, vendor recommendation, or — failing that — the one that's actively maintained). Disable inputs in the redundant TAs (`disabled = 1` in `inputs.conf`), or uninstall them entirely if no functionality is being lost. Keep one TA's eventtype/tag chain active per dataset; disabling tags in the redundant TA's `tags.conf` can be sufficient if the TA itself must remain installed for other reasons.

### Deprecated TA migration paths

The Splunk add-on ecosystem accumulates deprecated sourcetypes whenever a TA changes its parsing strategy or a vendor changes its log format. Detections written against the old sourcetypes silently stop matching when the data reshapes.

| Vendor / data | Old pattern | New pattern | Migration trigger | What breaks if not updated |
|---|---|---|---|---|
| Microsoft IIS | `ms:iis:default`, `ms:iis:default:85`, `ms:iis:splunk` (search-time extraction) | `ms:iis:auto` (index-time, W3C header-driven) | Upgrade of `Splunk_TA_microsoft-iis`; switch from search-time to index-time extraction | Web data model goes empty; saved searches with `sourcetype=ms:iis:default` return no results |
| Office 365 Management Activity | `ms:o365:management` (legacy `Splunk_TA_microsoft-cloudservices` input) | `o365:management:activity` (`splunk_ta_o365`) | Migration to dedicated O365 add-on | All M365 audit detections; Authentication / Change DM coverage from O365 |
| Office 365 message trace | `o365:reporting:messagetrace` (legacy reporting input) | `o365:graph:messagetrace` (Graph API) | Microsoft API deprecation; add-on version upgrade | Email data model coverage; phishing/BEC detections; mail-flow dashboards |
| Office 365 service status | `o365:service:status` | `o365:service:healthIssue` | Add-on v3.0.0 (Service Communications API → Microsoft Graph) | Service-health-based correlation searches |
| Palo Alto Networks | Pre-v3 split add-ons (`Splunk_TA_paloalto` v2.x, separate `TA-cortex-xdr`, separate IoT add-on) | Consolidated `Splunk_TA_paloalto` v3+ | Add-on consolidation in v3.0.0 | Cortex XDR sourcetypes rename (`paloalto:xdr:*` → `pan:xdr:*`); IoT sourcetype rename |
| SentinelOne | `sourcetype=agent`, `sourcetype=group` (no namespace prefix) | `sentinelone:channel:agents`, `sentinelone:channel:groups`, etc. | Pre-v5 → v5+ App upgrade | Agent inventory, threat triage, console activity dashboards |
| Mimecast | v3.x with API 1.0 (`Application ID` + `Access Key` + `Secret Key`) | v5+ with API 2.0 keys | Mimecast API 1.0 retirement | **Cannot upgrade in place** — fresh install with new API keys; old data remains, new data lands in same sourcetypes but ingest stops without re-onboarding |

#### Migration playbook (generic)

1. **Identify deployment scope.** `| tstats count by sourcetype | search sourcetype IN (<old>, <new>)` to confirm which sourcetypes have data and over what timeframe.
2. **Inventory dependent content.** Saved searches, macros, eventtypes, lookups, dashboards, ES correlation searches, ITSI KPIs — all need an audit:
   ```
   | rest /servicesNS/-/-/saved/searches splunk_server=local count=0
   | search search="*<old_sourcetype>*"
   | table title, eai:acl.app, search
   ```
3. **Plan an overlap window.** Both old and new sourcetypes coexisting for a short period lets detections be migrated and validated without coverage gaps. Disable the old input *after* the new one is verified.
4. **Update macros/eventtypes first, content second.** Where possible, abstract the sourcetype rename behind a macro or eventtype so downstream content doesn't need changes — this is the single highest-value migration practice.
5. **Validate CIM coverage post-migration.** `| tstats from datamodel=<DM> by sourcetype` against both old and new sourcetypes during the overlap; data-model population should match.
6. **Document the rename.** In environment-context notes — old saved searches will outlive deployment memory.

### API throttling and ingestion lag

Modular inputs polling vendor APIs are subject to vendor-side rate limits. When throttling kicks in, ingestion lags but doesn't fail outright — the symptom is "data is present but late," easily mistaken for an outage or for missing data altogether.

#### Where to look

```
index=_internal sourcetype=*errors* (component=ModularInputs OR component=ExecProcessor)
    (throttle OR throttled OR "rate limit" OR "429" OR "Too Many Requests")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, source, message
| sort - count
```

Per-TA error sourcetypes are common (e.g. `sentinelone_app_for_splunk:error`, `microsoft:graph:security:errors`) — these are the first place to look for any modular-input-based source:

```
index=_internal sourcetype=*<vendor>*error* OR source=*<vendor>*error*
| stats count by sourcetype, message
| sort - count
```

#### Distinguishing throttling from outages

| Signal | Throttling | Outage |
|---|---|---|
| Errors in `_internal` | 429 / "rate limit" / "throttled" | 5xx / connection refused / timeout |
| Event flow | Slowed but continuous | Stopped completely |
| Catches up | Yes, after backoff window | Only after restoration |
| Pattern | Steady-state ingestion lag (e.g. 30 min behind real time) | Step-function gap with sharp recovery |
| Time of day | Often correlates with peak source activity | Usually random |

Throttling is normal during initial backfills, after long ingestion gaps, and in environments with multiple Splunk instances polling the same vendor. Most TAs implement retry-with-backoff. Persistent throttling (lag growing over time, not resolving) indicates the modular input cannot keep up with source volume — switch to a push-based architecture if available.

### Token / credential management for modular inputs

API tokens and secrets are the most common silent failure point for modular inputs. The input is configured, the heavy forwarder is healthy, the vendor side is producing events, and yet no data arrives. Almost always a credential issue.

#### Common token failure modes

| Failure | Symptom | Detection |
|---|---|---|
| Token expired | Ingestion stops at a specific timestamp; no errors visible without checking the input log | Per-TA error sourcetype shows 401 / 403 / "expired" |
| Insufficient scopes / permissions | Auth succeeds (no 401) but data is empty or missing categories | Compare expected vs actual event categories; check the app registration / API client scopes |
| Wrong region / base URL | Auth succeeds against a different tenant or returns no data | Verify base URL matches tenant region (Mimecast US vs UK vs EU; Microsoft Graph national clouds; AWS GovCloud) |
| Token format quirk | 401 immediately on first poll | Check vendor-specific prefix requirements (e.g. `ApiToken ` prefix for SentinelOne) |
| Secret storage truncation | Auth fails with malformed-token errors despite correct configuration | Splunk Storage Manager has a 256-character encrypted secret limit; tokens longer than this can be silently truncated unless the TA splits them |

#### Vendor-specific quirks worth knowing

| Vendor | Quirk |
|---|---|
| Mimecast | Default API tokens expire after **3 days** — silently breaks ingest. Create a dedicated user with an Authentication Profile set to "Never Expires" before generating the token. v5+ uses API 2.0 keys (`Application ID` + `Access Key` + `Secret Key` from v3.x are obsolete) |
| SentinelOne | API token storage hits the Splunk Storage Manager 256-character limit; the App splits tokens (first 220 encrypted, remainder unencrypted) to work around it. Tokens may also require the `ApiToken ` prefix (with trailing space) |
| Microsoft Defender for Endpoint | Requires `WindowsDefenderATP` API permissions on the Entra ID app registration — *not* the broader Microsoft Graph permission set. Misconfigured scopes return 200 with no data |
| Microsoft Graph (multi-tenant) | Each Entra ID tenant requires its own app registration and TA input |
| AWS modular inputs | IAM role/user permissions must include the documented per-input policy; missing permissions return 200 from auth but empty results from data calls |
| Lansweeper Cloud | API token from `docs.lansweeper.com/docs/api/authenticate`; on-prem requires a separate DB Connect path against MSSQL (LocalDB doesn't support remote connections) |

#### Operational practice

- **Set token expiry alarms** based on the issuance date plus the vendor's default lifetime, with a reminder before expiry.
- **Document the credential's source** in environment context — which user issued it, which app registration, which tenant, what scopes.
- **Validate post-rotation.** Every credential rotation should be followed by a "data has resumed" check (a `tstats` over the source's expected event volume in the post-rotation window).
- **Use a dedicated service account** rather than a real user's credentials wherever possible. Real user accounts are deactivated when people leave; service-account credentials survive personnel churn.

For the actual sourcetype shapes produced by each TA referenced above, see the corresponding section of `splunk-sourcetype-library.md`.

---

## 6. Knowledge object hygiene

### Saved-search inventory and churn

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| eval is_scheduled = if('is_scheduled'=1, "scheduled", "unscheduled")
| stats count by eai:acl.app, is_scheduled, eai:acl.sharing
| sort - count
```

Last-execution time per saved search (joined against audit log):
```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| where 'is_scheduled'=1
| fields title, eai:acl.app, cron_schedule
| join type=left title [
    search index=_audit action=search info=completed savedsearch_name=*
    | stats max(_time) as last_run by savedsearch_name
    | rename savedsearch_name as title
]
| eval last_run_str = if(isnull(last_run), "NEVER", strftime(last_run, "%F %T"))
| eval days_since = if(isnull(last_run), 9999, round((now() - last_run)/86400, 1))
| sort - days_since
```

Searches that have *never* run:
```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| where 'is_scheduled'=1 AND disabled=0
| fields title, eai:acl.app
| search NOT [
    search index=_audit action=search info=completed
    | stats count by savedsearch_name
    | rename savedsearch_name as title
    | fields title
]
```

### Permission scope and propagation

Knowledge objects (saved searches, macros, lookups, eventtypes, tags, fields, datamodels) have:

- **Owner** — the user who created or owns the object.
- **App** — the app context the object belongs to.
- **Sharing** — `private` (owner only), `app` (visible within app), `global` (all apps).

Sharing controls visibility; explicit `[role_*]` ACLs on the object control read/write. To make an object usable cluster-wide, share it `global`.

In `default.meta` / `local.meta`:

```
[savedsearches/<name>]
access = read : [ * ], write : [ admin, power ]
export = system

[lookups]
access = read : [ * ], write : [ admin ]
export = system
```

`export = system` is required for global sharing across apps.

### Lookups: CSV vs KV store

| Concern | CSV lookup | KV store lookup |
|---|---|---|
| Recommended size cap | <100 MB / <10M rows (hard limit `max_memtable_bytes` = 10 MB by default for in-memory sort) | Hundreds of GB possible, but per-key access is the right pattern |
| Replication across SHC | Bundle replication every change — large CSVs cripple replication | KV store is cluster-replicated, no bundle hit |
| Update pattern | Whole-file rewrite | Per-record API |
| Search-time cost | Full scan unless indexed | Indexed lookup if `accelerated_field` or `_key` configured |
| Best for | Reference data updated rarely | Frequently-updated state, asset/identity, large datasets |

`transforms.conf` for a CSV lookup:

```
[my_lookup]
filename = my_lookup.csv
match_type = WILDCARD(host)
min_matches = 1
default_match = unknown
case_sensitive_match = false
```

`match_type`:
- `WILDCARD(field)` — supports `*` patterns in the lookup file
- `CIDR(field)` — IP CIDR matching
- `EXACT(field)` (default) — literal match

`min_matches` / `default_match` provide fallback values when the lookup misses.

KV store lookup:
```
[my_kv_lookup]
external_type = kvstore
collection = my_collection
fields_list = _key, host, owner, environment
```

### Macro / eventtype / tag / field-extraction ordering

Order of evaluation at search time:

1. Index-time-extracted fields (`TRANSFORMS-` from `props.conf`)
2. Search-time `REPORT-` / `EXTRACT-` from `props.conf`
3. `LOOKUP-`
4. `FIELDALIAS-`
5. `EVAL-` (calculated fields)
6. Eventtype matching (`eventtypes.conf`)
7. Tag application (`tags.conf`)
8. Macro expansion (lexical, in the SPL)

Common "field not extracting" causes:

| Symptom | Likely cause |
|---|---|
| Field missing only on some hosts | `props.conf` scoped by `host::` rather than `sourcetype` |
| Field present in raw events but not in DM | Field aliased after DM constraint evaluation, or alias scoped to wrong app |
| Field works for admin but not other users | Lookup or extraction scoped `private` instead of `app`/`global` |
| Field works in one search but not another | Macro expansion difference, or app-scoping shadowing a global definition |
| New extraction not taking effect | Splunk needs `| extract reload=t` in search, or `_introspection` reload, or restart for `TRANSFORMS-` |

### `btool` — what config is actually applied

`btool` flattens the merged config across system, app, and user scopes. It's the canonical answer to "what is Splunk actually using?".

```
$SPLUNK_HOME/bin/splunk btool props list <sourcetype> --debug
$SPLUNK_HOME/bin/splunk btool transforms list <stanza> --debug
$SPLUNK_HOME/bin/splunk btool indexes list <index> --debug
$SPLUNK_HOME/bin/splunk btool inputs list --debug | grep -A5 <input>
$SPLUNK_HOME/bin/splunk btool check
```

`--debug` prefixes each line with the file that contributed it — read right-to-left up the chain to see precedence. Last writer wins for same-key/same-stanza, with the resolution order: system local > app local > app default > system default. `btool check` validates syntax across all conf files.

Splunk reference: [Use btool to troubleshoot configurations](https://docs.splunk.com/Documentation/Splunk/latest/Troubleshooting/Usebtooltotroubleshootconfigurations).

---

## 7. Monitoring Console quick reference

| Symptom | MC dashboard | What to look for |
|---|---|---|
| Skipped searches | Search > Scheduler Activity: Instance / Deployment | `Skipped` panel; skip-reason breakdown; concurrency-limit chart |
| Slow searches | Search > Search Activity: Instance | `Top 20 Memory-Consuming Searches`, `Long Running Searches`, `Median Duration` |
| Search head pegged (CPU) | Resource Usage: Instance | `CPU Usage` per process — `splunkd` vs `python` (modular inputs) vs `mongod` (KV store) |
| Indexer queue back-pressure | Indexing > Indexing Performance: Instance | `Median Fill Ratio` of parsing/agg/typing/indexQueue; `Indexing Rate` drop |
| Indexing throughput drops | Indexing > Indexing Performance: Deployment | Indexing rate per indexer; outliers vs cluster median |
| License overage | Licensing | `Today's License Usage` vs `Daily Quota`; warning count in last 30 days |
| License usage by sourcetype | Licensing > By Source Type | Sourcetype contribution to daily volume |
| KV store health | Search > KV Store: Instance / Deployment | `Replication Status`, `Storage Engine`, `Operations` |
| DMA status | Indexing > Data Model Acceleration | Per-DM completion %, size, last build, last error |
| Forwarder health | Forwarders: Instance / Deployment | Forwarders missing / not phoning home; throughput per forwarder |
| Search head clustering health | Search Head Clustering: Status and Configuration | Captain status, replication factor, conf bundle status |
| Indexer clustering health | Indexer Clustering: Status / Indexes | Search/replication factors met; pending fixups; rolling restart status |
| WLM utilisation | Workloads > Workload Management: Instance / Deployment | Per-pool CPU/memory share, admitted vs running counts |

Splunk reference: [What can the Monitoring Console do?](https://docs.splunk.com/Documentation/Splunk/latest/DMC/WhatcantheMonitoringConsoledo).

---

## 8. Self-monitoring SPL cheat sheet

### Top 20 most expensive ad-hoc searches today
```
index=_audit action=search info=completed earliest=@d
    user!=splunk-system-user (search_type=adhoc OR savedsearch_name="")
| stats sum(total_run_time) as cpu_seconds
        sum(scan_count) as events_scanned
        count as runs
        max(_time) as last_run
        by user, search
| eval last_run = strftime(last_run, "%F %T")
| sort - cpu_seconds
| head 20
```

### Skipped searches by app over last 24h
```
index=_internal source=*scheduler.log* status=skipped earliest=-24h
| stats count by app, savedsearch_name, reason
| sort - count
```

### Pipeline queue fill percentage by indexer
```
index=_internal source=*metrics.log* group=queue
    name IN (parsingQueue, aggQueue, typingQueue, indexQueue)
| eval fill_perc = round(current_size_kb*100.0/max_size_kb, 1)
| timechart span=5m max(fill_perc) by host
```

### Indexers with largest disk utilisation
```
| rest /services/server/status/partitions-space splunk_server=*
| eval used_pct = round(((capacity - free)/capacity)*100, 1)
| eval free_gb = round(free/1024, 1)
| eval cap_gb = round(capacity/1024, 1)
| stats max(used_pct) as max_used_pct min(free_gb) as min_free_gb max(cap_gb) as cap_gb by splunk_server, mount_point
| sort - max_used_pct
```

### Scheduled searches that have never run successfully
```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| where 'is_scheduled'=1 AND disabled=0
| fields title, eai:acl.app, cron_schedule
| search NOT [
    search index=_audit action=search info=completed earliest=-30d
    | stats count by savedsearch_name
    | rename savedsearch_name as title
    | fields title
]
```

### Indexes by daily volume vs allocated retention
```
| rest /services/data/indexes splunk_server=*
| eval size_gb = round(currentDBSizeMB/1024, 2)
| eval max_size_gb = round(maxTotalDataSizeMB/1024, 2)
| eval retention_days = round(frozenTimePeriodInSecs/86400, 0)
| join type=left title splunk_server [
    search index=_internal source=*license_usage.log* type=Usage earliest=-7d
    | stats avg(b) as avg_bytes by idx, host
    | eval avg_gb_per_day = round(avg_bytes/1024/1024/1024, 2)
    | rename idx as title, host as splunk_server
]
| eval projected_gb = avg_gb_per_day * retention_days
| eval pct_full = round(size_gb*100.0/max_size_gb, 1)
| table splunk_server, title, size_gb, max_size_gb, pct_full, retention_days, avg_gb_per_day, projected_gb
| sort - projected_gb
```

### License usage by sourcetype, last 30 days
```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| eval gb = b/1024/1024/1024
| stats sum(gb) as total_gb by st
| eval daily_avg_gb = round(total_gb/30, 2)
| sort - total_gb
```

### Search heads with high concurrency vs CPU saturation
```
index=_introspection sourcetype=splunk_resource_usage component=PerProcess
    data.process_type=search
| stats avg(data.pct_cpu) as avg_cpu max(data.pct_cpu) as max_cpu count as samples by host
| join type=left host [
    search index=_internal source=*scheduler.log* component=SavedSplunker
    | stats max(concurrency_used) as max_concurrency by host
]
| where avg_cpu > 70 OR max_concurrency > 20
| sort - avg_cpu
```

### Search head dispatch dir size (per SH)
```
| rest /services/server/status/dispatch-artifacts splunk_server=*
| stats sum(count) as artifacts max(size_mb) as size_mb by splunk_server
| sort - artifacts
```

### Forwarders that have stopped phoning home
```
| metadata type=hosts index=_*
| eval ageMin = round((now() - lastTime)/60, 1)
| where ageMin > 30
| eval lastSeen = strftime(lastTime, "%F %T")
| table host, lastSeen, ageMin
| sort - ageMin
```

### Top sourcetypes by event volume — last 24h
```
| tstats count where index=* by sourcetype, _time span=1h
| stats sum(count) as events by sourcetype
| sort - events
| head 25
```

### DMA buckets pending across the deployment
```
| rest /servicesNS/-/-/admin/summarization splunk_server=*
| eval dm = replace(summary.id, "^DM_.+?_", "")
| stats sum(summary.buckets) as total_buckets max(summary.complete) as pct by dm
| eval pending_estimate = round(total_buckets * (1 - pct), 0)
| where pending_estimate > 0
| sort - pending_estimate
```

### KV store collection sizes
```
| rest /servicesNS/-/-/storage/collections/data splunk_server=local count=0
| stats sum(size) as bytes by eai:acl.app, title
| eval mb = round(bytes/1024/1024, 2)
| sort - mb
```

---

## Conventions for adding entries

When extending this reference, each topic entry should include:

1. **What it diagnoses** — symptom or question the section answers
2. **Where to look** — MC dashboard / log file / REST endpoint
3. **SPL or commands** — runnable, generic, parameterised with `<placeholders>`
4. **Tunables** — relevant `.conf` settings with defaults
5. **Common failure modes** — the two or three things this issue is usually caused by
6. **Reference link** — canonical Splunk docs URL where applicable
