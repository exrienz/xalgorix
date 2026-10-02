# Diagnosing a scan that waits or pauses

A scan can remain running while an upstream request is waiting to retry. During
wildcard discovery, the discovery completion inventory is published after the session
returns, so an empty Events view does not identify the cause of a wait.

Read the logs of the process already serving the dashboard. Starting a second
server and receiving `address already in use` only diagnoses that second
process's startup failure.

For a systemd installation:

```sh
journalctl -u xalgorix --since "20 minutes ago" --no-pager
```

For a container installation, use its existing container logs. For a foreground
installation, read the terminal output of the running process.

Upstream wait diagnostics include:

| Field | Meaning |
| --- | --- |
| `class` | Rate limit, capacity overload, or explicit credit exhaustion |
| `http_status` | Response status; zero means no recognized transport status |
| `code` | Known protocol error code; unknown values and response messages are omitted |
| `retry_in` | Delay before the next request |
| `attempt` | Consecutive wait attempts |
| `cumulative_wait` | Spent wait time retained across the assessment |
| `wait_limit`, `wait_remaining` | Configured ceiling and remaining allowance, or `unlimited` |

A healthy response with executable tool calls logs a recovery transition.
Exhausting the wait allowance logs a pause with state preserved for resume.
These diagnostics stay in operator logs and are not scan coverage or customer
progress events.

Available account credits do not rule out request or token rate limits. An
ambiguous resource-exhausted response is treated as a temporary resource limit;
credit exhaustion requires an explicit credit or billing signal. Target
reachability and an external subdomain inventory do not establish upstream
request success or the inventory collected by a scan.

For a bug report, include the wait, budget-exhaustion, and recovery diagnostic
lines with scan identifiers removed. Keep credentials, response bodies, URLs,
and target evidence out of the report. A paused assessment retains its evidence
and unfinished work; it does not become complete by increasing a wait limit.
