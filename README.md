# Cyber Alert System

[![CI](https://github.com/oabukhalaf/cyber-alert-system/actions/workflows/ci.yml/badge.svg)](https://github.com/oabukhalaf/cyber-alert-system/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A detection tool for SSH authentication logs. It parses OpenSSH entries in Linux
auth logs (`/var/log/auth.log`, `/var/log/secure`), follows the log as it's written,
and runs detection rules that flag brute-force attacks, password spraying, and
successful logins that follow a run of failures. Each alert is mapped to a
MITRE ATT&CK technique. Alerts appear in the terminal or on a live web dashboard
and are saved to SQLite.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/dashboard-dark.jpg">
  <img alt="Dashboard showing totals, a timeline of successful and failed logins, top attacking IPs and targeted usernames, and three alerts from the sample log" src="docs/dashboard-light.jpg">
</picture>

## Features

- **Detection rules mapped to MITRE ATT&CK.** Stateful sliding-window rules with
  per-rule thresholds, alert throttling, and severity levels (see
  [Detection rules](#detection-rules)).
- **Configurable.** Tune or disable rules in a YAML file. Misspelled settings and
  invalid values are reported as errors instead of being silently ignored.
- **Persistent alert history.** Alerts are stored in SQLite, and storing the same
  alert twice has no effect, so restarts and re-scans never create duplicates.
- **Robust log parsing.** Handles password, public-key and keyboard-interactive logins,
  probes for nonexistent users, IPv4 and IPv6 sources, both classic syslog and RFC 3339
  timestamps, rsyslog's `message repeated N times` compression, and the `sshd-session`
  process name used by OpenSSH 9.8+.
- **Rotation-safe tailing.** Follows the log like `tail -F`: survives logrotate's
  truncation and file replacement, and never emits half-written lines.
- **Live dashboard.** Totals, a timeline of successful and failed logins, top
  attacking IPs and targeted usernames, filterable alerts and recent events, updated
  over WebSockets (Flask + Socket.IO) as the log grows. Charts are plain SVG with a
  table view, in light and dark themes.
- **REST API.** Read-only JSON endpoints for the summary, timeline, alerts and events
  (see [REST API](#rest-api)).
- **Command line.** `summary`, `detect`, `watch` and `serve` commands.
- **Safe handling of hostile input.** Log contents are attacker-controlled, so the
  parser, terminal output and dashboard are all built so that input can't spoof,
  inject into or hide anything.

## Quick start

```bash
git clone https://github.com/oabukhalaf/cyber-alert-system.git
cd cyber-alert-system
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

Run detection on the bundled sample log, a day on a server with a brute-force burst,
a password spray, and a successful login right after a run of failures:

```bash
cyber-alert detect
```

```text
2026-09-27 10:31:24  ALERT  MEDIUM    T1110.001  SSH brute force from 203.0.113.45
                     6 failed logins for root in 9s
2026-09-27 13:05:18  ALERT  MEDIUM    T1110.003  Password spray from 198.51.100.23
                     5 different usernames tried in 16s
2026-09-27 16:48:25  ALERT  CRITICAL  T1110      Login as deploy from 192.0.2.77 after repeated failures
                     Accepted password login followed 4 failed logins in 15s; the account's credentials may be compromised

3 alerts: 1 critical, 2 medium
```

`cyber-alert summary` prints login statistics for the same file. To start the
dashboard, run the following and open <http://127.0.0.1:5000>:

```bash
cyber-alert serve
```

The dashboard updates within about two seconds as lines are appended to the log.

## Detection rules

| Rule | ATT&CK technique | Severity | Fires when (defaults) |
|---|---|---|---|
| `ssh-brute-force` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing | Medium | One IP fails 5+ times for the **same username** within 1 minute |
| `ssh-password-spray` | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying | Medium | One IP tries 5+ **different usernames** within 5 minutes |
| `ssh-login-after-failures` | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Critical | A login **succeeds** from an IP with 3+ failed logins in the previous 10 minutes |

A sustained attack produces one alert, not one per log line. To change thresholds or
turn rules off, edit [`config/rules.yaml`](config/rules.yaml) and pass it with `--rules`:

```yaml
rules:
  ssh-brute-force:
    threshold: 10
    window: 2m        # durations accept s, m, h, d
  ssh-password-spray:
    enabled: false
```

Rules left out of the file keep their defaults.

## Usage

```text
cyber-alert summary [LOG] [--top N]
    Login statistics for a log file
cyber-alert detect  [LOG] [--rules FILE] [--db FILE]
    Run detection rules over a log file
cyber-alert watch   [LOG] [--rules FILE] [--db FILE] [--alerts-only] [--from-start]
    Print events and alerts as they're logged
cyber-alert serve   [LOG] [--rules FILE] [--db FILE] [--host H] [--port P] [--debug]
    Run the web dashboard
```

- `LOG` defaults to `$CYBER_ALERT_LOG_FILE`, or `logs/sample_auth.log` if that's unset.
- `--db` saves alerts to a SQLite database. `serve` always keeps alert history, in
  `cyber-alert.db` unless `--db` says otherwise. When it starts, it processes the whole
  existing log, so activity that happened while it was down still raises alerts.
- The dashboard binds to `127.0.0.1` by default. It has no login of its own, so to reach
  it from another machine, put it behind a reverse proxy that handles authentication
  rather than binding it to a public `--host`. `--debug` turns on Flask's interactive
  debugger, which allows code execution; use it only locally.

To monitor a real server (reading auth logs usually requires root or the `adm` group):

```bash
sudo .venv/bin/cyber-alert watch /var/log/auth.log --alerts-only --db alerts.db
```

## REST API

`cyber-alert serve` also exposes read-only JSON endpoints, which the dashboard is built on:

| Endpoint | Returns | Query parameters |
|---|---|---|
| `GET /api/summary` | Totals, top failed-login sources and usernames, alert counts by severity | `top` (default 10) |
| `GET /api/timeline` | Successful and failed logins per time bucket | `bucket`: `auto` (default), or a duration such as `15m`, `1h` |
| `GET /api/alerts` | Stored alerts, newest first | `severity` (minimum), `rule`, `source_ip`, `limit` (default 100) |
| `GET /api/events` | The most recent auth events, newest first | `limit` (default 100) |

```bash
curl "http://127.0.0.1:5000/api/alerts?severity=critical"
```

Limits accept 1–500. Invalid parameters return HTTP 400 with a JSON `error` message.

## Project structure

```text
src/cyber_alert/
    parser.py      Log lines -> structured AuthEvent objects
    tailer.py      Rotation-safe incremental file reader
    detection.py   Rule base class, sliding windows, throttling, detector
    rules/         Detection rules, one per file
    alerts.py      Alert model, severities, ATT&CK techniques
    config.py      YAML rule configuration and validation
    store.py       SQLite alert history
    stats.py       Running totals and the login timeline
    monitor.py     Live state the dashboard reads: detection, stats, recent events
    cli.py         `cyber-alert` command
    web.py         Flask app factory, security headers, Socket.IO event stream
    api.py         JSON API
    templates/     Dashboard page
    static/        Dashboard JavaScript and CSS
config/rules.yaml  Rule settings (the built-in defaults)
tests/             pytest suite
logs/              Sample auth log
docs/              Screenshots
```

## Design notes

### Detection

- **Time comes from the log, not the clock.** Rules measure windows using event
  timestamps, so replaying a log file raises exactly the alerts that watching it live
  would have. This keeps detection deterministic and makes every rule testable with
  synthetic events.
- **Group by what defines the attack.** Brute force groups failures by source IP *and*
  username, and spraying counts distinct usernames per IP. Grouping brute force by IP
  alone would also flag every password spray, with the wrong technique.
- **Throttle, don't flood.** The brute-force and spray rules alert at most once per
  attacker per window, and the login rule forgets the failures it has already reported.
  Otherwise one attack of thousands of attempts would bury the alert that matters.
- **Bounded memory.** Sliding windows evict old events and periodically drop sources
  that have gone quiet, so an attacker rotating through many IPs can't grow memory
  without bound.
- **Idempotent storage.** Because rules are deterministic, re-reading a log recreates
  identical alerts, and a `UNIQUE (rule_id, source_ip, first_seen)` constraint makes
  storing one again a no-op.

### Parsing and output

- **The username can't spoof the source IP.** Usernames in failed-login lines are
  chosen by the attacker, so a username like `x from 6.6.6.6 port 22` could trick a
  naive regex into blaming the wrong address. The parser anchors on the *last*
  `from <ip> port <n>` on the line, which is the part sshd itself appends.
- **Collapsed repeats count.** rsyslog can replace identical lines with
  `message repeated 5 times: [...]`. Counting that line once would undercount a
  brute-force attack by the very attempts that matter most.
- **Byte offsets, not line diffing.** The tailer remembers how far into the file it
  has read and uses the file's identity (device and inode) to spot rotation. It reopens
  the file on each poll so it never blocks rotation, including on Windows, where an open
  file can't be renamed.
- **Escape on output.** In the terminal, control characters in usernames are shown as
  `\x1b`, so a username can't inject ANSI escape sequences.
- **Year inference.** Classic syslog timestamps have no year. Events are assigned the
  most recent year that doesn't put them in the future, so logs spanning New Year parse
  correctly.

### Dashboard

- **Defense in depth against XSS.** Log text reaches the page only through
  `textContent`, never `innerHTML`. All scripts and styles are served as files, so a
  Content-Security-Policy can forbid inline code entirely: even if escaping were
  missed somewhere, an injected `<script>` or `onerror=` handler wouldn't run.
- **Statistics are kept live, not recomputed.** The log watcher updates running
  totals and a per-minute timeline as events arrive, under a lock that keeps the
  dashboard's reads consistent. The timeline regroups per-minute counts into whatever
  bucket size fits the time span.
- **Coalesced refreshes.** A burst of log lines produces one dashboard refresh per
  second, not one per line. If the Socket.IO client can't load, the page falls back
  to polling.
- **No chart library.** The charts are drawn as SVG and HTML, which keeps third-party
  scripts to one (Socket.IO). Chart colors were checked for colorblind separation
  and contrast in both themes, and the timeline has a table view for screen readers.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=cyber_alert     # tests with coverage
ruff check . && ruff format --check .
```

CI runs linting and the test suite on Python 3.10–3.14 on Linux, plus Windows.

To add a rule, subclass `Rule` in a new file under `src/cyber_alert/rules/`, register it
in `ALL_RULES`, and add its defaults to `config/rules.yaml`. A test checks that the
config file stays in sync with every rule's defaults.

## Roadmap

- [x] Shared parser, rotation-safe tailer, CLI, unified dashboard, tests and CI
- [x] Detection engine with brute-force, password-spray and login-after-failures rules
      mapped to MITRE ATT&CK
- [x] YAML rule configuration and persistent alert storage (SQLite)
- [x] Live dashboard with charts and alert filtering, and a REST API
- [ ] Alert notifications (Slack, Discord, email)
- [ ] Docker image and an attack simulator for demos

## License

[MIT](LICENSE)
