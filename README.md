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
- **Notifications.** Sends alerts to Slack, Discord, email or any webhook, with
  retries, per-channel severity thresholds, and escaping so attacker-chosen usernames
  can't ping a channel or inject email headers (see [Notifications](#notifications)).
- **Configurable.** Tune rules and notifications in one YAML file, with secrets kept
  in environment variables. Misspelled settings and invalid values are reported as
  errors instead of being silently ignored.
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
- **Attack simulator and Docker.** `docker compose up` runs the dashboard against
  simulated brute-force, password-spray and break-in attacks, and CI does the same
  end to end (see [Docker](#docker)).
- **Command line.** `summary`, `detect`, `watch`, `serve`, `simulate` and
  `test-notifications` commands.
- **Safe handling of hostile input.** Log contents are attacker-controlled, so the
  parser, terminal output and dashboard are all built so that input can't spoof,
  inject into or hide anything.

## Quick start

The fastest way to see it work is Docker, which starts the dashboard alongside a
simulator that stages attacks against it:

```bash
git clone https://github.com/oabukhalaf/cyber-alert-system.git
cd cyber-alert-system
docker compose up --build
```

Then open <http://127.0.0.1:5000>; alerts appear within a minute. To install it
directly instead:

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
turn rules off, edit [`config/cyber-alert.yaml`](config/cyber-alert.yaml) and pass it
with `--config` (or set `$CYBER_ALERT_CONFIG`):

```yaml
rules:
  ssh-brute-force:
    threshold: 10
    window: 2m        # durations accept s, m, h, d
  ssh-password-spray:
    enabled: false
```

Rules left out of the file keep their defaults.

## Notifications

`serve` and `watch` can send alerts as they're raised. Add channels to the
`notifications` section of the config file:

```yaml
notifications:
  min_severity: high      # default; low, medium, high or critical
  max_age: 1h             # alerts about older activity are stored but not sent
  channels:
    - type: slack
      webhook_url: ${SLACK_WEBHOOK_URL}
    - type: discord
      webhook_url: ${DISCORD_WEBHOOK_URL}
      min_severity: critical
    - type: email
      smtp_host: smtp.example.com
      username: ${SMTP_USERNAME}
      password: ${SMTP_PASSWORD}
      from: alerts@example.com
      to: [oncall@example.com]
    - type: webhook       # POSTs {"source": "cyber-alert", "alert": {...}} as JSON
      url: https://example.com/hooks/cyber-alert
      headers:
        Authorization: Bearer ${WEBHOOK_TOKEN}
```

`${NAME}` is replaced with the environment variable `NAME` when the file is loaded,
so secrets stay out of the file. Then check that every channel works:

```bash
cyber-alert test-notifications --config config/cyber-alert.yaml
```

- **Only new alerts are sent.** With a database, alerts already stored (for example,
  after a restart) aren't sent again.
- **No floods from history.** `max_age` keeps a first run over an old log from
  sending days of alerts at once.
- **Delivery never slows detection.** Alerts are sent from a background thread with a
  10-second timeout and up to 3 attempts, backing off between them (and honoring
  `Retry-After` when rate-limited). Errors that retrying can't fix, such as a rejected
  webhook URL, aren't retried.
- Webhook URLs must use `https://` (plain `http://` is allowed only to `localhost`),
  and log messages identify channels by host only, never by their secret URL.

## Usage

```text
cyber-alert summary [LOG] [--top N]
    Login statistics for a log file
cyber-alert simulate LOG [--speed X] [--duration SECONDS] [--seed N]
    Append simulated SSH traffic, attacks included, to a log file
cyber-alert detect  [LOG] [--config FILE] [--db FILE]
    Run detection rules over a log file
cyber-alert watch   [LOG] [--config FILE] [--db FILE] [--alerts-only] [--from-start]
    Print events and alerts as they're logged, and send notifications
cyber-alert serve   [LOG] [--config FILE] [--db FILE] [--host H] [--port P] [--debug]
    Run the web dashboard, and send notifications
cyber-alert test-notifications [--config FILE]
    Send a test alert to every configured notification channel
```

- `LOG` defaults to `$CYBER_ALERT_LOG_FILE`, or `logs/sample_auth.log` if that's unset.
  `--config` defaults to `$CYBER_ALERT_CONFIG`, or built-in settings if that's unset.
- `--db` saves alerts to a SQLite database. `serve` always keeps alert history, in
  `cyber-alert.db` unless `--db` says otherwise. When it starts, it processes the whole
  existing log, so activity that happened while it was down still raises alerts.
- The dashboard binds to `127.0.0.1` by default. It has no login of its own, so to reach
  it from another machine, put it behind a reverse proxy that handles authentication
  rather than binding it to a public `--host`. `--debug` turns on Flask's interactive
  debugger, which allows code execution; use it only locally.

To monitor a real server (reading auth logs usually requires root or the `adm` group):

```bash
sudo .venv/bin/cyber-alert watch /var/log/auth.log --alerts-only \
    --db alerts.db --config config/cyber-alert.yaml
```

To generate traffic to watch, `simulate` appends realistic sshd lines in real time:
staff logins with occasional mistyped passwords, and every so often a brute force,
a password spray or a break-in. Attackers use reserved documentation IP ranges.

```bash
cyber-alert simulate demo.log --speed 5      # in one terminal
cyber-alert serve demo.log                   # in another
```

`--speed` scales time, `--duration SECONDS` stops after that much simulated time, and
`--seed` makes the traffic repeatable.

## Docker

```bash
docker compose up --build
```

This starts the dashboard at <http://127.0.0.1:5000> together with the simulator, so
alerts appear within a minute. Set `SIMULATOR_SPEED=5` to speed things up. The image
runs as an unprivileged user, keeps alert history in a volume, and has a health
check. The port is published on `127.0.0.1` only, because the dashboard has no login.

To monitor a real server instead, run only the dashboard and give it the host's logs.
Mount the log *directory* rather than the file: logrotate replaces the file, and a
single-file mount would keep pointing at the old one.

```yaml
# compose.override.yaml
services:
  dashboard:
    volumes:
      - /var/log:/host-logs:ro
      - ./my-config.yaml:/etc/cyber-alert/cyber-alert.yaml:ro
    environment:
      CYBER_ALERT_LOG_FILE: /host-logs/auth.log
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL}
    group_add:
      - "4"   # the host's adm group (Debian/Ubuntu), which can read auth.log
```

```bash
docker compose up --build --detach dashboard
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
    notify.py      Slack, Discord, email and webhook notifications
    config.py      YAML configuration and validation
    store.py       SQLite alert history
    stats.py       Running totals and the login timeline
    monitor.py     Live state the dashboard reads: detection, stats, recent events
    cli.py         `cyber-alert` command
    simulate.py    Realistic SSH traffic generator for demos and tests
    text.py        Safe display of attacker-controlled text
    web.py         Flask app factory, security headers, Socket.IO event stream
    api.py         JSON API
    templates/     Dashboard page
    static/        Dashboard JavaScript and CSS
config/            Example config file (rule defaults and notification examples)
tests/             pytest suite
logs/              Sample auth log
docs/              Screenshots
Dockerfile         Two-stage image build, non-root
compose.yaml       Dashboard plus simulator demo
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
- **A successful login ends a run of failures.** Both failure-counting rules reset when
  the user gets in, so someone who mistypes a password now and then never looks like
  an attacker, while guessing that *does* succeed is caught as a critical
  login-after-failures alert. The attack simulator found both of these false
  positives, and a test now runs it at 10x speed to keep them from coming back.
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
- **Escape for every destination.** Each output escapes usernames for its own syntax:
  - Terminal: control characters are shown as `\x1b`, so a username can't inject ANSI
    escape sequences.
  - Slack: `&`, `<` and `>` are escaped, so a username like `<!channel>` can't ping a
    whole workspace or hide a link.
  - Discord: Markdown is escaped and mentions are disabled.
  - Email: line breaks are escaped, so a username can't add headers such as `Bcc:`.
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

CI runs linting and the test suite on Python 3.10–3.14 on Linux, plus Windows. An
end-to-end job builds the Docker image, runs it against the attack simulator, and
fails unless every alert type is raised.

To add a rule, subclass `Rule` in a new file under `src/cyber_alert/rules/`, register it
in `ALL_RULES`, and add its defaults to `config/cyber-alert.yaml`. A test checks that the
config file stays in sync with every rule's defaults.

## Roadmap

- [x] Shared parser, rotation-safe tailer, CLI, unified dashboard, tests and CI
- [x] Detection engine with brute-force, password-spray and login-after-failures rules
      mapped to MITRE ATT&CK
- [x] YAML rule configuration and persistent alert storage (SQLite)
- [x] Live dashboard with charts and alert filtering, and a REST API
- [x] Alert notifications (Slack, Discord, email, webhooks)
- [x] Docker image and an attack simulator for demos
- [ ] GeoIP and ASN enrichment for source addresses
- [ ] More log sources (web server and VPN authentication logs)
- [ ] Optional automatic blocking of attacking addresses, as fail2ban does

## License

[MIT](LICENSE)
