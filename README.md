# Cyber Alert System

[![CI](https://github.com/oabukhalaf/cyber-alert-system/actions/workflows/ci.yml/badge.svg)](https://github.com/oabukhalaf/cyber-alert-system/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A tool for monitoring SSH authentication logs. It parses OpenSSH entries in Linux
auth logs (`/var/log/auth.log`, `/var/log/secure`), follows the log as it's written,
and shows login activity in a terminal or a live web dashboard.

## Features

- **Robust log parsing.** Handles password, public-key and keyboard-interactive logins,
  probes for nonexistent users, IPv4 and IPv6 sources, both classic syslog and RFC 3339
  timestamps, rsyslog's `message repeated N times` compression, and the `sshd-session`
  process name used by OpenSSH 9.8+.
- **Rotation-safe tailing.** Follows the log like `tail -F`: survives logrotate's
  truncation and file replacement, and never emits half-written lines.
- **Command line.** `summary` for statistics, `watch` to stream events as they happen.
- **Web dashboard.** A summary page plus a live feed pushed over WebSockets
  (Flask + Socket.IO).
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

Try it on the bundled sample log, a day on a server that includes a brute-force burst,
a username spray, and a successful login right after a run of failures:

```bash
cyber-alert summary
```

```text
Summary of logs/sample_auth.log
  38 auth events from 2026-09-27 08:02:11 to 2026-09-27 16:48:25
  26 failed, 5 successful

Failed logins by source IP
  198.51.100.23                     10
  203.0.113.45                       9
  192.0.2.77                         4
  2001:db8:85a3::8a2e:370:7334       2
  10.0.4.35                          1
...
```

Then start the dashboard and open <http://127.0.0.1:5000>:

```bash
cyber-alert serve
```

The live feed at `/live` shows new events as they're appended to the log file.

## Usage

```text
cyber-alert summary [LOG] [--top N]           Login statistics for a log file
cyber-alert watch   [LOG] [--from-start]      Print events as they're logged
cyber-alert serve   [LOG] [--host H] [--port P] [--debug]
                                              Run the web dashboard
```

`LOG` defaults to `$CYBER_ALERT_LOG_FILE`, or `logs/sample_auth.log` if that's unset.
To monitor a real server (reading auth logs usually requires root or the `adm` group):

```bash
sudo .venv/bin/cyber-alert watch /var/log/auth.log
```

The dashboard binds to `127.0.0.1` by default. `--debug` turns on Flask's
interactive debugger, which allows code execution, so never combine it with a
public `--host`.

## Project structure

```text
src/cyber_alert/
    parser.py      Log lines -> structured AuthEvent objects
    tailer.py      Rotation-safe incremental file reader
    stats.py       Aggregate counts for the summary views
    cli.py         `cyber-alert` command
    web.py         Flask app factory and Socket.IO event stream
    templates/     Dashboard pages
tests/             pytest suite
logs/              Sample auth log
```

## Design notes

- **The username can't spoof the source IP.** Usernames in failed-login lines are
  chosen by the attacker, so a username like `x from 6.6.6.6 port 22` could trick a
  naive regex into blaming the wrong address. The parser anchors on the *last*
  `from <ip> port <n>` on the line, which is the part sshd itself appends.
- **Byte offsets, not line diffing.** The tailer remembers how far into the file it
  has read and uses the file's identity (device and inode) to spot rotation. It reopens
  the file on each poll so it never blocks rotation, including on Windows, where an open
  file can't be renamed.
- **Collapsed repeats count.** rsyslog can replace identical lines with
  `message repeated 5 times: [...]`. Ignoring that would undercount a brute-force attack
  by the very attempts that matter most.
- **Escape on output.** Usernames are escaped in HTML (Jinja autoescaping, `textContent`
  in the live feed) and in the terminal, where control characters are shown as `\x1b`
  so a username can't inject ANSI escape sequences.
- **Year inference.** Classic syslog timestamps have no year. Events are assigned the
  most recent year that doesn't put them in the future, so logs spanning New Year parse
  correctly.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=cyber_alert     # tests with coverage
ruff check . && ruff format --check .
```

CI runs linting and the test suite on Python 3.10–3.14 on Linux, plus Windows.

## Roadmap

- [x] Shared parser, rotation-safe tailer, CLI, unified dashboard, tests and CI
- [ ] Detection engine: sliding-window rules for brute force, password spraying,
      username enumeration, and successful logins after repeated failures, mapped to
      MITRE ATT&CK techniques
- [ ] YAML rule configuration and persistent alert storage (SQLite)
- [ ] Alert notifications (Slack, Discord, email)
- [ ] Docker image and an attack simulator for demos

## License

[MIT](LICENSE)
