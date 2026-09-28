import threading

from cyber_alert.tailer import LogTailer, follow


def append(path, data: str | bytes) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    with path.open("ab") as f:
        f.write(data)


def test_starts_at_end_of_existing_file_by_default(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "old\n")
    tailer = LogTailer(log)

    assert tailer.poll() == []
    append(log, "new\n")
    assert tailer.poll() == ["new"]
    assert tailer.poll() == []


def test_from_start_replays_existing_lines(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "one\ntwo\n")

    assert LogTailer(log, from_start=True).poll() == ["one", "two"]


def test_partial_line_is_held_until_complete(tmp_path):
    log = tmp_path / "auth.log"
    log.touch()
    tailer = LogTailer(log)

    append(log, "half a li")
    assert tailer.poll() == []
    append(log, "ne\nnext\n")
    assert tailer.poll() == ["half a line", "next"]


def test_truncated_file_is_reread_from_the_top(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "first line\nsecond line\n")
    tailer = LogTailer(log, from_start=True)
    tailer.poll()

    log.write_bytes(b"short\n")  # truncated in place, then shorter than what we'd read

    assert tailer.poll() == ["short"]


def test_rotated_file_is_followed(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "before\n")
    tailer = LogTailer(log, from_start=True)
    tailer.poll()

    log.rename(tmp_path / "auth.log.1")
    # Longer than the old file, so only the file-identity check can detect the switch.
    append(log, "after rotation\nand more\n")

    assert tailer.poll() == ["after rotation", "and more"]


def test_missing_file_is_picked_up_once_created(tmp_path):
    log = tmp_path / "auth.log"
    tailer = LogTailer(log)

    assert tailer.poll() == []
    append(log, "hello\n")
    assert tailer.poll() == ["hello"]


def test_crlf_and_invalid_utf8(tmp_path):
    log = tmp_path / "auth.log"
    log.touch()
    tailer = LogTailer(log)

    append(log, b"caf\xe9\r\n")

    assert tailer.poll() == ["caf�"]


def test_follow_stops_when_event_is_set(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "line\n")
    stop = threading.Event()
    lines = follow(log, from_start=True, poll_interval=0.01, stop=stop)

    assert next(lines) == "line"
    stop.set()
    assert list(lines) == []
