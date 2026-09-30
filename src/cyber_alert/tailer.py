"""Follow a log file as it grows, the way ``tail -F`` does."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from pathlib import Path


class LogTailer:
    """Incrementally read complete lines appended to a log file.

    Survives the two things logrotate does to a file: truncating it in place
    (``copytruncate``) and moving it aside so a new file takes its place. The file
    is reopened on every poll rather than held open, so we never block rotation
    (Windows refuses to rename a file another process has open).

    Like any polling tailer, it can't see what happens between polls: lines
    appended to a file just before it's rotated are missed, and a truncated file
    that grows past our old offset before the next poll isn't recognized as
    truncated. Keep the poll interval short relative to how often logs rotate.
    """

    def __init__(self, path: str | Path, *, from_start: bool = False, encoding: str = "utf-8"):
        self.path = Path(path)
        self.encoding = encoding
        self._file_id: tuple[int, int] | None = None
        self._offset = 0
        self._partial = b""
        if not from_start:
            try:
                stat = self.path.stat()
            except FileNotFoundError:
                pass  # Anything written once the file appears is new.
            else:
                self._file_id = (stat.st_dev, stat.st_ino)
                self._offset = stat.st_size

    def poll(self) -> list[str]:
        """Return the complete lines written since the last poll."""
        try:
            f = self.path.open("rb")
        except FileNotFoundError:
            return []
        with f:
            stat = os.fstat(f.fileno())
            file_id = (stat.st_dev, stat.st_ino)
            if file_id != self._file_id or stat.st_size < self._offset:
                # A different file now lives at this path, or this one was truncated.
                self._file_id, self._offset, self._partial = file_id, 0, b""
            f.seek(self._offset)
            chunk = f.read()
        self._offset += len(chunk)

        # Offsets are tracked in bytes, so decode only once a line is complete; a
        # line still being written is held back until its newline arrives.
        *lines, self._partial = (self._partial + chunk).split(b"\n")
        return [line.rstrip(b"\r").decode(self.encoding, errors="replace") for line in lines]


def follow(
    path: str | Path,
    *,
    from_start: bool = False,
    poll_interval: float = 1.0,
    stop: threading.Event | None = None,
) -> Iterator[str]:
    """Yield lines from ``path`` as they're written, until ``stop`` is set."""
    tailer = LogTailer(path, from_start=from_start)
    stop = stop or threading.Event()
    while not stop.is_set():
        yield from tailer.poll()
        stop.wait(poll_interval)
