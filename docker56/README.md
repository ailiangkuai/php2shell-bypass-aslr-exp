# php2shell 56 — PHP 5.6.40 + nginx (php-fpm) 模式复现

本目录是主 README（PHP 8.4.26 + Apache mod_php 模式）的姊妹篇：目标换成 **php:5.6.40-fpm + nginx 1.27**，利用路径与 8.4 完全不同。实测一条命令 RCE（`id`/`uname` 以 www-data 执行，proof 落盘 `out56/p56`）。

## exp

从零到 RCE 的完整命令，整段复制执行即可（在仓库根目录下）：

```bash
# 依赖：Docker Engine/Desktop + Docker Compose v2 + Python 3.9+（纯标准库，无第三方包）

# 1) 起目标：php-fpm 单 worker + nginx 反代；fpm 的 9000 端口发布到宿主机
#    127.0.0.1:9090（模拟真实世界 "fpm 端口暴露" 的配置失误）
docker compose -f docker56/docker-compose.yml up -d

# 2) 确认两条链路都通
curl -s http://127.0.0.1:8089/index.php          # nginx -> fpm，输出 OK
Test-NetConnection 127.0.0.1 -Port 9090          # Windows；Linux 用 nc -vz 127.0.0.1 9090

# 3) 一条命令完成利用
python3 exploit56.py 127.0.0.1:9090
# [[P56-PROOF-BEGIN]]
# php_version=5.6.40
# sapi=fpm-fcgi
# id=uid=33(www-data) gid=33(www-data) groups=33(www-data)
# uname=Linux ... x86_64 GNU/Linux
# [[P56-PROOF-END]]
# [+] RCE confirmed — proof block received.

# 4) proof 已写回宿主机
cat out56/p56
```

任意 PHP 代码（payload 需自带 `<?php ?>` 标签）：

```bash
python3 exploit56.py 127.0.0.1:9090 -c '<?php system("cat /etc/passwd"); ?>'
```

常用参数：`-f/--file`（容器内真实 PHP 脚本路径，默认 `/var/www/html/index.php`）、`-c/--code`、`--php-value`（默认 `auto_prepend_file = php://input`）、`--php-admin-value`（默认 `allow_url_include = On`）、`--timeout`。

## 机制概览

攻击面是 **FastCGI 直连 + INI 覆盖**，全程不碰内存，ASLR 无关：

1. **暴露面**：`docker-compose.yml` 把 fpm 的 TCP 9000 发布到宿主机（经典失误配置，参考 Shutterstock 等真实事件）。nginx 正常反代下客户端无法注入参数，直连 fpm 才是前提。
2. **注入**：FastCGI 协议允许 FCGI_PARAMS 携带两个 FPM 特殊键：
   - `PHP_VALUE = auto_prepend_file = php://input` — 在执行 SCRIPT_FILENAME 前先 include 请求体；
   - `PHP_ADMIN_VALUE = allow_url_include = On` — 5.6 的 `fpm_php.c` 对 admin 值不做 modifiable 校验，SYSTEM 级 ini 也能覆盖。
3. **执行**：任意 PHP 代码放 FCGI_STDIN（即 POST body），`php://input` 流被当作 PHP 模板解析 → 任意代码执行。
4. `exploit56.py` 自实现 FastCGI 协议客户端（BEGIN_REQUEST → PARAMS → STDIN → 解析 STDOUT/STDERR/END_REQUEST），约 300 行纯标准库。

## 为什么不是 8.4 那条 UAF 链（实证结论）

8.4 exploit 的根基是 Apache worker 在 request startup 阶段 OOM bailout 后**存活**、脏堆被下一请求复用。在 PHP 5.6 FPM 下该前提不成立：

| 对照实验（tools56/probe2_56.py） | 结果 |
|---|---|
| 1001 字段 + upload_progress + 文件上传（无 OOM） | child 存活 |
| 纯 OOM（12MB 字段触发 memory_limit） | **child exit(70)** |
| 完整 A 请求（OOM + session 组合） | **child exit(70)** |
| 1001 字段 + 大字段（无 session） | **child exit(70)** |

结论：任何 startup 阶段 OOM bailout 都会走 `php_request_startup` 返回 FAILURE → `exit(FPM_EXIT_SOFTWARE=70)`，worker 连同脏堆一起销毁，跨请求 UAF 无从谈起。结构性排除，不是标定问题。

其余路径同样排除：

- **CVE-2019-11043**（`fpm_main.c` 下溢 bug）：5.6.40 源码存在该 bug，但公开利用 phuip-fpizdam 依赖 PHP 7 的 `_fcgi_data_seg` 结构；且本 nginx 无 `fastcgi_split_path_info`/PATH_INFO 配置。双重不适用。
- **执行阶段 OOM**（`php_execute_script` 内 bailout 不杀 worker，源码已验证）：理论上 worker 可存活，但靶场页面只有 `echo "OK"`，没有应用侧触发点。
- session 注入无 LFI 消费者、图片马、alias 穿越、PATH_INFO 等均不可行。

## 公告 FPM 路径（CVE-2026-109619）的对照验证 —— 也排除

2026-10-21 公告（GHSA-6wmf-4rv5-p3rp）描述的 FPM 侧利用需"producer/consumer 成对"：应用执行阶段发布全局状态 → fatal/OOM 打断匹配的 reset → 下一请求在正常初始化前消费残留。按此模型搭了验证环境实测（tools56/probe3_56.py，靶场页 [www/gh.php](www/gh.php)）：

| 生产者变体 | OOM 位置 | producer 响应 | child | consumer cookie vs 基线(NORMAL) |
|---|---|---|---|---|
| A：执行阶段 `str_repeat` OOM fatal | `php_execute_script` 内 | 200，OOM fatal，输出已发布 | 存活 | **无差异**（3 轮全 NORMAL） |
| B：`$_SESSION` 持 6MB 活串正常结束，OOM 落在 RSHUTDOWN 的 `ps_write` 序列化 | `php_request_shutdown` 内（`in Unknown on line 0`） | 200，OOM fatal | 存活 | **无差异**（3 轮全 NORMAL） |

负结果的源码解释（php-src PHP-5.6.40 `ext/session/session.c`）：

- 变体 B：`PHP_RSHUTDOWN_FUNCTION(session)` 把 `php_session_flush` 包在 `zend_try` 里（L2414-2416），序列化 OOM bailout 被捕获后仍执行 `php_rshutdown_session_globals`（L2417），`PS(id)`/`PS(http_session_vars)` 被正常置空——8.4 那种"悬空 PS(id)"在 5.6 被 2006 年就存在的 zend_try 防住。
- 变体 A：执行阶段 fatal 后 FPM 的 `php_request_shutdown` 完整跑完模块 RSHUTDOWN（变体 B 的 zend_try 同样覆盖该路径），session 全局态正常重置。

加上公告自己确认的"FPM startup 失败即杀 child"（与 probe2 实证一致），CVE-2026-109619 在 php-5.6-fpm 下三个窗口（startup 发布、执行阶段 fatal、RSHUTDOWN 内 fatal）全部无法留下可消费的残留：**该 CVE 的 FPM 路径在 5.6 结构性不可行，与上游不给 5.6 补丁的事实互恰**。

## 环境说明

| 组件 | 版本 | 来源 |
|---|---|---|
| PHP | 5.6.40（fpm-fcgi） | `php:5.6.40-fpm` |
| nginx | 1.27（alpine） | 反代 `fpm:9000`，宿主机 `127.0.0.1:8089` |
| fpm 暴露面 | 宿主机 `127.0.0.1:9090` → 容器 9000 | [docker-compose.yml](docker-compose.yml) |
| worker 模型 | 单 child、`pm.max_requests=0`（不回收） | [pool.conf](pool.conf) |

`php.ini` 沿用 8.4 lab 的前提条件（display_errors、memory_limit=8M、upload_progress 等），便于对照实验；FastCGI 路径本身不依赖这些配置。

## 复现声明

- **一条命令 RCE**：`python3 exploit56.py 127.0.0.1:9090`，无需偏移标定、无需重试循环、无需 worker 轮换。
- **前提**：攻击者可达 fpm 监听端口（本 lab 通过 compose 端口发布模拟）。若 fpm 仅绑定 unix socket 或端口不可达，本路径不成立，5.6-fpm 下也无其他可行 RCE 路径（见上）。
- **与 8.4 模式的关系**：最终产物相同（以 web 用户执行任意命令），但 8.4 是"应用零漏洞、纯打引擎 bug + 绕 ASLR"，本模式是"真实世界配置失误型攻击面"，两者互补展示同一目标的不同深度。
- 仅用于授权环境中的漏洞研究与复现。
