# php2shell 56 — PHP 5.6.40 + nginx (php-fpm) 生产参数攻击测试

本目录是一个 **生产参数靶场**：`php:5.6.40-fpm` 镜像，ini/pool 换成生产常态
（`memory_limit=128M > post_max_size=8M`、多 worker + 回收），用于验证
"线上 php5.6.40 + nginx 是否受 2026-10-21 公告影响"。

## 关键约束：不攻击 fpm 端口

生产环境 FPM 的 9000 端口从不对外暴露（只监听容器内网供 nginx `fastcgi_pass`）。
因此本靶场 **刻意不映射 9000**，所有测试流量只走 nginx 入口 `127.0.0.1:8091`。
直连 9000 测出来的"可达性"在生产里没有对应路径，没有意义。

## 环境说明

| 组件 | 版本/配置 | 说明 |
|---|---|---|
| PHP | 5.6.40（fpm-fcgi） | `php:5.6.40-fpm` |
| nginx | 1.27（alpine） | 反代 `fpm:9000`，宿主机 `127.0.0.1:8091` |
| fpm 暴露面 | 无（不映射端口） | 仅容器内网 9000，供 nginx `fastcgi_pass` |
| memory_limit / post_max_size | 128M / 8M | 生产常态，`memory_limit > post_max_size` |
| worker 模型 | 多 worker（5）+ `pm.max_requests=500` | [pool.conf](pool.conf) |
| display_errors | Off | 生产常态，错误不外泄 |

关键文件：

- [docker-compose.yml](docker-compose.yml) — 编排（fpm 无端口映射）
- [php.ini](php.ini) — 生产参数
- [pool.conf](pool.conf) — 多 worker + 回收
- [nginx-site.conf](nginx-site.conf) — `client_max_body_size 32m`
- [www/index.php](www/index.php) — worker PID 回显（靶场特权页，线上无）
- [www/diag.php](www/diag.php) — 配置/闸门标定页（靶场特权页，线上无）

## 操作流程

```bash
# 1) 起生产参数靶场（fpm 无端口映射，只有 nginx 8091）
docker compose -f docker56/docker-compose.yml up -d

# 2) 确认唯一入口是 nginx，且 fpm 无对外端口
curl -s http://127.0.0.1:8091/index.php        # 期望: pid=<n> ok
docker port php56-fpm                            # 期望: 空（无任何端口映射）

# 3) 跑窗口1 验证探针（只经 nginx，默认 3 轮）
python tools56/probe6_prod.py --rounds 3

# 可选：模拟线上拿不到 PID 的判定（纯状态码）
python tools56/probe6_prod.py --rounds 3 --no-pid
```

## 怎样判断"被攻破"

probe6 会向靶场发一个 `Content-Length` 超过 `post_max_size` 的 multipart 攻击请求
（含 `PHP_SESSION_UPLOAD_PROGRESS` + 文件字段 + 大字段，与公告窗口1 的 A 请求同构）。
判定只看**这个攻击请求自身的响应状态码**：

| 攻击请求响应 | 含义 | 结论 |
|---|---|---|
| **200**，body 正常 `pid=.. ok` | `post_max_size` 在 rfc1867.c:715 于 FILE_START 之前拦截，multipart 解析未开始，OOM 未触发，worker 存活 | **未被攻破（窗口1 闭合）** |
| **502 / 504** | 解析期 OOM 把 worker 打死（`exit(70)`），nginx 拿不到响应 | **被攻破（窗口1 打开）** |

辅助信号（仅靶场可见，生产拿不到，不构成攻击路径）：

- worker PID 变化（多 worker 下不可靠，只作辅助）；
- `docker logs php56-fpm` 出现 `child N exited with code 70`。

**"被攻破"的两层含义**：

1. **DoS 层（本测试可直接观测）**：攻击请求能远程打死 worker（502 / exit 70）。这表示你的 `post_max_size` 配得过大（能容纳攻击 body 且 ≥ memory_limit），解析期 OOM 窗口被打开，攻击者可反复请求让 worker 崩溃重启、造成服务抖动。**这是本测试判定"被攻破"的直接信号。**
2. **RCE 层（公告完整链）**：需要 worker 死亡后残留状态被下一请求消费。5.6 FPM 下多 worker + `max_requests` 回收 + 解析期 OOM 直接杀 worker，跨请求残留结构上不成立，不会走到这一步。

## 参数配比决定可达性（翻转实验）

把 [php.ini](php.ini) 的 `memory_limit`/`post_max_size` 两个数字对调（8M/64M）再重测，
probe6 会从 `200/存活` 翻转为 `502/exit 70`——证明"是否被攻破"由这两个参数的相对大小决定，
与 PHP 5.6.40 版本号无关。

一句话验收：**攻击请求一直 200 = 你的 `post_max_size` 挡住了它，未被攻破；出现 502/504 = `post_max_size` 没挡住，窗口1 被打开，被攻破（DoS 层）。**

## 线上自查清单（按优先级）

1. `memory_limit` vs `post_max_size`（决定性）：只要 `memory_limit > post_max_size`，窗口1 就不可达。
2. `upload_max_filesize`：上传文件单字段上限，通常 `< post_max_size`，进一步缩小面。
3. `session.upload_progress.enabled`：若为 `Off`，公告链的 session 面整体不存在。
4. nginx `client_max_body_size`：第一道硬闸，默认 1m 会先把超限流量挡在 413。
5. `display_errors`：生产应为 `Off`，此时判据只能靠状态码（200 vs 502）。
6. `pm.max_children` / `pm.max_requests`：多 worker + 回收使跨请求 producer/consumer 无法落在同一进程上。

## 复现声明

- 本测试只经 nginx 入口，不攻击 fpm 端口，模拟生产"fpm 端口不外露"的真实前提。
- 仅用于授权环境中的漏洞研究与复现。
