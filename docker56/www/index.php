<?php
// 生产镜像页：唯一的"特权"是回显 worker PID。
// 真实线上拿不到 PID，探针用状态码降级判定（见 tools56/probe6_prod.py）。
echo "pid=" . getmypid() . " ok";
