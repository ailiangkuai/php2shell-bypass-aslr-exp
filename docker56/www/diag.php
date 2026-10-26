<?php
// 靶场标定页：仅用于测量 post_max_size / client_max_body_size 闸门的位置。
// 线上不存在这样的页面，因此正式探针（probe6_prod.py）在缺少本页时会
// 自动降级为纯状态码判定；本页只服务于"参数配比如何决定可达性"的实验。
//
// 注意：PHP 5.6 不支持 ?? 运算符（7.0 才有），这里一律用 isset()。
header('Content-Type: text/plain');

echo "pid=" . getmypid() . "\n";
echo "content_length=" . (isset($_SERVER['CONTENT_LENGTH']) ? $_SERVER['CONTENT_LENGTH'] : '') . "\n";
echo "method=" . (isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '') . "\n";
echo "post_count=" . count($_POST) . "\n";
echo "files_count=" . count($_FILES) . "\n";

$maxlen = 0;
foreach ($_POST as $v) {
    if (is_string($v) && strlen($v) > $maxlen) {
        $maxlen = strlen($v);
    }
}
echo "post_max_value_len=" . $maxlen . "\n";

$keys = array('memory_limit', 'post_max_size', 'upload_max_filesize',
              'max_input_vars', 'max_file_uploads', 'display_errors',
              'session.upload_progress.enabled');
foreach ($keys as $k) {
    echo "ini." . $k . "=" . ini_get($k) . "\n";
}
