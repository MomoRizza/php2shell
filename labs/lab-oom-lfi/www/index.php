<?php
$page = $_GET['page'] ?? null;

if ($page) {
    // Developer's "sanitization": only allow safe chars
    // (forgot about absolute paths and path traversal)
    if (preg_match('#^[a-zA-Z0-9_/.\-]+$#', $page)) {
        include($page);
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>NoviCMS v0.1</title></head>
<body>
<h1>NoviCMS</h1>
<nav>
  <a href="?page=home.php">Home</a> |
  <a href="?page=about.php">About</a>
</nav>
<p style="color:#999;font-size:11px">PHP <?= phpversion() ?> | <?= php_sapi_name() ?></p>
</body>
</html>
