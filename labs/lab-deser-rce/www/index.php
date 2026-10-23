<?php
// A "logging framework" with a dangerous gadget class
// The class exists in memory on every request — autoloaded

class LogRotator {
    public $logfile;
    public $archive_cmd;

    public function __construct($logfile = '/var/log/app.log') {
        $this->logfile = $logfile;
        $this->archive_cmd = "gzip {$logfile}.old";
    }

    public function rotate() {
        if (file_exists($this->logfile)) {
            rename($this->logfile, $this->logfile . '.old');
            system($this->archive_cmd);
        }
    }

    // Gadget: __destruct calls system() with attacker-controlled input
    public function __destruct() {
        // "Cleanup" — runs the archive command when object is destroyed
        if ($this->archive_cmd && $this->logfile) {
            // Developer thought: "just archive on shutdown, what could go wrong?"
            @system($this->archive_cmd);
        }
    }
}

// Normal app — session-based visit counter
session_start();
if (!isset($_SESSION['visits'])) {
    $_SESSION['visits'] = 0;
}
$_SESSION['visits']++;
?>
<!DOCTYPE html>
<html>
<head><title>LogApp v2.3</title></head>
<body>
<h1>LogApp Dashboard</h1>
<p>Visit #<?= $_SESSION['visits'] ?></p>
<p>Upload a log file for analysis:</p>
<form method="POST" enctype="multipart/form-data" action="upload.php">
    <input type="file" name="logfile">
    <button type="submit">Analyze</button>
</form>
<p style="color:#999;font-size:11px">
  PHP <?= phpversion() ?> | <?= php_sapi_name() ?> |
  session.serialize_handler = <?= ini_get('session.serialize_handler') ?>
</p>
</body>
</html>
