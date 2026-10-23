<?php
// The LogRotator class must be in memory for PHP to deserialize it
class LogRotator {
    public $logfile;
    public $archive_cmd;
    public function __destruct() {
        if ($this->archive_cmd && $this->logfile) {
            @system($this->archive_cmd);
        }
    }
}

// "Legacy" admin page that was configured with the old session handler
// This creates the handler mismatch: session was WRITTEN with php_serialize
// but this page READS it with the default `php` handler
ini_set('session.serialize_handler', 'php');
session_start();

// The `php` handler splits session data on |
// If the session file contains: a:1:{s:N:"upload_progress_|O:11:"LogRotator"...
// The `php` handler reads key = "a:1:{s:N:"upload_progress_"
// Then tries to unserialize: O:11:"LogRotator":2:{...}
// → creates a LogRotator object → __destruct fires system() at request end

echo "Admin panel loaded. Session data:\n";
echo "<pre>" . htmlspecialchars(print_r($_SESSION, true)) . "</pre>";
