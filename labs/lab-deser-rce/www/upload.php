<?php
require_once 'index.php';
if ($_FILES['logfile'] ?? false) {
    echo "<p>Received: " . htmlspecialchars($_FILES['logfile']['name']) . "</p>";
    echo "<p>Size: " . $_FILES['logfile']['size'] . " bytes</p>";
}
