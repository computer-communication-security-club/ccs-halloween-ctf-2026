<?php
// Router for local previews with `php -S`; Apache uses site.conf instead.
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if (in_array($path, ['/style.css', '/report.js', '/health.txt'], true)) {
    return false;
}
require __DIR__ . '/index.php';
