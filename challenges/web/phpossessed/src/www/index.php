<?php
declare(strict_types=1);
require __DIR__ . '/registry.php';
require __DIR__ . '/places.php';

if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
$path = rtrim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/') ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if (preg_match('~^/photo/([a-f0-9]{24}\.(jpg|png|webp))$~D', $path, $match)) {
    $file = storage_dir() . '/' . $match[1];
    if (!is_file($file)) { http_response_code(404); exit; }
    header('Content-Type: ' . ['jpg' => 'image/jpeg', 'png' => 'image/png', 'webp' => 'image/webp'][$match[2]]);
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: public, max-age=86400');
    readfile($file);
    exit;
}

if ($path === '/') {
    $places = all_places();
    $count = count($places);
    $cards = place_cards($places);
    render('Haunted places of Mongolia', <<<HTML
<section class="hero">
  <div class="hero-copy"><p class="eyebrow"><span class="live-dot"></span> THE HALLOWEEN FIELD COLLECTION · MONGOLIA</p>
  <h1>Some places<br>never <em>rest.</em></h1>
  <p class="hero-description">Beyond the city lights, every silence has a story. Explore Mongolia’s eerie places, uncover old legends, or leave a record of your own encounter.</p>
  <div class="hero-actions"><a class="button" href="#places">Explore the unknown <span>↗</span></a><a class="text-link" href="/report">Share your encounter →</a></div>
  <div class="hero-stats"><div><strong>0{$count}</strong><span>PLACES ON RECORD</span></div><div><strong>MN</strong><span>OUR FIRST CHAPTER</span></div><div><strong>31 / 10</strong><span>THE VEIL IS THIN</span></div></div></div>
  <div class="hero-art"><div class="art-caption"><span>FIELD NOTE / 001</span><strong>When the city sleeps,<br>the stories wake.</strong><span>48° N · MONGOLIA</span><span class="photo-credit">Photo: <a href="https://commons.wikimedia.org/wiki/File:Choijin_lama_temple_museum_(1)_(2551100718).jpg" target="_blank" rel="noopener noreferrer">Francisco Anzola</a> · <a href="https://creativecommons.org/licenses/by/2.0/" target="_blank" rel="noopener noreferrer">CC BY 2.0</a><br>Guardian statue · cropped and darkened</span></div></div>
</section>
<section id="places" class="collection"><div class="section-heading"><div><p class="eyebrow">THE UNEXPLAINED ATLAS</p><h2>Places with a past<span>.</span></h2></div><span class="collection-count">{$count} open case files</span></div>
<p class="collection-intro">Real places. Unsettling stories. Starter cases are labeled as folklore or fiction; visitor accounts remain unverified.</p>
{$cards}</section>
<section class="invitation"><div><p class="eyebrow">HEARD SOMETHING YOU CAN’T EXPLAIN?</p><h2>Give the silence a story.</h2><p>Register a place, tell us what happened, and add your picture.</p></div><a class="button" href="/report">File an encounter ↗</a></section>
HTML);
}

if ($path === '/report') {
    $_SESSION['csrf'] ??= bin2hex(random_bytes(24));
    $fields = [];
    foreach (['location', 'region', 'title', 'author', 'account'] as $key) {
        $fields[$key] = is_string($_POST[$key] ?? null) ? trim($_POST[$key]) : '';
    }
    $errorHtml = '';
    if ($method === 'POST') {
        try {
            if (!is_string($_POST['csrf'] ?? null) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
                throw new RuntimeException('This form expired. Please try submitting again.');
            }
            foreach (['location' => 140, 'region' => 140, 'title' => 180, 'author' => 80, 'account' => 4000] as $key => $max) {
                if ($fields[$key] === '' || strlen($fields[$key]) > $max || preg_match('//u', $fields[$key]) !== 1) {
                    throw new RuntimeException('Complete every field within its stated character limit.');
                }
            }
            $place = save_place($fields, $_FILES['picture'] ?? []);
            // Keep the browser cookie below typical 4 KB cookie limits.
            preg_match('/^.{0,500}/us', $fields['account'], $excerpt);
            $account = $excerpt[0] . (strlen($excerpt[0]) < strlen($fields['account']) ? "\n[Full story in the public case file.]" : '');
            $case = new CaseFile($fields['location'], $account, 'UNVERIFIED');
            // Retain the challenge's plain-text case cookie and escaped archive.
            setcookie('case', base64_encode($case->report()), ['expires' => time() + 86400 * 30, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
            $_SESSION['flash'] = 'Your encounter is on record. Case ' . $case->id . ' is sealed into your browser.';
            header('Location: /place/' . $place['id'], true, 303);
            exit;
        } catch (Throwable $error) {
            http_response_code($error instanceof RuntimeException ? 422 : 503);
            $errorHtml = '<div class="form-error" role="alert">' . h($error instanceof RuntimeException ? $error->getMessage() : 'The registry is temporarily unavailable. Please try again.') . '</div>';
        }
    }
    $f = array_map('h', $fields);
    $csrf = h($_SESSION['csrf']);
    render('Register a haunted place', <<<HTML
<div class="page-heading"><a class="back-link" href="/">← Back to the collection</a><p class="eyebrow">EVERY ENCOUNTER LEAVES A TRACE</p><h1>Put it on <em>record.</em></h1><p>A place. A picture. The moment you still can’t explain.</p></div>
<div class="report-layout"><form method="post" action="/report" enctype="multipart/form-data" class="report-form">
{$errorHtml}<input type="hidden" name="csrf" value="{$csrf}">
<label for="location">Place name <span>140 bytes max</span></label><input id="location" name="location" maxlength="140" value="{$f['location']}" placeholder="The place you can’t forget" required>
<label for="region">Location / region</label><input id="region" name="region" maxlength="140" value="{$f['region']}" placeholder="District, province, country" required>
<label for="title">Give your encounter a title</label><input id="title" name="title" maxlength="180" value="{$f['title']}" placeholder="Three knocks after midnight" required>
<label for="author">Your name or alias</label><input id="author" name="author" maxlength="80" value="{$f['author']}" placeholder="How should we credit you?" required>
<label for="account">What happened? <span>4000 bytes max</span></label><textarea id="account" name="account" rows="7" maxlength="4000" placeholder="Start with where you were. Tell us what you saw, heard, or felt…" required>{$f['account']}</textarea>
<label for="picture">A picture of the place</label><div class="upload-box"><span class="upload-icon">↥</span><strong>Bring a piece of the story</strong><p>JPG, PNG or WebP · up to 1 MB · max 8000 × 8000 px</p><input type="file" id="picture" name="picture" accept="image/jpeg,image/png,image/webp" required><img id="picture-preview" alt="Your selected picture" hidden></div>
<p class="muted">Submit a picture you have permission to share. Reports and photos are visible to all visitors and clear when this challenge resets.</p><button type="submit">Register the encounter ↗</button>
</form><aside class="field-note"><span class="eyebrow">A NOTE TO OUR WITNESSES</span><h2>Details outlive<br>the dark.</h2><p>When did it happen? Were you alone? What made this moment different?</p><p>Tell your own story. Keep private addresses and personal information out of your report.</p><span class="note-number">PHP / FIELD GUIDE 001</span></aside></div>
<script src="/report.js" defer></script>
HTML);
}

if (preg_match('~^/place/([a-z0-9-]+)$~D', $path, $match)) {
    foreach (all_places() as $place) {
        if ($place['id'] !== $match[1]) continue;
        $p = array_map(static fn($value) => is_string($value) ? h($value) : $value, $place);
        $story = nl2br($p['account']);
        $photoCredit = isset($p['photo_source']) ? ' <a href="' . $p['photo_source'] . '" target="_blank" rel="noopener noreferrer">Original photograph</a> · <a href="' . $p['photo_license_url'] . '" target="_blank" rel="noopener noreferrer">' . $p['photo_license'] . '</a>.' : '';
        $source = isset($p['source']) ? '<p class="source">Read the background: <a href="' . $p['source'] . '" target="_blank" rel="noopener noreferrer">' . $p['source_label'] . ' ↗</a></p>' : '';
        render($place['location'], <<<HTML
<article class="detail"><a class="back-link" href="/#places">← Back to the collection</a><p class="eyebrow">{$p['region']} / {$p['status']}</p><h1>{$p['location']}</h1><p class="detail-subtitle">{$p['title']}</p><figure><img src="{$p['image']}" alt="{$p['location']}"><figcaption class="photo-credit">{$p['caption']}{$photoCredit}</figcaption></figure><div class="story-layout"><div><span class="eyebrow">ON THE RECORD</span><p>Filed by {$p['author']}</p><span class="badge">{$p['status']}</span></div><div class="story"><h2>{$p['title']}</h2><p>{$story}</p>{$source}<a class="text-link" href="/report">Have your own story? File an encounter →</a></div></div></article>
HTML);
    }
}

if ($path === '/archive') {
    $report = isset($_COOKIE['case']) && is_string($_COOKIE['case']) ? base64_decode($_COOKIE['case'], true) : false;
    $body = '<p class="muted">No case file in this browser yet. <a href="/report">File an encounter</a> to start your archive.</p>';
    if ($report !== false && $report !== '' && strlen($report) <= 8192) {
        $body = '<pre class="case">' . h($report) . '</pre><p class="muted">Your personal case file travels in your browser cookie.</p>';
    }
    render('Your case file', '<div class="page-heading"><p class="eyebrow">THE WITNESS ARCHIVE</p><h1>Your case <em>file.</em></h1></div>' . $body);
}
http_response_code(404);
render('Case not found', '<div class="page-heading"><p class="eyebrow">404 / NO TRACE FOUND</p><h1>This trail went <em>cold.</em></h1><p>The case you’re looking for isn’t on record.</p><a class="button" href="/">Return to the collection ↗</a></div>');
