<?php
declare(strict_types=1);

/* PHPossessed — a plain PHP app. Model, views, front controller.
   The runtime it runs on is the vulnerable part, not this code. */

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function render(string $title, string $bodyHtml): never
{
    $flash = '';
    if (!empty($_SESSION['flash'])) {
        $flash = '<p class="flash">' . h((string) $_SESSION['flash']) . '</p>';
        unset($_SESSION['flash']);
    }
    $t = h($title);
    header('Content-Type: text/html; charset=utf-8');
    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$t} · PHPossessed</title>
<link rel="stylesheet" href="/style.css">

</head>
<body>
<header><div class="wrap">
  <a class="wordmark" href="/">PHP<span>ossessed</span><small>THE PARANORMAL FIELD JOURNAL</small></a>
  <nav><a href="/">Explore places</a><a href="/archive">Your case file</a>
       <a class="nav-cta" href="/report">+ Register a place</a></nav>
</div></header>
<main><div class="wrap">
{$flash}
{$bodyHtml}
</div></main>
<footer><span>PHPossessed · Stories from the other side</span><span>Witness accounts are unverified. Respect local communities and access rules.</span></footer>
</body>
</html>
HTML;
    exit;
}

class CaseFile
{
    public string $id;
    public string $location;
    public string $account;
    public string $status;
    public int $filed;
    public array $timeline;
    public string $seal;

    public function __construct(string $location, string $account, string $status = 'UNVERIFIED')
    {
        $this->id = 'CASE-' . strtoupper(substr(bin2hex(random_bytes(6)), 0, 6));
        $this->location = $location;
        $this->account = $account;
        $this->status = $status;
        $this->filed = time();
        $this->timeline = ['filed' => $this->filed];
        $this->seal = bin2hex(random_bytes(8));
    }

    public function seal(): string
    {
        return $this->seal;
    }

    public function report(): string
    {
        return sprintf(
            "PHPOSSESSED — CASE FILE\n%s\nlocation : %s\nstatus   : %s\nfiled    : %s\naccount  : %s\nseal     : %s\n",
            $this->id,
            $this->location,
            $this->status,
            date('c', $this->filed),
            $this->account,
            $this->seal,
        );
    }

    public function __toString(): string
    {
        return $this->report();
    }
}

