<?php
declare(strict_types=1);

function render_header(string $title = '', string $active = ''): void
{
    $u    = current_user();
    $app  = cfg('app_name', 'SV Pro Downloads');
    $nav  = [['index.php', 'files', 'Téléchargements']];
    $sub  = [];
    if ($u && has_role('editor')) {
        $sub = [
            ['admin/index.php',      'dash',   'Tableau de bord'],
            ['admin/files.php',      'afiles', 'Fichiers'],
            ['admin/upload.php',     'upload', 'Envoyer'],
            ['admin/import.php',     'import', 'Importer'],
            ['admin/categories.php', 'cats',   'Catégories'],
            ['admin/links.php',      'links',  'Liens de partage'],
            ['admin/logs.php',       'logs',   'Journal'],
        ];
        if (has_role('admin')) {
            $sub[] = ['admin/users.php', 'users', 'Utilisateurs'];
            $sub[] = ['admin/settings.php', 'settings', 'Réglages'];
        }
        $inAdmin = in_array($active, array_column($sub, 1), true);
        $nav[] = ['admin/index.php', $inAdmin ? $active : 'admin', 'Administration'];
    }
    ?><!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title><?= e(($title ? $title . ' — ' : '') . $app) ?></title>
<link rel="icon" type="image/png" href="<?= e(url('assets/favicon.png')) ?>">
<link rel="stylesheet" href="<?= e(url('assets/style.css')) ?>?v=<?= APP_VERSION ?>">
</head>
<body>
<header class="topbar">
  <div class="wrap topbar-inner">
    <a class="brand" href="<?= e(url()) ?>">
      <img src="<?= e(url('assets/logo.png')) ?>" alt="SV Pro" width="48" height="48">
      <span class="brand-text">
        <strong><?= e($app) ?></strong>
        <small>Samuel Vermeulen — Consultant Informatique &amp; Internet</small>
      </span>
    </a>
    <button class="nav-toggle" type="button" aria-label="Menu" aria-expanded="false" data-nav-toggle>
      <span></span><span></span><span></span>
    </button>
    <nav class="mainnav" data-nav>
      <?php foreach ($nav as [$href, $key, $label]): ?>
        <a href="<?= e(url($href)) ?>"<?= $active === $key ? ' class="active"' : '' ?>><?= e($label) ?></a>
      <?php endforeach; ?>
      <span class="nav-sep"></span>
      <?php if ($u): ?>
        <span class="userchip" title="<?= e(role_label($u['role'])) ?>">
          <span class="avatar"><?= e(mb_strtoupper(mb_substr($u['username'], 0, 1))) ?></span><?= e($u['username']) ?>
        </span>
        <a href="<?= e(url('logout.php?t=' . csrf_token())) ?>" class="btn btn-ghost btn-sm">Déconnexion</a>
      <?php else: ?>
        <a href="<?= e(url('login.php')) ?>" class="btn btn-light btn-sm">Connexion</a>
      <?php endif; ?>
    </nav>
  </div>
</header>
<?php if ($sub && in_array($active, array_column($sub, 1), true)): ?>
<nav class="subnav" aria-label="Administration">
  <div class="wrap subnav-inner">
    <?php foreach ($sub as [$href, $key, $label]): ?>
      <a href="<?= e(url($href)) ?>"<?= $active === $key ? ' class="active"' : '' ?>><?= e($label) ?></a>
    <?php endforeach; ?>
  </div>
</nav>
<?php endif; ?>
<main class="wrap main">
<?php foreach (take_flashes() as [$type, $msg]): ?>
  <div class="alert alert-<?= e($type) ?>" data-dismiss><?= $msg /* déjà échappé à l'appel */ ?></div>
<?php endforeach;
}

function render_footer(): void
{
    ?>
</main>
<footer class="foot">
  <img src="<?= e(url('assets/logo.png')) ?>" alt="SV Pro" width="44" height="44">
  <span><strong>SV Pro</strong> — Samuel Vermeulen, Consultant Informatique &amp; Internet</span>
  <span><?= e(cfg('app_name', 'SV Pro Downloads')) ?> v<?= APP_VERSION ?> · © <?= date('Y') ?></span>
</footer>
<script src="<?= e(url('assets/app.js')) ?>?v=<?= APP_VERSION ?>"></script>
</body>
</html>
<?php
}

/** Pastille de type de fichier */
function kind_badge(string $filename): string
{
    [$kind, $ext] = file_kind($filename);
    return '<span class="kind kind-' . $kind . '">' . e(mb_substr($ext, 0, 4)) . '</span>';
}

function pager(int $page, int $pages): string
{
    if ($pages <= 1) {
        return '';
    }
    $h = '<nav class="pager">';
    if ($page > 1) {
        $h .= '<a href="' . e(qs(['p' => $page - 1])) . '">‹ Préc.</a>';
    }
    for ($i = max(1, $page - 3); $i <= min($pages, $page + 3); $i++) {
        $h .= $i === $page ? '<span class="current">' . $i . '</span>' : '<a href="' . e(qs(['p' => $i])) . '">' . $i . '</a>';
    }
    if ($page < $pages) {
        $h .= '<a href="' . e(qs(['p' => $page + 1])) . '">Suiv. ›</a>';
    }
    return $h . '</nav>';
}

function vis_badge(string $v): string
{
    return '<span class="badge badge-' . e($v) . '">' . e(visibility_label($v)) . '</span>';
}
