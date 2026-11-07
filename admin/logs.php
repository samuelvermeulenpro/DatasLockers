<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
require_role('editor');

$L = t('download_log');
$where = [];
$params = [];
$fileId = (int) ($_GET['file'] ?? 0);
$from = (string) ($_GET['from'] ?? '');
$to   = (string) ($_GET['to'] ?? '');

if ($fileId) {
    $where[] = 'l.file_id = ?';
    $params[] = $fileId;
}
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
    $where[] = 'l.created_at >= ?';
    $params[] = $from . ' 00:00:00';
}
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
    $where[] = 'l.created_at <= ?';
    $params[] = $to . ' 23:59:59';
}
$w = $where ? 'WHERE ' . implode(' AND ', $where) : '';
$base = "FROM $L l JOIN " . t('files') . ' f ON f.id = l.file_id
         LEFT JOIN ' . t('users') . ' u ON u.id = l.user_id
         LEFT JOIN ' . t('share_links') . " s ON s.id = l.link_id $w";

/* Export CSV */
if (($_GET['export'] ?? '') === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="journal-telechargements-' . date('Ymd') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF"); // BOM pour Excel
    fputcsv($out, ['Date', 'Fichier', 'Utilisateur', 'Lien', 'IP', 'Navigateur'], ';');
    $st = q("SELECT l.created_at, f.title, u.username, s.label, l.ip, l.user_agent $base ORDER BY l.id DESC", $params);
    while ($r = $st->fetch()) {
        fputcsv($out, [$r['created_at'], $r['title'], $r['username'] ?? '', $r['label'] ?? '', $r['ip'], $r['user_agent']], ';');
    }
    exit;
}

$per = 50;
$total = (int) q("SELECT COUNT(*) $base", $params)->fetchColumn();
[$page, $pages, $offset] = paginate($total, (int) ($_GET['p'] ?? 1), $per);
$rows = q("SELECT l.*, f.title, u.username, s.label AS link_label $base ORDER BY l.id DESC LIMIT $per OFFSET $offset", $params)->fetchAll();
$files = q('SELECT id, title FROM ' . t('files') . ' ORDER BY title')->fetchAll();

render_header('Journal', 'logs');
?>
<div class="page-head">
  <div><h1>Journal des téléchargements</h1><p class="muted"><?= $total ?> entrée(s)<?= cfg('anonymize_ip', true) ? ' · IP tronquées (RGPD)' : '' ?><?= (int) cfg('log_retention_days', 365) > 0 ? ' · conservation ' . (int) cfg('log_retention_days') . ' jours' : '' ?></p></div>
  <a class="btn btn-ghost" href="<?= e(qs(['export' => 'csv', 'p' => null])) ?>">Exporter CSV</a>
</div>

<form class="card filters" method="get">
  <select name="file">
    <option value="">Tous les fichiers</option>
    <?php foreach ($files as $f): ?><option value="<?= $f['id'] ?>"<?= $fileId === (int) $f['id'] ? ' selected' : '' ?>><?= e($f['title']) ?></option><?php endforeach; ?>
  </select>
  <label class="inline-label">Du <input type="date" name="from" value="<?= e($from) ?>"></label>
  <label class="inline-label">au <input type="date" name="to" value="<?= e($to) ?>"></label>
  <button class="btn btn-ghost">Filtrer</button>
</form>

<div class="card table-card">
  <table class="table">
    <thead><tr><th>Date</th><th>Fichier</th><th>Origine</th><th class="hide-sm">IP</th><th class="hide-sm">Navigateur</th></tr></thead>
    <tbody>
    <?php if (!$rows): ?><tr><td colspan="5" class="empty-row">Aucune entrée.</td></tr><?php endif; ?>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="nowrap"><?= fr_date($r['created_at'], true) ?></td>
        <td><a href="<?= e(url('file.php?id=' . $r['file_id'])) ?>"><?= e($r['title']) ?></a></td>
        <td><?php if ($r['username']): ?>👤 <?= e($r['username']) ?><?php elseif ($r['link_id']): ?><span class="badge badge-hidden">lien</span> <?= e($r['link_label'] ?? '') ?><?php else: ?><span class="muted">anonyme</span><?php endif; ?></td>
        <td class="hide-sm"><code><?= e($r['ip']) ?></code></td>
        <td class="hide-sm small muted ua" title="<?= e($r['user_agent']) ?>"><?= e(mb_strimwidth((string) $r['user_agent'], 0, 60, '…')) ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>
<?= pager($page, $pages) ?>
<?php render_footer();
