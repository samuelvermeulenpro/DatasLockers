<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
require_role('editor');

$F = t('files');
$L = t('download_log');

$stats = q("SELECT COUNT(*) n, COALESCE(SUM(size),0) bytes, COALESCE(SUM(downloads),0) dl,
                   SUM(visibility='public') pub, SUM(visibility='private') priv, SUM(visibility='hidden') hid
            FROM $F")->fetch();
$dl30  = (int) q("SELECT COUNT(*) FROM $L WHERE created_at >= (NOW() - INTERVAL 30 DAY)")->fetchColumn();

// 14 derniers jours
$rows = q("SELECT DATE(created_at) d, COUNT(*) n FROM $L WHERE created_at >= (CURDATE() - INTERVAL 13 DAY) GROUP BY d")->fetchAll(PDO::FETCH_KEY_PAIR);
$days = [];
for ($i = 13; $i >= 0; $i--) {
    $d = date('Y-m-d', strtotime("-$i day"));
    $days[$d] = (int) ($rows[$d] ?? 0);
}
$maxDay = max(1, max($days));

$top    = q("SELECT id, title, original_name, downloads FROM $F ORDER BY downloads DESC, title LIMIT 6")->fetchAll();
$recent = q("SELECT id, title, original_name, created_at, visibility FROM $F ORDER BY created_at DESC LIMIT 6")->fetchAll();
$last   = q("SELECT l.created_at, l.ip, f.id, f.title, u.username, l.link_id
             FROM $L l JOIN $F f ON f.id = l.file_id LEFT JOIN " . t('users') . " u ON u.id = l.user_id
             ORDER BY l.id DESC LIMIT 8")->fetchAll();

$free = @disk_free_space(storage_path());
$badFiles = q("SELECT DISTINCT f.id, f.title FROM " . t('checksum_entries') . " e JOIN $F f ON f.id = e.target_file_id WHERE e.status = 'mismatch' ORDER BY f.title")->fetchAll();
$nVersions = (int) q('SELECT COUNT(*) FROM ' . t('file_versions'))->fetchColumn();
$verBytes  = num(q('SELECT COALESCE(SUM(size),0) FROM ' . t('file_versions'))->fetchColumn());
$nVerified = (int) q("SELECT COUNT(DISTINCT target_file_id) FROM " . t('checksum_entries') . " WHERE status = 'ok'")->fetchColumn();
$jours = ['dim.', 'lun.', 'mar.', 'mer.', 'jeu.', 'ven.', 'sam.'];

render_header('Tableau de bord', 'dash');
?>
<div class="page-head">
  <div><h1>Tableau de bord</h1><p class="muted">Vue d'ensemble des téléchargements</p></div>
  <a class="btn btn-primary" href="<?= e(url('admin/upload.php')) ?>">+ Envoyer des fichiers</a>
</div>

<?php if ($badFiles): ?>
  <div class="alert alert-error">
    <strong>⚠ <?= count($badFiles) ?> fichier<?= count($badFiles) > 1 ? 's ne correspondent' : ' ne correspond' ?> pas à <?= count($badFiles) > 1 ? 'leur' : 'sa' ?> somme de contrôle :</strong>
    <?php foreach ($badFiles as $i => $b): ?><?= $i ? ', ' : ' ' ?><a href="<?= e(url('file.php?id=' . $b['id'])) ?>"><?= e($b['title']) ?></a><?php endforeach; ?>
  </div>
<?php endif; ?>
<div class="tiles">
  <div class="tile"><span class="tile-label">Fichiers</span><strong><?= (int) $stats['n'] ?></strong>
    <span class="muted small"><?= (int) $stats['pub'] ?> publics · <?= (int) $stats['priv'] ?> membres · <?= (int) $stats['hid'] ?> masqués<?= $nVerified ? ' · ' . $nVerified . ' vérifié(s) ✔' : '' ?></span></div>
  <div class="tile"><span class="tile-label">Espace utilisé</span><strong><?= human_size(num($stats['bytes']) + $verBytes) ?></strong>
    <span class="muted small"><?= $nVersions ? $nVersions . ' ancienne(s) version(s) · ' . human_size($verBytes) . ' · ' : '' ?><?= $free !== false ? human_size($free) . ' libres' : '' ?></span></div>
  <div class="tile"><span class="tile-label">Téléchargements (total)</span><strong><?= (int) $stats['dl'] ?></strong><span class="muted small">depuis l'origine</span></div>
  <div class="tile accent"><span class="tile-label">30 derniers jours</span><strong><?= $dl30 ?></strong><span class="small">téléchargements</span></div>
</div>

<div class="card">
  <h3>Téléchargements — 14 derniers jours</h3>
  <div class="bars" role="img" aria-label="Histogramme des téléchargements par jour">
    <?php foreach ($days as $d => $n): $ts = strtotime($d); ?>
      <div class="bar-col" title="<?= date('d/m', $ts) ?> : <?= $n ?>">
        <span class="bar-val"><?= $n ?: '' ?></span>
        <div class="bar" style="height: <?= round($n / $maxDay * 100) ?>%"></div>
        <span class="bar-lbl"><?= $jours[(int) date('w', $ts)] ?><br><?= date('d', $ts) ?></span>
      </div>
    <?php endforeach; ?>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <h3>Les plus téléchargés</h3>
    <ol class="rank">
      <?php foreach ($top as $f): ?>
        <li><?= kind_badge($f['original_name']) ?><a href="<?= e(url('file.php?id=' . $f['id'])) ?>"><?= e($f['title']) ?></a><span class="count"><?= (int) $f['downloads'] ?></span></li>
      <?php endforeach; ?>
      <?php if (!$top): ?><li class="muted">Aucun fichier.</li><?php endif; ?>
    </ol>
  </div>
  <div class="card">
    <h3>Derniers ajouts</h3>
    <ul class="rank">
      <?php foreach ($recent as $f): ?>
        <li><?= kind_badge($f['original_name']) ?><a href="<?= e(url('admin/upload.php?id=' . $f['id'])) ?>"><?= e($f['title']) ?></a><span class="muted small"><?= fr_date($f['created_at']) ?></span></li>
      <?php endforeach; ?>
      <?php if (!$recent): ?><li class="muted">Aucun fichier.</li><?php endif; ?>
    </ul>
  </div>
</div>

<div class="card table-card">
  <div class="card-head"><h3>Activité récente</h3><a href="<?= e(url('admin/logs.php')) ?>">Tout le journal →</a></div>
  <table class="table">
    <thead><tr><th>Date</th><th>Fichier</th><th class="hide-sm">Par</th><th class="hide-sm">IP</th></tr></thead>
    <tbody>
    <?php foreach ($last as $r): ?>
      <tr>
        <td class="nowrap"><?= fr_date($r['created_at'], true) ?></td>
        <td><a href="<?= e(url('file.php?id=' . $r['id'])) ?>"><?= e($r['title']) ?></a></td>
        <td class="hide-sm"><?= $r['username'] ? e($r['username']) : ($r['link_id'] ? '<span class="badge badge-hidden">lien</span>' : '<span class="muted">anonyme</span>') ?></td>
        <td class="hide-sm"><code><?= e($r['ip']) ?></code></td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$last): ?><tr><td colspan="4" class="empty-row">Aucun téléchargement pour l'instant.</td></tr><?php endif; ?>
    </tbody>
  </table>
</div>
<?php render_footer();
