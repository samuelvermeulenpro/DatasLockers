<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('editor');

$S = t('share_links');
$F = t('files');
$fileId = (int) ($_GET['file'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    if ($action === 'create') {
        $fid   = (int) ($_POST['file_id'] ?? 0);
        $days  = (int) ($_POST['days'] ?? 0);
        $max   = (int) ($_POST['max'] ?? 0);
        $label = mb_substr(trim((string) ($_POST['label'] ?? '')), 0, 120);
        if (!q("SELECT 1 FROM $F WHERE id = ?", [$fid])->fetchColumn()) {
            flash('error', 'Fichier introuvable.');
        } else {
            $token = bin2hex(random_bytes(20));
            q("INSERT INTO $S (file_id, token, label, expires_at, max_downloads, created_by) VALUES (?,?,?,?,?,?)", [
                $fid, $token, $label ?: null,
                $days > 0 ? date('Y-m-d H:i:s', strtotime("+$days days")) : null,
                $max > 0 ? $max : null,
                $me['id'],
            ]);
            $_SESSION['new_link'] = $token;
            flash('success', 'Lien de partage créé.');
        }
        redirect('admin/links.php' . ($fileId ? '?file=' . $fileId : ''));
    }
    if ($action === 'delete') {
        q("DELETE FROM $S WHERE id = ?", [(int) ($_POST['id'] ?? 0)]);
        flash('success', 'Lien révoqué.');
        redirect('admin/links.php' . ($fileId ? '?file=' . $fileId : ''));
    }
    if ($action === 'purge') {
        $n = q("DELETE FROM $S WHERE (expires_at IS NOT NULL AND expires_at < NOW()) OR (max_downloads IS NOT NULL AND uses >= max_downloads)")->rowCount();
        flash('success', "$n lien(s) expiré(s) supprimé(s).");
        redirect('admin/links.php');
    }
}

$newToken = $_SESSION['new_link'] ?? null;
unset($_SESSION['new_link']);

$params = [];
$w = '';
if ($fileId) {
    $w = 'WHERE l.file_id = ?';
    $params[] = $fileId;
}
$links = q("SELECT l.*, f.title, f.original_name, u.username
            FROM $S l JOIN $F f ON f.id = l.file_id LEFT JOIN " . t('users') . " u ON u.id = l.created_by
            $w ORDER BY l.created_at DESC LIMIT 200", $params)->fetchAll();
$allFiles = q("SELECT id, title, visibility FROM $F ORDER BY title")->fetchAll();
$current = $fileId ? q("SELECT title FROM $F WHERE id = ?", [$fileId])->fetchColumn() : null;

render_header('Liens de partage', 'links');
?>
<div class="page-head">
  <div>
    <h1>Liens de partage</h1>
    <p class="muted"><?= $current ? 'Pour « ' . e($current) . ' » · <a href="?">voir tous les liens</a>' : 'Donnent accès à un fichier, même privé ou masqué, sans compte.' ?></p>
  </div>
  <form method="post" data-confirm="Supprimer tous les liens expirés ou épuisés ?"><?= csrf_field() ?><input type="hidden" name="action" value="purge"><button class="btn btn-ghost btn-sm">Purger les liens expirés</button></form>
</div>

<?php if ($newToken): ?>
  <div class="card highlight">
    <strong>Nouveau lien :</strong>
    <div class="copy-row">
      <input readonly value="<?= e(abs_url('download.php?s=' . $newToken)) ?>" data-select>
      <button class="btn btn-primary btn-sm" type="button" data-copy="<?= e(abs_url('download.php?s=' . $newToken)) ?>">Copier</button>
    </div>
  </div>
<?php endif; ?>

<div class="layout-side reverse">
  <section class="card table-card">
    <table class="table">
      <thead><tr><th>Fichier / libellé</th><th>État</th><th class="num">Utilisations</th><th class="hide-sm">Expire</th><th></th></tr></thead>
      <tbody>
      <?php if (!$links): ?><tr><td colspan="5" class="empty-row">Aucun lien.</td></tr><?php endif; ?>
      <?php foreach ($links as $l):
          $expired = $l['expires_at'] && strtotime($l['expires_at']) < time();
          $used    = $l['max_downloads'] !== null && (int) $l['uses'] >= (int) $l['max_downloads'];
          $link    = abs_url('download.php?s=' . $l['token']); ?>
        <tr<?= ($expired || $used) ? ' class="dim"' : '' ?>>
          <td>
            <div class="file-cell"><?= kind_badge($l['original_name']) ?>
              <div><a href="<?= e(url('file.php?id=' . $l['file_id'])) ?>"><?= e($l['title']) ?></a>
                <div class="muted small"><?= $l['label'] ? e($l['label']) . ' · ' : '' ?>créé le <?= fr_date($l['created_at']) ?><?= $l['username'] ? ' par ' . e($l['username']) : '' ?></div>
              </div>
            </div>
          </td>
          <td><?= $expired ? '<span class="badge badge-hidden">Expiré</span>' : ($used ? '<span class="badge badge-hidden">Épuisé</span>' : '<span class="badge badge-public">Actif</span>') ?></td>
          <td class="num"><?= (int) $l['uses'] ?><?= $l['max_downloads'] !== null ? ' / ' . (int) $l['max_downloads'] : '' ?></td>
          <td class="hide-sm"><?= $l['expires_at'] ? fr_date($l['expires_at'], true) : '<span class="muted">jamais</span>' ?></td>
          <td class="actions nowrap">
            <button class="btn btn-ghost btn-sm" type="button" data-copy="<?= e($link) ?>">Copier</button>
            <form method="post" class="inline" data-confirm="Révoquer ce lien ?"><?= csrf_field() ?><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $l['id'] ?>"><button class="icon-btn danger" title="Révoquer">✕</button></form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </section>

  <aside class="card">
    <h3>Nouveau lien</h3>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="create">
      <label>Fichier
        <select name="file_id" required>
          <option value="">Choisir…</option>
          <?php foreach ($allFiles as $f): ?>
            <option value="<?= $f['id'] ?>"<?= $fileId === (int) $f['id'] ? ' selected' : '' ?>><?= e($f['title']) ?><?= $f['visibility'] !== 'public' ? ' (' . visibility_label($f['visibility']) . ')' : '' ?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <label>Libellé (destinataire, note…)<input name="label" maxlength="120" placeholder="ex. Client Dupont"></label>
      <label>Expiration
        <select name="days">
          <option value="1">24 heures</option>
          <option value="7" selected>7 jours</option>
          <option value="30">30 jours</option>
          <option value="90">90 jours</option>
          <option value="0">Jamais</option>
        </select>
      </label>
      <label>Nombre max. de téléchargements<input type="number" name="max" min="0" placeholder="illimité"></label>
      <button class="btn btn-primary btn-block">Créer le lien</button>
    </form>
  </aside>
</div>
<?php render_footer();
