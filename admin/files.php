<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('editor');

/* ---------- Actions groupées ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $ids = array_values(array_filter(array_map('intval', (array) ($_POST['ids'] ?? []))));
    $action = (string) ($_POST['action'] ?? '');
    if (!$ids) {
        flash('error', 'Aucun fichier sélectionné.');
    } else {
        $in = implode(',', array_fill(0, count($ids), '?'));
        switch ($action) {
            case 'delete':
                $n = delete_files($ids);
                flash('success', $n . ' fichier(s) supprimé(s), versions comprises.');
                break;
            case 'verify':
                @set_time_limit(0);
                $bad = [];
                $bigIds = [];
                foreach ($ids as $fid) {
                    if ($row = file_row($fid)) {
                        if (is_big($row)) {
                            $bigIds[] = $fid;
                            continue;
                        }
                        q('DELETE FROM ' . t('file_hashes') . ' WHERE file_id = ?', [$fid]); // recalcul complet
                        $bad = array_merge($bad, integrity_process($row));
                    }
                }
                if ($bigIds) {
                    $uid = (int) $me['id'];
                    defer_after_response(function () use ($bigIds, $uid) {
                        $bad = [];
                        foreach ($bigIds as $fid) {
                            q('DELETE FROM ' . t('file_hashes') . ' WHERE file_id = ?', [$fid]);
                            if ($row = file_row($fid)) {
                                $bad = array_merge($bad, integrity_process($row));
                            }
                        }
                        if ($bad) {
                            notify_files([], $bad, $uid);
                        }
                        foreach ($bigIds as $fid) {
                            precompute_hashes($fid);
                        }
                    });
                    flash('info', count($bigIds) . ' fichier(s) volumineux revérifié(s) en arrière-plan — actualisez dans quelques minutes.');
                    $ids = array_values(array_diff($ids, $bigIds));
                }
                if ($ids) {
                    $sum = integrity_summary($ids);
                    $okN = count(array_filter($sum, fn($x) => $x === 'ok'));
                    $badN = count(array_unique($bad)) ?: count(array_filter($sum, fn($x) => $x === 'mismatch'));
                    $oldN = count(array_filter($sum, fn($x) => $x === 'outdated'));
                    defer_after_response(function () use ($ids) {
                        foreach ($ids as $fid) {
                            precompute_hashes($fid);
                        }
                    });
                    flash($badN ? 'error' : 'success', "Vérification terminée : $okN conforme(s), $badN non conforme(s)"
                        . ($oldN ? ", $oldN avec une somme de la version précédente" : '')
                        . (count($ids) - count($sum) ? ', ' . (count($ids) - count($sum)) . ' sans somme de contrôle' : '') . '.');
                }
                break;
            case 'sums_download':
            case 'sums_publish':
                $rows = q('SELECT * FROM ' . t('files') . " WHERE id IN ($in) ORDER BY original_name", $ids)->fetchAll();
                // un fichier de sommes ne figure pas dans un autre fichier de sommes
                $src = array_values(array_filter($rows, fn($r) => !is_checksum_file($r['original_name']))) ?: $rows;
                $skipped = count($rows) - count($src);
                $format = (string) ($_POST['sum_format'] ?? 'gnu');
                $algo = (string) ($_POST['sum_algo'] ?? 'sha256');
                $algos = $algo === 'all' ? array_keys(gen_algos()) : [$algo];
                // empreintes manquantes sur de gros fichiers : calcul en arrière-plan, puis on réessaie
                $want = $format === 'sfv' ? ['crc32b'] : $algos;
                $pending = [];
                foreach ($src as $r) {
                    if (is_big($r) && ($miss = missing_digests($r, $want))) {
                        $pending[(int) $r['id']] = $miss;
                    }
                }
                if ($pending) {
                    defer_after_response(function () use ($pending) {
                        foreach ($pending as $fid => $miss) {
                            foreach ($miss as $a) {
                                file_digest(file_row($fid), $a);
                            }
                        }
                    });
                    flash('info', 'Empreintes manquantes sur ' . count($pending) . ' fichier(s) volumineux : calcul lancé en arrière-plan. Relancez la génération dans quelques minutes.');
                    break;
                }
                try {
                    [$fname, $content] = checksum_generate($src, $algos, $format, true);
                } catch (RuntimeException $ex) {
                    flash('error', 'Génération impossible : ' . e($ex->getMessage()) . '.');
                    break;
                }
                if ($action === 'sums_download') {
                    send_checksum_text($fname, $content);
                }
                [$row, $type] = checksum_publish($src, $format === 'sfv' ? ['crc32b'] : $algos, $fname, $content, (int) $me['id']);
                if ($type === 'same') {
                    flash('info', '« ' . e($fname) . ' » est déjà publié avec un contenu identique.');
                } else {
                    flash('success', '« <a href="' . e(url('file.php?id=' . $row['id'])) . '">' . e($fname) . '</a> » '
                        . ($type === 'version' ? 'mis à jour (nouvelle version)' : 'publié') . ' pour ' . count($src) . ' fichier(s) — vérifié ✔'
                        . ($skipped ? " ($skipped fichier(s) de sommes ignoré(s))" : ''));
                    $uid = (int) $me['id'];
                    defer_after_response(fn() => notify_files([['file' => $row, 'type' => $type]], [], $uid));
                }
                break;
            case 'public':
            case 'private':
            case 'hidden':
                q('UPDATE ' . t('files') . " SET visibility = ? WHERE id IN ($in)", array_merge([$action], $ids));
                flash('success', 'Accès mis à jour : ' . e(visibility_label($action)) . '.');
                break;
            case 'move':
                $cat = ($_POST['move_to'] ?? '') !== '' ? (int) $_POST['move_to'] : null;
                q('UPDATE ' . t('files') . " SET category_id = ? WHERE id IN ($in)", array_merge([$cat], $ids));
                flash('success', 'Fichier(s) déplacé(s).');
                break;
            default:
                flash('error', 'Action inconnue.');
        }
    }
    redirect('admin/files.php' . qs());
}

/* ---------- Liste ---------- */
$search = trim((string) ($_GET['q'] ?? ''));
$cat    = (int) ($_GET['cat'] ?? 0);
$vis    = (string) ($_GET['vis'] ?? '');
$per    = (int) cfg('per_page', 25);
$where = [];
$params = [];
$tree = categories_tree();

if ($cat === -1) {
    $where[] = 'f.category_id IS NULL';
} elseif ($cat > 0) {
    $ids = [$cat];
    if (isset($tree[$cat])) {
        $ids = array_merge($ids, array_keys($tree[$cat]['children']));
    }
    $where[] = 'f.category_id IN (' . implode(',', array_map('intval', $ids)) . ')';
}
if (in_array($vis, ['public', 'private', 'hidden'], true)) {
    $where[] = 'f.visibility = ?';
    $params[] = $vis;
}
if ($search !== '') {
    $where[] = '(f.title LIKE ? OR f.original_name LIKE ? OR f.description LIKE ?)';
    $like = '%' . addcslashes($search, '%_\\') . '%';
    array_push($params, $like, $like, $like);
}
$w = $where ? 'WHERE ' . implode(' AND ', $where) : '';
$total = (int) q('SELECT COUNT(*) FROM ' . t('files') . " f $w", $params)->fetchColumn();
[$page, $pages, $offset] = paginate($total, (int) ($_GET['p'] ?? 1), $per);

$files = q('SELECT f.*, c.name cat_name, pc.name struct_name,
              (SELECT COUNT(*) FROM ' . t('share_links') . ' l WHERE l.file_id = f.id) AS nlinks,
              (SELECT COUNT(*) FROM ' . t('file_versions') . ' v WHERE v.file_id = f.id) AS nversions
            FROM ' . t('files') . ' f
            LEFT JOIN ' . t('categories') . ' c ON c.id = f.category_id
            LEFT JOIN ' . t('categories') . " pc ON pc.id = c.parent_id
            $w ORDER BY f.updated_at DESC LIMIT $per OFFSET $offset", $params)->fetchAll();

$integrity = integrity_summary(array_column($files, 'id'));

render_header('Gestion des fichiers', 'afiles');
?>
<div class="page-head">
  <div><h1>Gestion des fichiers</h1><p class="muted"><?= $total ?> fichier(s)</p></div>
  <a class="btn btn-primary" href="<?= e(url('admin/upload.php')) ?>">+ Envoyer</a>
</div>

<form class="card filters" method="get">
  <input type="search" name="q" value="<?= e($search) ?>" placeholder="Titre, nom de fichier…">
  <select name="cat">
    <option value="">Toutes catégories</option>
    <option value="-1"<?= $cat === -1 ? ' selected' : '' ?>>— Sans catégorie —</option>
    <?= category_options($cat > 0 ? $cat : null) ?>
  </select>
  <select name="vis">
    <option value="">Tous accès</option>
    <?php foreach (['public', 'private', 'hidden'] as $o): ?>
      <option value="<?= $o ?>"<?= $vis === $o ? ' selected' : '' ?>><?= visibility_label($o) ?></option>
    <?php endforeach; ?>
  </select>
  <button class="btn btn-ghost">Filtrer</button>
</form>

<form method="post" data-bulk>
  <?= csrf_field() ?>
  <div class="card table-card">
    <table class="table">
      <thead><tr>
        <th class="w-check"><input type="checkbox" data-check-all aria-label="Tout sélectionner"></th>
        <th>Fichier</th><th class="hide-sm">Catégorie</th><th>Accès</th><th class="num hide-sm">Taille</th><th class="num hide-sm">Téléch.</th><th class="hide-sm">Mis à jour</th><th></th>
      </tr></thead>
      <tbody>
      <?php if (!$files): ?>
        <tr><td colspan="8" class="empty-row">Aucun fichier.</td></tr>
      <?php endif; ?>
      <?php foreach ($files as $f): ?>
        <tr>
          <td class="w-check"><input type="checkbox" name="ids[]" value="<?= $f['id'] ?>" data-check></td>
          <td>
            <div class="file-cell"><?= kind_badge($f['original_name']) ?>
              <div><a class="file-title" href="<?= e(url('file.php?id=' . $f['id'])) ?>"><?= e($f['title']) ?></a>
                <?php if ($f['version']): ?><span class="ver">v<?= e($f['version']) ?></span><?php endif; ?>
                <?= integrity_badge($integrity[$f['id']] ?? null) ?>
                <div class="muted small"><?= e($f['original_name']) ?><?= $f['nlinks'] ? ' · 🔗 ' . (int) $f['nlinks'] : '' ?><?= $f['nversions'] ? ' · <a href="' . e(url('file.php?id=' . $f['id'] . '#versions')) . '">' . ((int) $f['nversions'] + 1) . ' versions</a>' : '' ?></div>
              </div>
            </div>
          </td>
          <td class="hide-sm"><?= $f['cat_name'] ? '<span class="crumb">' . ($f['struct_name'] ? e($f['struct_name']) . ' › ' : '') . e($f['cat_name']) . '</span>' : '<span class="muted">—</span>' ?></td>
          <td><?= vis_badge($f['visibility']) ?></td>
          <td class="num hide-sm"><?= human_size(num($f['size'])) ?></td>
          <td class="num hide-sm"><?= (int) $f['downloads'] ?></td>
          <td class="hide-sm"><?= fr_date($f['updated_at']) ?></td>
          <td class="actions nowrap">
            <a class="btn btn-ghost btn-sm" href="<?= e(url('admin/upload.php?id=' . $f['id'])) ?>">Modifier</a>
            <a class="btn btn-ghost btn-sm" href="<?= e(url('admin/links.php?file=' . $f['id'])) ?>" title="Liens de partage">🔗</a>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="bulkbar" data-bulkbar>
    <span><strong data-count>0</strong> sélectionné(s)</span>
    <select name="action" data-bulk-action>
      <option value="">Action…</option>
      <option value="public">Rendre public</option>
      <option value="private">Réserver aux membres</option>
      <option value="hidden">Masquer</option>
      <option value="move">Déplacer vers…</option>
      <option value="verify">Revérifier les sommes de contrôle</option>
      <option value="sums_download">Générer un fichier de sommes (télécharger)</option>
      <option value="sums_publish">Générer un fichier de sommes (publier)</option>
      <option value="delete">Supprimer définitivement</option>
    </select>
    <select name="move_to" data-move-to hidden>
      <option value="">— Sans catégorie —</option>
      <?= category_options(null) ?>
    </select>
    <span data-sums hidden class="bulk-sums">
      <select name="sum_format" aria-label="Format">
        <option value="gnu">GNU (SHA256SUMS…)</option>
        <option value="bsd">BSD / --tag</option>
        <option value="sfv">SFV (CRC32)</option>
      </select>
      <select name="sum_algo" aria-label="Algorithme">
        <?php foreach (gen_algos() as $a => $label): ?><option value="<?= e($a) ?>"<?= $a === 'sha256' ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?>
        <option value="all">Toutes (BSD)</option>
      </select>
    </span>
    <button class="btn btn-primary btn-sm">Appliquer</button>
  </div>
</form>
<?= pager($page, $pages) ?>
<?php render_footer();
