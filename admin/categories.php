<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
require_role('editor');

$C = t('categories');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    $name   = trim((string) ($_POST['name'] ?? ''));
    $id     = (int) ($_POST['id'] ?? 0);
    $parent = ($_POST['parent_id'] ?? '') !== '' ? (int) $_POST['parent_id'] : null;

    // Seules les structures (niveau 1) peuvent être parentes
    if ($parent !== null) {
        $pr = q("SELECT parent_id FROM $C WHERE id = ?", [$parent])->fetch();
        if (!$pr || $pr['parent_id'] !== null) {
            $parent = null;
        }
    }

    switch ($action) {
        case 'add':
            if ($name === '') {
                flash('error', 'Le nom est obligatoire.');
                break;
            }
            $pos = (int) q("SELECT COALESCE(MAX(position),0)+1 FROM $C WHERE parent_id <=> ?", [$parent])->fetchColumn();
            q("INSERT INTO $C (parent_id, name, position) VALUES (?,?,?)", [$parent, mb_substr($name, 0, 120), $pos]);
            flash('success', ($parent ? 'Service' : 'Structure') . ' « ' . e($name) . ' » ajouté(e).');
            break;

        case 'rename':
            if ($name !== '' && $id) {
                $hasKids = (int) q("SELECT COUNT(*) FROM $C WHERE parent_id = ?", [$id])->fetchColumn();
                if ($parent === $id || ($hasKids && $parent !== null)) {
                    $parent = null; // une structure qui a des services reste une structure
                }
                q("UPDATE $C SET name = ?, parent_id = ? WHERE id = ?", [mb_substr($name, 0, 120), $parent, $id]);
                flash('success', 'Catégorie mise à jour.');
            }
            break;

        case 'move':
            $dir = ($_POST['dir'] ?? '') === 'up' ? -1 : 1;
            $row = q("SELECT id, parent_id FROM $C WHERE id = ?", [$id])->fetch();
            if ($row) {
                $sib = q("SELECT id FROM $C WHERE parent_id <=> ? ORDER BY position, name", [$row['parent_id']])->fetchAll(PDO::FETCH_COLUMN);
                $i = array_search($row['id'], $sib);
                $j = $i + $dir;
                if ($i !== false && isset($sib[$j])) {
                    [$sib[$i], $sib[$j]] = [$sib[$j], $sib[$i]];
                    foreach ($sib as $p => $cid) {
                        q("UPDATE $C SET position = ? WHERE id = ?", [$p, $cid]);
                    }
                }
            }
            break;

        case 'delete':
            $n = (int) q('SELECT COUNT(*) FROM ' . t('files') . " WHERE category_id = ? OR category_id IN (SELECT id FROM $C WHERE parent_id = ?)", [$id, $id])->fetchColumn();
            q("DELETE FROM $C WHERE id = ?", [$id]);
            flash('success', 'Catégorie supprimée' . ($n ? " — $n fichier(s) désormais sans catégorie" : '') . '.');
            break;
    }
    redirect('admin/categories.php');
}

$tree   = categories_tree();
$counts = q('SELECT category_id, COUNT(*) FROM ' . t('files') . ' GROUP BY category_id')->fetchAll(PDO::FETCH_KEY_PAIR);
$editId = (int) ($_GET['edit'] ?? 0);

function cat_row(array $c, bool $isChild, array $tree, array $counts, int $editId): void
{
    $n = $counts[$c['id']] ?? 0;
    ?>
    <li class="<?= $isChild ? 'cat-child' : 'cat-struct' ?>">
      <?php if ($editId === (int) $c['id']): ?>
        <form method="post" class="inline-form">
          <?= csrf_field() ?><input type="hidden" name="action" value="rename"><input type="hidden" name="id" value="<?= $c['id'] ?>">
          <input name="name" value="<?= e($c['name']) ?>" required autofocus>
          <select name="parent_id">
            <option value="">(structure)</option>
            <?php foreach ($tree as $s): if ((int) $s['id'] === (int) $c['id']) continue; ?>
              <option value="<?= $s['id'] ?>"<?= (int) $c['parent_id'] === (int) $s['id'] ? ' selected' : '' ?>>dans <?= e($s['name']) ?></option>
            <?php endforeach; ?>
          </select>
          <button class="btn btn-primary btn-sm">OK</button>
          <a class="btn btn-ghost btn-sm" href="?">Annuler</a>
        </form>
      <?php else: ?>
        <span class="cat-name"><?= $isChild ? '› ' : '' ?><?= e($c['name']) ?></span>
        <span class="count" title="Fichiers"><?= $n ?></span>
        <span class="cat-actions">
          <form method="post"><?= csrf_field() ?><input type="hidden" name="action" value="move"><input type="hidden" name="id" value="<?= $c['id'] ?>"><input type="hidden" name="dir" value="up"><button class="icon-btn" title="Monter">↑</button></form>
          <form method="post"><?= csrf_field() ?><input type="hidden" name="action" value="move"><input type="hidden" name="id" value="<?= $c['id'] ?>"><input type="hidden" name="dir" value="down"><button class="icon-btn" title="Descendre">↓</button></form>
          <a class="icon-btn" href="?edit=<?= $c['id'] ?>" title="Renommer / déplacer">✎</a>
          <form method="post" data-confirm="Supprimer « <?= e($c['name']) ?> »<?= $isChild ? '' : ' et ses services' ?> ? Les fichiers seront conservés, sans catégorie.">
            <?= csrf_field() ?><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $c['id'] ?>"><button class="icon-btn danger" title="Supprimer">✕</button>
          </form>
        </span>
      <?php endif; ?>
    </li>
    <?php
}

render_header('Catégories', 'cats');
?>
<div class="page-head">
  <div><h1>Catégories</h1><p class="muted">Deux niveaux : <strong>structure</strong> › <strong>service</strong></p></div>
</div>

<div class="layout-side reverse">
  <section class="card">
    <?php if (!$tree): ?>
      <p class="muted">Aucune catégorie pour l'instant.</p>
    <?php else: ?>
      <ul class="cat-admin">
        <?php foreach ($tree as $s):
            cat_row($s, false, $tree, $counts, $editId);
            foreach ($s['children'] as $c) {
                cat_row($c, true, $tree, $counts, $editId);
            }
        endforeach; ?>
      </ul>
    <?php endif; ?>
  </section>

  <aside class="card">
    <h3>Ajouter</h3>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="add">
      <label>Nom<input name="name" required maxlength="120"></label>
      <label>Placer
        <select name="parent_id">
          <option value="">Nouvelle structure</option>
          <?php foreach ($tree as $s): ?><option value="<?= $s['id'] ?>">Service dans « <?= e($s['name']) ?> »</option><?php endforeach; ?>
        </select>
      </label>
      <button class="btn btn-primary btn-block">Ajouter</button>
    </form>
  </aside>
</div>
<?php render_footer();
