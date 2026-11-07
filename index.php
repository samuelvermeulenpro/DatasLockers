<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

$u      = current_user();
$search = trim((string) ($_GET['q'] ?? ''));
$cat    = (int) ($_GET['cat'] ?? 0);
$sort   = (string) ($_GET['sort'] ?? 'recent');
$per    = (int) cfg('per_page', 25);

$where  = [];
$params = [];

// Visibilité selon le profil
if (has_role('editor')) {
    $where[] = "f.visibility IN ('public','private')"; // les masqués restent dans l'admin
} elseif ($u) {
    $where[] = "f.visibility IN ('public','private')";
} else {
    $where[] = "f.visibility = 'public'";
}

$tree = categories_tree();
if ($cat > 0) {
    $ids = [$cat];
    if (isset($tree[$cat])) {
        $ids = array_merge($ids, array_keys($tree[$cat]['children']));
    }
    $where[] = 'f.category_id IN (' . implode(',', array_map('intval', $ids)) . ')';
}
if ($search !== '') {
    $where[] = '(f.title LIKE ? OR f.description LIKE ? OR f.original_name LIKE ?)';
    $like = '%' . addcslashes($search, '%_\\') . '%';
    array_push($params, $like, $like, $like);
}

$orders = [
    'recent' => 'f.updated_at DESC',
    'name'   => 'f.title ASC',
    'dl'     => 'f.downloads DESC, f.title ASC',
    'size'   => 'f.size DESC',
];
$order = $orders[$sort] ?? $orders['recent'];
$w     = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$total = (int) q('SELECT COUNT(*) FROM ' . t('files') . " f $w", $params)->fetchColumn();
[$page, $pages, $offset] = paginate($total, (int) ($_GET['p'] ?? 1), $per);

$files = q('SELECT f.*, c.name AS cat_name, pc.name AS struct_name
            FROM ' . t('files') . ' f
            LEFT JOIN ' . t('categories') . ' c  ON c.id = f.category_id
            LEFT JOIN ' . t('categories') . " pc ON pc.id = c.parent_id
            $w ORDER BY $order LIMIT $per OFFSET $offset", $params)->fetchAll();

// Compteurs par catégorie (selon visibilité)
$visSql = $u ? "visibility IN ('public','private')" : "visibility = 'public'";
$counts = q('SELECT category_id, COUNT(*) n FROM ' . t('files') . " WHERE $visSql GROUP BY category_id")->fetchAll(PDO::FETCH_KEY_PAIR);
$allCount = array_sum($counts);

$integrity = integrity_summary(array_column($files, 'id'));

render_header('Téléchargements', 'files');
?>
<div class="page-head">
  <div>
    <h1>Téléchargements</h1>
    <p class="muted"><?= $total ?> fichier<?= $total > 1 ? 's' : '' ?><?= $search !== '' ? ' pour « ' . e($search) . ' »' : '' ?></p>
  </div>
  <form class="searchbar" method="get">
    <?php if ($cat): ?><input type="hidden" name="cat" value="<?= $cat ?>"><?php endif; ?>
    <input type="search" name="q" value="<?= e($search) ?>" placeholder="Rechercher un fichier…" aria-label="Rechercher">
    <select name="sort" aria-label="Trier" onchange="this.form.submit()">
      <option value="recent"<?= $sort === 'recent' ? ' selected' : '' ?>>Plus récents</option>
      <option value="name"<?= $sort === 'name' ? ' selected' : '' ?>>Nom A→Z</option>
      <option value="dl"<?= $sort === 'dl' ? ' selected' : '' ?>>Plus téléchargés</option>
      <option value="size"<?= $sort === 'size' ? ' selected' : '' ?>>Taille</option>
    </select>
    <button class="btn btn-primary">Chercher</button>
  </form>
</div>

<div class="layout-side">
  <aside class="card sidebar">
    <h3>Catégories</h3>
    <ul class="cat-tree">
      <li><a href="<?= e(qs(['cat' => null, 'p' => null])) ?>"<?= !$cat ? ' class="active"' : '' ?>>Tous les fichiers <span class="count"><?= $allCount ?></span></a></li>
      <?php foreach ($tree as $s):
          $sCount = ($counts[$s['id']] ?? 0) + array_sum(array_map(fn($c) => $counts[$c['id']] ?? 0, $s['children'])); ?>
        <li class="struct">
          <a href="<?= e(qs(['cat' => $s['id'], 'p' => null])) ?>"<?= $cat === (int) $s['id'] ? ' class="active"' : '' ?>><?= e($s['name']) ?> <span class="count"><?= $sCount ?></span></a>
          <?php if ($s['children']): ?>
          <ul>
            <?php foreach ($s['children'] as $c): ?>
              <li><a href="<?= e(qs(['cat' => $c['id'], 'p' => null])) ?>"<?= $cat === (int) $c['id'] ? ' class="active"' : '' ?>><?= e($c['name']) ?> <span class="count"><?= $counts[$c['id']] ?? 0 ?></span></a></li>
            <?php endforeach; ?>
          </ul>
          <?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ul>
    <?php if (!$u): ?>
      <p class="muted small">Certains fichiers sont réservés aux membres. <a href="<?= e(url('login.php')) ?>">Se connecter</a></p>
    <?php endif; ?>
  </aside>

  <section>
    <?php if (!$files): ?>
      <div class="card empty">
        <h2>Aucun fichier</h2>
        <p class="muted">Rien ne correspond à ces critères pour le moment.</p>
      </div>
    <?php else: ?>
      <div class="card table-card">
        <table class="table files-table">
          <thead>
            <tr><th>Fichier</th><th class="hide-sm">Catégorie</th><th class="hide-sm num">Taille</th><th class="hide-sm">Mis à jour</th><th class="num hide-sm">Téléch.</th><th></th></tr>
          </thead>
          <tbody>
          <?php foreach ($files as $f): ?>
            <tr>
              <td>
                <div class="file-cell">
                  <?= kind_badge($f['original_name']) ?>
                  <div>
                    <a class="file-title" href="<?= e(url('file.php?id=' . $f['id'])) ?>"><?= e($f['title']) ?></a>
                    <?php if ($f['version']): ?><span class="ver">v<?= e($f['version']) ?></span><?php endif; ?>
                    <?php if ($f['visibility'] === 'private'): ?> <?= vis_badge('private') ?><?php endif; ?>
                    <?= integrity_badge($integrity[$f['id']] ?? null) ?>
                    <div class="muted small"><?= e($f['original_name']) ?><span class="show-sm"> · <?= human_size(num($f['size'])) ?></span></div>
                  </div>
                </div>
              </td>
              <td class="hide-sm"><?php if ($f['cat_name']): ?><span class="crumb"><?= $f['struct_name'] ? e($f['struct_name']) . ' › ' : '' ?><?= e($f['cat_name']) ?></span><?php else: ?><span class="muted">—</span><?php endif; ?></td>
              <td class="hide-sm num"><?= human_size(num($f['size'])) ?></td>
              <td class="hide-sm"><?= fr_date($f['updated_at']) ?></td>
              <td class="num hide-sm"><?= (int) $f['downloads'] ?></td>
              <td class="actions"><a class="btn btn-primary btn-sm" href="<?= e(url('download.php?id=' . $f['id'])) ?>" title="Télécharger">⬇ <span class="hide-sm">Télécharger</span></a></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?= pager($page, $pages) ?>
    <?php endif; ?>
  </section>
</div>
<?php render_footer();
