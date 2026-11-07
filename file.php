<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

$id = (int) ($_GET['id'] ?? 0);
$f  = q('SELECT f.*, c.name AS cat_name, c.id AS cat_id, pc.name AS struct_name, pc.id AS struct_id, u.username AS uploader
         FROM ' . t('files') . ' f
         LEFT JOIN ' . t('categories') . ' c  ON c.id = f.category_id
         LEFT JOIN ' . t('categories') . ' pc ON pc.id = c.parent_id
         LEFT JOIN ' . t('users') . ' u ON u.id = f.uploaded_by
         WHERE f.id = ?', [$id])->fetch();

if (!$f || !can_view_file($f)) {
    if ($f && $f['visibility'] === 'private' && !current_user()) {
        $_SESSION['after_login'] = $_SERVER['REQUEST_URI'];
        flash('info', 'Ce fichier est réservé aux membres. Connectez-vous pour y accéder.');
        redirect('login.php');
    }
    http_response_code(404);
    render_header('Introuvable');
    echo '<div class="card empty"><h2>Fichier introuvable</h2><p><a href="' . e(url()) . '">Retour à la liste</a></p></div>';
    render_footer();
    exit;
}

$editor   = has_role('editor');
[$kind, $ext] = file_kind($f['original_name']);
$preview  = preview_kind($f);
$checks   = integrity_for_target((int) $f['id']);
$sumLines = is_checksum_file($f['original_name']) ? integrity_for_source((int) $f['id']) : [];
$showVer  = $editor || versions_public();
$versions = $showVer ? file_versions((int) $f['id']) : [];
$state    = integrity_summary([$f['id']])[$f['id']] ?? null;
$digests  = [];
foreach (gen_algos() as $a => $label) {
    $digests[$a] = cached_digest($f, $a);
}

/** Lien vers un fichier si le visiteur peut le voir, sinon simple nom */
function file_ref(?int $id, string $label, ?string $vis): string
{
    if ($id && $vis !== null && can_view_file(['visibility' => $vis])) {
        return '<a href="' . e(url('file.php?id=' . $id)) . '">' . e($label) . '</a>';
    }
    return e($label);
}

render_header($f['title'], 'files');
?>
<nav class="breadcrumb">
  <a href="<?= e(url()) ?>">Téléchargements</a>
  <?php if ($f['struct_name']): ?> › <a href="<?= e(url('index.php?cat=' . $f['struct_id'])) ?>"><?= e($f['struct_name']) ?></a><?php endif; ?>
  <?php if ($f['cat_name']): ?> › <a href="<?= e(url('index.php?cat=' . $f['cat_id'])) ?>"><?= e($f['cat_name']) ?></a><?php endif; ?>
</nav>

<div class="detail-grid">
  <div>
  <article class="card detail-main">
    <div class="detail-head">
      <span class="kind kind-<?= e($kind) ?> kind-lg"><?= e(mb_substr($ext, 0, 4)) ?></span>
      <div>
        <h1><?= e($f['title']) ?> <?php if ($f['version']): ?><span class="ver">v<?= e($f['version']) ?></span><?php endif; ?></h1>
        <p class="muted"><?= e($f['original_name']) ?> <?= integrity_badge($state) ?></p>
      </div>
    </div>
    <?php if ($f['description']): ?>
      <div class="prose"><?= nl2br(e($f['description'])) ?></div>
    <?php else: ?>
      <p class="muted">Pas de description.</p>
    <?php endif; ?>

    <?php if ($f['version_notes']): ?>
      <div class="notes">
        <h3>Notes de version<?= $f['version'] ? ' — v' . e($f['version']) : '' ?></h3>
        <div class="prose"><?= nl2br(e($f['version_notes'])) ?></div>
      </div>
    <?php endif; ?>

    <div class="detail-actions">
      <a class="btn btn-primary btn-lg" href="<?= e(url('download.php?id=' . $f['id'])) ?>">⬇ Télécharger (<?= human_size(num($f['size'])) ?>)</a>
      <?php if ($editor): ?>
        <a class="btn btn-ghost" href="<?= e(url('admin/upload.php?id=' . $f['id'])) ?>">Modifier / nouvelle version</a>
        <a class="btn btn-ghost" href="<?= e(url('admin/links.php?file=' . $f['id'])) ?>">Lien de partage</a>
      <?php endif; ?>
    </div>
  </article>

  <?php if ($preview): ?>
  <section class="card preview" id="apercu">
    <h3>Aperçu</h3>
    <?php $src = e(url('preview.php?id=' . $f['id'] . '&h=' . substr($f['sha256'], 0, 8))); ?>
    <?php if ($preview === 'image'): ?>
      <a href="<?= $src ?>" target="_blank" rel="noopener"><img src="<?= $src ?>" alt="Aperçu de <?= e($f['title']) ?>" loading="lazy"></a>
    <?php elseif ($preview === 'pdf'): ?>
      <iframe src="<?= $src ?>" title="Aperçu PDF de <?= e($f['title']) ?>" loading="lazy"></iframe>
      <p class="hint"><a href="<?= $src ?>" target="_blank" rel="noopener">Ouvrir le PDF dans un nouvel onglet</a></p>
    <?php elseif ($preview === 'audio'): ?>
      <audio controls preload="metadata" src="<?= $src ?>"></audio>
    <?php elseif ($preview === 'video'): ?>
      <video controls preload="metadata" src="<?= $src ?>"></video>
    <?php else: [$txt, $cut] = preview_text($f); ?>
      <pre class="text-preview"><?= e($txt) ?></pre>
      <?php if ($cut): ?><p class="hint">Aperçu limité aux <?= (int) setting('preview_text_kb', 256) ?> premiers Ko — téléchargez le fichier pour le voir en entier.</p><?php endif; ?>
    <?php endif; ?>
  </section>
  <?php endif; ?>

  <section class="card" id="empreintes">
    <h3>Empreintes &amp; sommes de contrôle</h3>
    <table class="table digests">
      <tbody>
      <?php foreach (gen_algos() as $a => $label): $hex = $digests[$a]; ?>
        <tr>
          <th scope="row"><?= e($label) ?></th>
          <td><?php if ($hex): ?><code class="hash" title="Cliquer pour copier" data-copy="<?= e($hex) ?>"><?= e($hex) ?></code><?php else: ?><span class="muted small">non calculée</span><?php endif; ?></td>
          <td class="actions nowrap">
            <?php if ($hex): ?>
              <button type="button" class="btn btn-ghost btn-sm" data-copy="<?= e($hex) ?>">Copier</button>
            <?php elseif ($editor): ?>
              <form method="post" action="<?= e(url('checksum.php')) ?>" class="inline">
                <?= csrf_field() ?><input type="hidden" name="id" value="<?= $f['id'] ?>"><input type="hidden" name="action" value="compute"><input type="hidden" name="algo" value="<?= e($a) ?>">
                <button class="btn btn-ghost btn-sm" title="<?= num($f['size']) > 500 * 1048576 ? 'Gros fichier : le calcul peut prendre un moment' : '' ?>">Calculer</button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>

    <form method="<?= $editor ? 'post' : 'get' ?>" action="<?= e(url('checksum.php')) ?>" class="gen-form" data-gen-form data-name="<?= e($f['original_name']) ?>">
      <?php if ($editor): ?><?= csrf_field() ?><?php endif; ?>
      <input type="hidden" name="id" value="<?= $f['id'] ?>">
      <label>Format
        <select name="format" data-gen-format>
          <?php foreach (GEN_FORMATS as $k => $l): ?><option value="<?= $k ?>"><?= e($l) ?></option><?php endforeach; ?>
        </select>
      </label>
      <label>Algorithme
        <select name="algo" data-gen-algo>
          <?php foreach (gen_algos() as $a => $label): $avail = $editor || $digests[$a]; ?>
            <option value="<?= e($a) ?>"<?= $a === 'sha256' ? ' selected' : '' ?><?= $avail ? '' : ' disabled' ?>><?= e($label) ?><?= $avail ? '' : ' (non calculée)' ?></option>
          <?php endforeach; ?>
          <option value="all"<?= $editor || !in_array(null, $digests, true) ? '' : ' disabled' ?>>Toutes (format BSD)</option>
        </select>
      </label>
      <div class="gen-actions">
        <button name="action" value="download">⬇ Générer le fichier</button>
        <?php if ($editor): ?><button name="action" value="publish" class="btn-ghost" title="Ajoute le fichier de sommes au gestionnaire, dans la même catégorie (nouvelle version s'il existe déjà)">Publier dans le gestionnaire</button><?php endif; ?>
      </div>
      <p class="hint gen-preview" data-gen-name></p>
    </form>
  </section>

  <?php if ($sumLines): ?>
  <section class="card table-card" id="sommes">
    <div class="card-head"><h3>Fichiers vérifiés par ce fichier de sommes</h3></div>
    <table class="table">
      <thead><tr><th>Fichier</th><th>Algorithme</th><th>Résultat</th><th class="hide-sm">Vérifié le</th></tr></thead>
      <tbody>
      <?php foreach ($sumLines as $l): ?>
        <tr>
          <td><?= $l['target_file_id'] ? file_ref((int) $l['target_file_id'], $l['target_title'] ?? $l['filename'], $l['target_visibility']) : e($l['filename']) ?>
            <?php if ($l['target_file_id'] && $l['target_title'] !== $l['filename']): ?><div class="muted small"><?= e($l['filename']) ?></div><?php endif; ?></td>
          <td><?= e(hash_label($l['algo'])) ?></td>
          <td><span class="check check-<?= e((string) $l['status']) ?>"><?= e(CHECK_STATUS_LABEL[$l['status']] ?? 'En attente') ?><?= $l['status'] === 'outdated' && $l['matched_version'] ? ' (v' . e($l['matched_version']) . ')' : '' ?></span></td>
          <td class="hide-sm"><?= fr_date($l['checked_at'], true) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </section>
  <?php endif; ?>

  <?php if ($showVer && ($versions || $editor)): ?>
  <section class="card table-card" id="versions">
    <div class="card-head"><h3>Historique des versions</h3>
      <?php if ($editor): ?><a class="btn btn-ghost btn-sm" href="<?= e(url('admin/upload.php?id=' . $f['id'])) ?>">+ Nouvelle version</a><?php endif; ?></div>
    <table class="table versions-table">
      <thead><tr><th>Version</th><th>Fichier</th><th class="hide-sm">Date</th><th class="num hide-sm">Taille</th><th class="num hide-sm">Téléch.</th><th></th></tr></thead>
      <tbody>
        <tr class="current">
          <td><strong><?= $f['version'] ? 'v' . e($f['version']) : 'Actuelle' ?></strong> <span class="badge badge-public">actuelle</span></td>
          <td><?= e($f['original_name']) ?><div class="muted small hash-short" title="SHA-256 <?= e($f['sha256']) ?>"><?= e(substr($f['sha256'], 0, 16)) ?>…</div></td>
          <td class="hide-sm"><?= fr_date($f['content_at'] ?? $f['created_at'], true) ?></td>
          <td class="num hide-sm"><?= human_size(num($f['size'])) ?></td>
          <td class="num hide-sm">—</td>
          <td class="actions"><a class="btn btn-primary btn-sm" href="<?= e(url('download.php?id=' . $f['id'])) ?>">⬇</a></td>
        </tr>
      <?php foreach ($versions as $v): ?>
        <tr>
          <td><?= $v['version'] ? 'v' . e($v['version']) : '<span class="muted">sans n°</span>' ?></td>
          <td><?= e($v['original_name']) ?>
            <div class="muted small hash-short" title="SHA-256 <?= e($v['sha256']) ?>"><?= e(substr($v['sha256'], 0, 16)) ?>…<?= $editor && $v['username'] ? ' · ' . e($v['username']) : '' ?></div>
            <?php if ($v['notes']): ?><details class="vnotes"><summary>Notes</summary><div class="prose"><?= nl2br(e($v['notes'])) ?></div></details><?php endif; ?>
          </td>
          <td class="hide-sm"><?= fr_date($v['created_at'], true) ?></td>
          <td class="num hide-sm"><?= human_size(num($v['size'])) ?></td>
          <td class="num hide-sm"><?= (int) $v['downloads'] ?></td>
          <td class="actions nowrap">
            <a class="btn btn-ghost btn-sm" href="<?= e(url('download.php?id=' . $f['id'] . '&v=' . $v['id'])) ?>" title="Télécharger cette version">⬇</a>
            <?php if ($editor): ?>
              <form method="post" action="<?= e(url('admin/versions.php')) ?>" class="inline" data-confirm="Rétablir <?= e($v['version'] ? 'la v' . $v['version'] : 'cette version') ?> comme version actuelle ? L'actuelle sera conservée dans l'historique.">
                <?= csrf_field() ?><input type="hidden" name="action" value="restore"><input type="hidden" name="id" value="<?= $v['id'] ?>">
                <button class="icon-btn" title="Rétablir cette version">↺</button>
              </form>
              <form method="post" action="<?= e(url('admin/versions.php')) ?>" class="inline" data-confirm="Supprimer définitivement cette version ?">
                <?= csrf_field() ?><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $v['id'] ?>">
                <button class="icon-btn danger" title="Supprimer cette version">✕</button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$versions): ?>
        <tr><td colspan="6" class="empty-row">Aucune version précédente<?= $editor && versions_keep() === 0 ? ' — historique désactivé dans les Réglages' : '' ?>.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </section>
  <?php endif; ?>
  </div>

  <aside>
    <div class="card">
      <h3>Informations</h3>
      <dl class="meta">
        <dt>Taille</dt><dd><?= human_size(num($f['size'])) ?></dd>
        <dt>Type</dt><dd><?= e($f['mime']) ?></dd>
        <dt>Ajouté le</dt><dd><?= fr_date($f['created_at']) ?></dd>
        <dt>Mis à jour</dt><dd><?= fr_date($f['content_at'] ?? $f['updated_at'], true) ?></dd>
        <dt>Téléchargements</dt><dd><?= (int) $f['downloads'] ?></dd>
        <?php if ($versions): ?><dt>Versions</dt><dd><a href="#versions"><?= count($versions) + 1 ?></a></dd><?php endif; ?>
        <dt>Accès</dt><dd><?= vis_badge($f['visibility']) ?></dd>
        <?php if ($editor): ?><dt>Stockage</dt><dd><?= is_encrypted_file(storage_path($f['stored_name'])) ? '🔒 chiffré' : '<span class="muted">en clair</span>' ?></dd><?php endif; ?>
        <?php if ($f['uploader'] && current_user()): ?><dt>Publié par</dt><dd><?= e($f['uploader']) ?></dd><?php endif; ?>
        <dt>SHA-256</dt><dd><code class="hash" title="Cliquer pour copier" data-copy="<?= e($f['sha256']) ?>"><?= e(substr($f['sha256'], 0, 24)) ?>…</code> <a class="small" href="#empreintes">toutes les empreintes</a></dd>
      </dl>
    </div>

    <div class="card integrity-card<?= $state === 'mismatch' ? ' bad' : '' ?>">
      <h3>Intégrité</h3>
      <?php if ($checks): ?>
        <ul class="checks-list">
        <?php foreach ($checks as $c): ?>
          <li class="check-<?= e((string) $c['status']) ?>">
            <strong><?= $c['status'] === 'ok' ? '✔' : ($c['status'] === 'mismatch' ? '✖' : '•') ?> <?= e(hash_label($c['algo'])) ?></strong> — <?= e(CHECK_STATUS_LABEL[$c['status']] ?? 'en attente') ?><?= $c['status'] === 'outdated' && $c['matched_version'] ? ' (v' . e($c['matched_version']) . ')' : '' ?>
            <div class="muted small">via <?= file_ref((int) $c['source_file_id'], $c['source_name'], $c['source_visibility']) ?> · <?= fr_date($c['checked_at'], true) ?></div>
            <?php if ($c['status'] === 'mismatch'): ?><div class="small">attendu <code><?= e(substr($c['expected'], 0, 16)) ?>…</code></div><?php endif; ?>
            <?php if ($c['status'] === 'outdated' && $editor): ?><div class="small">Publiez le fichier de sommes de la version actuelle (nouvelle version de « <?= e($c['source_name']) ?> »).</div><?php endif; ?>
          </li>
        <?php endforeach; ?>
        </ul>
      <?php else: ?>
        <p class="muted small" style="margin:0">Aucun fichier de sommes (<code>.sha256sum</code>, <code>SHA256SUMS</code>…) ne référence ce fichier. Vous pouvez comparer vous-même l'empreinte SHA-256 ci-dessus.</p>
      <?php endif; ?>
    </div>
  </aside>
</div>
<?php render_footer();
