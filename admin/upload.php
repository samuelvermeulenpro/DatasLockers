<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('editor');

$id   = (int) ($_GET['id'] ?? 0);
$file = $id ? q('SELECT * FROM ' . t('files') . ' WHERE id = ?', [$id])->fetch() : null;
if ($id && !$file) {
    flash('error', 'Fichier introuvable.');
    redirect('admin/files.php');
}
$isAjax = ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest';
$maxBytes = max_upload_bytes();
$errors = [];

$v = [
    'title'       => $file['title'] ?? '',
    'description' => $file['description'] ?? '',
    'version'     => $file['version'] ?? '',
    'category_id' => $file['category_id'] ?? ($_GET['cat'] ?? null),
    'visibility'  => $file['visibility'] ?? 'public',
    'version_notes' => $file['version_notes'] ?? '',
];
$notifyItems = [];
$mismatch = [];
$bgIntegrity = []; // fichiers volumineux : vérification après la réponse

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // post_max_size dépassé : PHP vide $_POST et $_FILES
    if (empty($_POST) && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
        $errors[] = 'Envoi trop volumineux pour la configuration du serveur (post_max_size = ' . ini_get('post_max_size') . ').';
    } else {
        csrf_check();
        $v['title']       = trim((string) ($_POST['title'] ?? ''));
        $v['description'] = trim((string) ($_POST['description'] ?? ''));
        $v['version']     = mb_substr(trim((string) ($_POST['version'] ?? '')), 0, 40);
        $v['version_notes'] = trim((string) ($_POST['version_notes'] ?? ''));
        $v['category_id'] = ($_POST['category_id'] ?? '') !== '' ? (int) $_POST['category_id'] : null;
        $v['visibility']  = in_array($_POST['visibility'] ?? '', ['public', 'private', 'hidden'], true) ? $_POST['visibility'] : 'public';
        if ($v['category_id'] && !q('SELECT 1 FROM ' . t('categories') . ' WHERE id = ?', [$v['category_id']])->fetchColumn()) {
            $v['category_id'] = null;
        }
        $uploads = array_merge(uploaded_list('files'), chunked_list());

        if ($file) {
            /* ---- Modification ---- */
            if ($v['title'] === '') {
                $errors[] = 'Le titre est obligatoire.';
            }
            $new = null;
            if (!$errors && $uploads) {
                try {
                    $new = store_upload($uploads[0], $maxBytes);
                } catch (RuntimeException $ex) {
                    $errors[] = 'Fichier refusé : ' . $ex->getMessage() . '.';
                }
            }
            if (!$errors) {
                if ($new) {
                    $sameLabel = $v['version'] !== '' && $v['version'] === (string) $file['version'];
                    replace_content($file, $new, $v['version'] ?: null, $v['version_notes'] ?: null, (int) $me['id']);
                }
                q('UPDATE ' . t('files') . ' SET title=?, description=?, version=?, version_notes=?, category_id=?, visibility=? WHERE id=?', [
                    $v['title'], $v['description'] ?: null, $v['version'] ?: null, $v['version_notes'] ?: null,
                    $v['category_id'], $v['visibility'], $file['id'],
                ]);
                $fresh = file_row((int) $file['id']);
                if ($new || $fresh['category_id'] !== $file['category_id']) {
                    if (is_big($fresh)) {
                        $bgIntegrity[] = (int) $fresh['id'];
                    } else {
                        $mismatch = integrity_process($fresh);
                    }
                }
                if ($new) {
                    $notifyItems[] = ['file' => $fresh, 'type' => 'version'];
                    flash('success', 'Nouvelle version de « ' . e($v['title']) . ' » publiée'
                        . (versions_keep() > 0 ? ' — la précédente est conservée dans l\'historique.' : '.'));
                    $outdated = (int) q('SELECT COUNT(*) FROM ' . t('checksum_entries') . " WHERE target_file_id = ? AND status = 'outdated'", [$file['id']])->fetchColumn();
                    if ($outdated) {
                        flash('info', 'Les sommes de contrôle publiées concernent la version précédente : pensez à envoyer celles de la nouvelle version.');
                    }
                    if (!empty($sameLabel)) {
                        flash('info', 'Le numéro de version n\'a pas changé (v' . e($v['version']) . ') : pensez à l\'incrémenter.');
                    }
                } else {
                    flash('success', 'Fichier « ' . e($v['title']) . ' » mis à jour.');
                }
                $target = url('file.php?id=' . $file['id']);
            }
        } else {
            /* ---- Création (un ou plusieurs fichiers) ---- */
            if (!$uploads) {
                $errors[] = 'Sélectionnez au moins un fichier.';
            }
            $ok = 0;
            $newIds = [];
            foreach ($uploads as $up) {
                try {
                    $m = store_upload($up, $maxBytes);
                    $newIds[] = insert_file($m, $v, (int) $me['id'], (count($uploads) === 1 && $v['title'] !== '') ? $v['title'] : null);
                    $ok++;
                } catch (RuntimeException $ex) {
                    $errors[] = e($up['name']) . ' : ' . e($ex->getMessage()) . '.';
                }
            }
            // Vérification des sommes une fois tout le lot enregistré (l'ordre d'envoi importe peu)
            foreach ($newIds as $nid) {
                $row = file_row($nid);
                if (is_big($row)) {
                    $bgIntegrity[] = $nid;
                } else {
                    $mismatch = array_merge($mismatch, integrity_process($row));
                }
            }
            foreach ($newIds as $nid) {
                $notifyItems[] = ['file' => file_row($nid), 'type' => 'new'];
            }
            if ($ok) {
                $verified = count(array_filter(integrity_summary($newIds), fn($s) => $s === 'ok'));
                flash('success', $ok . ' fichier' . ($ok > 1 ? 's ajoutés' : ' ajouté') . '.'
                    . ($verified ? ' ' . $verified . ' vérifié' . ($verified > 1 ? 's' : '') . ' par somme de contrôle ✔' : ''));
                $target = $ok === 1 ? url('file.php?id=' . $newIds[0]) : url('admin/files.php');
            }
            if ($ok && $errors) {
                foreach ($errors as $err) {
                    flash('error', $err);
                }
                $errors = [];
            }
        }
    }

    $mismatch = array_values(array_unique(array_filter($mismatch)));
    foreach ($mismatch as $bid) {
        $bf = file_row($bid);
        if ($bf) {
            flash('error', '✖ « ' . e($bf['title']) . ' » ne correspond pas à sa somme de contrôle.');
        }
    }
    // Après la réponse : vérification des gros fichiers, notifications, empreintes supplémentaires
    $toHash = array_map(fn($it) => (int) $it['file']['id'], $notifyItems);
    if ($notifyItems || $mismatch || $bgIntegrity) {
        $uid = (int) $me['id'];
        defer_after_response(function () use ($notifyItems, $mismatch, $bgIntegrity, $toHash, $uid) {
            foreach ($bgIntegrity as $bid) {
                if ($row = file_row($bid)) {
                    $mismatch = array_merge($mismatch, integrity_process($row));
                }
            }
            if ($notifyItems || $mismatch) {
                // fiches relues : l'état d'intégrité figure dans l'e-mail
                $items = array_values(array_filter(array_map(fn($it) => ['file' => file_row((int) $it['file']['id']), 'type' => $it['type']], $notifyItems), fn($it) => $it['file']));
                notify_files($items, array_values(array_unique(array_filter($mismatch))), $uid);
            }
            foreach ($toHash as $hid) {
                precompute_hashes($hid);
            }
        });
    }
    if ($bgIntegrity) {
        flash('info', 'Fichier volumineux : la vérification des sommes de contrôle et le calcul des empreintes se poursuivent en arrière-plan — actualisez la fiche dans quelques minutes.');
    }

    if ($isAjax) {
        header('Content-Type: application/json');
        echo json_encode(isset($target) && !$errors
            ? ['ok' => true, 'redirect' => $target]
            : ['ok' => false, 'errors' => array_map(fn($m) => html_entity_decode(strip_tags($m), ENT_QUOTES, 'UTF-8'), $errors)]);
        exit;
    }
    if (isset($target) && !$errors) {
        redirect($target);
    }
}

render_header($file ? 'Modifier un fichier' : 'Envoyer des fichiers', 'upload');
?>
<div class="page-head">
  <div>
    <h1><?= $file ? 'Modifier « ' . e($file['title']) . ' »' : 'Envoyer des fichiers' ?></h1>
    <p class="muted">Taille max. <?= human_size($maxBytes) ?> par fichier<?= $file ? '' : ' — plusieurs fichiers possibles' ?> · envoi par morceaux de <?= human_size(chunk_bytes()) ?>, avec reprise.
      <span title=".<?= e(implode(' .', allowed_extensions())) ?>"><?= count(allowed_extensions()) ?> types acceptés</span><?php if (has_role('admin')): ?> · <a href="<?= e(url('admin/settings.php')) ?>">modifier</a><?php endif; ?></p>
  </div>
  <div class="gen-actions">
    <?php if (!$file): ?><a class="btn btn-ghost" href="<?= e(url('admin/import.php')) ?>" title="Fichiers déposés par SFTP / scp">Importer depuis le serveur</a><?php endif; ?>
    <a class="btn btn-ghost" href="<?= e(url($file ? 'file.php?id=' . $file['id'] : 'admin/files.php')) ?>">← Retour</a>
  </div>
</div>

<div data-errors>
<?php foreach ($errors as $err): ?><div class="alert alert-error"><?= $err ?></div><?php endforeach; ?>
</div>

<form method="post" enctype="multipart/form-data" class="card form" data-upload data-chunk-url="<?= e(url('admin/chunk.php')) ?>" data-max="<?= $maxBytes ?>">
  <?= csrf_field() ?>
  <div class="dropzone" data-dropzone>
    <input type="file" name="files[]" id="files" <?= $file ? '' : 'multiple required' ?>>
    <label for="files">
      <strong><?= $file ? 'Nouvelle version du fichier (optionnel)' : 'Glissez vos fichiers ici' ?></strong>
      <span class="muted">ou cliquez pour parcourir</span>
    </label>
    <ul class="dz-list" data-dz-list>
      <?php if ($file): ?><li><?= kind_badge($file['original_name']) ?> <?= e($file['original_name']) ?> <span class="muted">· <?= human_size(num($file['size'])) ?> (actuel)</span></li><?php endif; ?>
    </ul>
  </div>
  <?php if ($file): ?>
    <p class="hint"><?= versions_keep() > 0
        ? 'Envoyer un fichier publie une nouvelle version ; l\'actuelle' . ($file['version'] ? ' (v' . e($file['version']) . ')' : '') . ' est conservée dans l\'<a href="' . e(url('file.php?id=' . $file['id'] . '#versions')) . '">historique</a>. Pensez à changer le numéro de version.'
        : 'Historique des versions désactivé : le fichier actuel sera remplacé définitivement.' ?></p>
  <?php endif; ?>
  <div class="progress" data-progress hidden><div class="bar"></div><span>0 %</span></div>
  <div class="upload-status" data-upstatus hidden>
    <span data-upinfo></span>
    <button type="button" class="btn btn-ghost btn-sm" data-upcancel>Interrompre</button>
  </div>

  <div class="grid-2">
    <label>Titre<?= $file ? '' : ' <span class="muted small">(envoi unique ; sinon nom du fichier)</span>' ?>
      <input name="title" value="<?= e($v['title']) ?>"<?= $file ? ' required' : '' ?> maxlength="200">
    </label>
    <label>Version
      <input name="version" value="<?= e($v['version']) ?>" maxlength="40" placeholder="ex. 2.1.0">
    </label>
    <label>Catégorie
      <select name="category_id">
        <option value="">— Sans catégorie —</option>
        <?= category_options($v['category_id'] !== null ? (int) $v['category_id'] : null) ?>
      </select>
    </label>
    <label>Accès
      <select name="visibility">
        <option value="public"<?= $v['visibility'] === 'public' ? ' selected' : '' ?>>Public — visible par tous</option>
        <option value="private"<?= $v['visibility'] === 'private' ? ' selected' : '' ?>>Membres — connexion requise</option>
        <option value="hidden"<?= $v['visibility'] === 'hidden' ? ' selected' : '' ?>>Masqué — lien de partage uniquement</option>
      </select>
    </label>
  </div>
  <label>Description
    <textarea name="description" rows="4"><?= e($v['description']) ?></textarea>
  </label>
  <label>Notes de version <span class="muted small">(nouveautés, corrections… — affichées sur la fiche et dans l'e-mail de notification)</span>
    <textarea name="version_notes" rows="3"><?= e($v['version_notes']) ?></textarea>
  </label>
  <div class="form-actions">
    <button class="btn btn-primary btn-lg"><?= $file ? 'Enregistrer' : 'Envoyer' ?></button>
  </div>
</form>
<?php render_footer();
