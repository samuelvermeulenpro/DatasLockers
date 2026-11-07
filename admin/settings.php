<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('admin');

// Avancement de la conversion chiffrement / déchiffrement (interrogé chaque seconde)
if (isset($_GET['crypto_progress'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(crypto_state() ?? ['state' => 'idle'], JSON_UNESCAPED_UNICODE);
    exit;
}

/** Groupes d'extensions proposés en un clic */
$presets = [
    'checksums' => ['Sommes de contrôle & signatures', CHECKSUM_EXT],
    'scripts'   => ['Scripts & code', ['sh', 'bash', 'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'py', 'pl', 'rb', 'js', 'ts', 'sql', 'ini', 'cfg', 'toml', 'env', 'html', 'css', 'reg']],
    'vm'        => ['Disques & machines virtuelles', ['iso', 'img', 'qcow2', 'vmdk', 'vdi', 'vhd', 'vhdx', 'ova', 'ovf', 'zst', 'lz4']],
    'office'    => ['Bureautique supplémentaire', ['epub', 'odg', 'vsdx', 'pub', 'msg', 'eml', 'ics', 'vcf', 'xml']],
    'net'       => ['Réseau & sécurité', ['ovpn', 'conf', 'crt', 'cer', 'der', 'p7b', 'csr', 'kdbx', 'rdp', 'pcap', 'pcapng']],
];

/** Découpe une saisie libre en extensions valides ; remplit $rejected */
function parse_ext(string $raw, array &$rejected): array
{
    $out = [];
    foreach (preg_split('/[\s,;]+/', strtolower($raw), -1, PREG_SPLIT_NO_EMPTY) as $x) {
        $x = ltrim($x, '.*');
        if ($x === '') {
            continue;
        }
        if (!preg_match('/^[a-z0-9][a-z0-9+_-]{0,19}$/', $x)) {
            $rejected[$x] = 'format invalide';
        } elseif (in_array($x, FORBIDDEN_EXT, true)) {
            $rejected[$x] = 'interdite (sécurité)';
        } else {
            $out[] = $x;
        }
    }
    return $out;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $current  = allowed_extensions();
    $rejected = [];
    $action   = (string) ($_POST['action'] ?? '');

    switch ($action) {
        case 'crypto_genkey':
            $tab = 'crypto';
            try {
                $kp = generate_master_key();
                flash('success', 'Clé de chiffrement créée : <code>' . e($kp) . '</code>. <strong>Téléchargez-en une sauvegarde maintenant</strong> et rangez-la hors du serveur.');
            } catch (RuntimeException $ex) {
                flash('error', 'Création de la clé impossible : ' . e($ex->getMessage()) . '.');
            }
            break;

        case 'crypto_toggle':
            $tab = 'crypto';
            $on = isset($_POST['encrypt_new']);
            if ($on && (!crypto_available() || master_key() === null)) {
                flash('error', 'Créez d\'abord la clé de chiffrement.');
                break;
            }
            setting_set('encrypt_new', $on);
            flash('success', $on ? '🔒 Les nouveaux fichiers seront chiffrés.' : 'Les nouveaux fichiers seront stockés en clair (les fichiers déjà chiffrés le restent et restent lisibles).');
            break;

        case 'crypto_convert':
            $tab = 'crypto';
            $enc = ($_POST['mode'] ?? '') === 'encrypt';
            if (master_key() === null) {
                flash('error', 'Clé de chiffrement introuvable.');
                break;
            }
            if ((crypto_state()['state'] ?? '') === 'running') {
                flash('error', 'Une conversion est déjà en cours.');
                break;
            }
            crypto_state_save(['state' => 'running', 'mode' => $enc ? 'encrypt' : 'decrypt', 'started' => date('c'),
                'total' => 0, 'done' => 0, 'count' => 0, 'index' => 0, 'current' => '', 'speed' => 0, 'messages' => []]);
            defer_after_response(function () use ($enc) {
                try {
                    crypto_job($enc);
                } catch (Throwable $ex) {
                    $st = crypto_state() ?? [];
                    $st['state'] = 'error';
                    $st['messages'][] = ['error', 'Conversion interrompue : ' . $ex->getMessage()];
                    crypto_state_save($st);
                }
            });
            if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest') {
                header('Content-Type: application/json');
                echo json_encode(['ok' => true]);
                exit;
            }
            break;

        case 'crypto_backup':
            $tab = 'crypto';
            $u = q('SELECT password_hash FROM ' . t('users') . ' WHERE id = ?', [$me['id']])->fetch();
            if (!$u || !password_verify((string) ($_POST['password'] ?? ''), $u['password_hash'])) {
                usleep(400000);
                flash('error', 'Mot de passe incorrect : sauvegarde de la clé refusée.');
                break;
            }
            $k = master_key();
            if ($k === null) {
                flash('error', 'Clé de chiffrement introuvable.');
                break;
            }
            $host = parse_url(site_base_url(), PHP_URL_HOST) ?: 'serveur';
            $txt = "# Clé maîtresse de chiffrement — " . cfg('app_name', 'SV Pro Downloads') . " ($host)\n"
                . "# Empreinte : " . key_fingerprint() . "\n"
                . "# Sauvegardée le " . date('d/m/Y H:i') . " par " . $me['username'] . "\n"
                . "# À conserver HORS du serveur (gestionnaire de mots de passe, coffre, clé USB chiffrée).\n"
                . "# Restauration : copier la dernière ligne seule dans " . encryption_key_path() . " (droits 0400).\n"
                . base64_encode($k) . "\n";
            session_write_close();
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="svpro-downloads-' . preg_replace('/[^a-z0-9.-]/i', '_', $host) . '.key.txt"');
            header('Cache-Control: no-store');
            echo $txt;
            exit;

        case 'add':
            $new = parse_ext((string) ($_POST['ext'] ?? ''), $rejected);
            $added = array_diff($new, $current);
            setting_set('allowed_ext', array_values(array_unique(array_merge($current, $new))));
            if ($added) {
                flash('success', 'Ajouté : ' . e('.' . implode(', .', $added)));
            } elseif (!$rejected) {
                flash('info', 'Ces extensions étaient déjà autorisées.');
            }
            break;

        case 'preset':
            $key = (string) ($_POST['preset'] ?? '');
            if (isset($presets[$key])) {
                setting_set('allowed_ext', array_values(array_unique(array_merge($current, $presets[$key][1]))));
                flash('success', 'Groupe « ' . e($presets[$key][0]) . ' » ajouté.');
            }
            break;

        case 'remove':
            $x = strtolower((string) ($_POST['ext'] ?? ''));
            setting_set('allowed_ext', array_values(array_diff($current, [$x])));
            flash('success', 'Extension .' . e($x) . ' retirée.');
            break;

        case 'replace':
            $list = parse_ext((string) ($_POST['list'] ?? ''), $rejected);
            setting_set('allowed_ext', array_values(array_unique($list)));
            flash('success', count(array_unique($list)) . ' extension(s) enregistrée(s).');
            break;

        case 'reset':
            setting_set('allowed_ext', array_values(array_unique(array_merge((array) cfg('allowed_ext', []), CHECKSUM_EXT))));
            flash('success', 'Liste réinitialisée aux valeurs de config.php.');
            break;

        case 'general':
            setting_set('allow_noext', isset($_POST['allow_noext']));
            $mb = max(1, min(1048576, (int) ($_POST['max_upload_mb'] ?? 512)));
            setting_set('max_upload_mb', $mb);
            setting_set('chunk_mb', max(1, min(512, (int) ($_POST['chunk_mb'] ?? 32))));
            setting_set('preview_enabled', isset($_POST['preview_enabled']));
            setting_set('preview_text_kb', max(16, min(4096, (int) ($_POST['preview_text_kb'] ?? 256))));
            setting_set('auto_hashes', array_values(array_intersect((array) ($_POST['auto_hashes'] ?? []), array_keys(gen_algos()))));
            flash('success', 'Réglages enregistrés.');
            break;

        case 'orphan_recover':
        case 'orphan_delete':
            $tab = 'files';
            $sn = (string) ($_POST['stored'] ?? '');
            $orph = array_column(storage_orphans(), null, 'stored');
            if (!isset($orph[$sn])) {
                flash('error', 'Fichier orphelin introuvable.');
                break;
            }
            if ($action === 'orphan_delete') {
                @unlink(storage_path($sn));
                flash('success', 'Fichier orphelin supprimé (' . human_size($orph[$sn]['size']) . ' libérés).');
                break;
            }
            $idir = rtrim((string) cfg('import_path', ''), '/\\');
            if ($idir === '' || !is_dir($idir) || !is_writable($idir)) {
                flash('error', 'Configurez d\'abord un dossier d\'import accessible en écriture (import_path dans config.php).');
                break;
            }
            $newName = 'recupere-' . date('Ymd-Hi', $orph[$sn]['mtime']) . '-' . substr($sn, 0, 6) . '.' . ext_for_mime($orph[$sn]['mime']);
            if ($orph[$sn]['encrypted']) {
                try {
                    crypto_convert_file(storage_path($sn), false, null); // remis en clair pour pouvoir être réimporté
                } catch (RuntimeException $ex) {
                    flash('error', 'Déchiffrement impossible : ' . e($ex->getMessage()) . '.');
                    break;
                }
            }
            if (@rename(storage_path($sn), $idir . DIRECTORY_SEPARATOR . $newName)) {
                @touch($idir . DIRECTORY_SEPARATOR . $newName, $orph[$sn]['mtime']);
                flash('success', 'Fichier récupéré dans le dossier d\'import sous le nom « ' . e($newName) . ' » : renommez-le si besoin (SFTP), puis <a href="' . e(url('admin/import.php')) . '">importez-le</a>.');
            } else {
                flash('error', 'Déplacement impossible vers le dossier d\'import.');
            }
            break;

        case 'reverify':
            $n = 0;
            foreach (q('SELECT id, original_name FROM ' . t('files'))->fetchAll() as $row) {
                $n += is_checksum_file($row['original_name']) ? 1 : 0;
            }
            defer_after_response(function () {
                foreach (q('SELECT * FROM ' . t('files'))->fetchAll() as $row) {
                    if (is_checksum_file($row['original_name'])) {
                        integrity_index_source($row);
                    }
                }
            });
            flash('info', "Réanalyse de $n fichier(s) de sommes lancée en arrière-plan — les résultats apparaissent sur les fiches et le tableau de bord d'ici quelques minutes.");
            $tab = 'files';
            break;

        case 'versions':
            setting_set('versions_keep', max(0, min(1000, (int) ($_POST['versions_keep'] ?? 10))));
            setting_set('versions_public', isset($_POST['versions_public']));
            $pruned = 0;
            if (versions_keep() > 0) {
                foreach (q('SELECT DISTINCT file_id FROM ' . t('file_versions'))->fetchAll(PDO::FETCH_COLUMN) as $fid) {
                    $pruned += prune_versions((int) $fid);
                }
            }
            flash('success', 'Réglages des versions enregistrés' . ($pruned ? " — $pruned ancienne(s) version(s) supprimée(s) au-delà de la limite." : '.'));
            $tab = 'versions';
            break;

        case 'notify':
            setting_set('notify_enabled', isset($_POST['notify_enabled']));
            setting_set('notify_events', [
                'new'      => isset($_POST['ev_new']),
                'version'  => isset($_POST['ev_version']),
                'mismatch' => isset($_POST['ev_mismatch']),
            ]);
            $rawTo = (string) ($_POST['notify_to'] ?? '');
            $good = [];
            foreach (preg_split('/[\s,;]+/', $rawTo, -1, PREG_SPLIT_NO_EMPTY) as $a) {
                filter_var($a, FILTER_VALIDATE_EMAIL) ? $good[] = strtolower($a) : $rejected[$a] = 'adresse e-mail invalide';
            }
            setting_set('notify_to', implode("\n", array_unique($good)));
            setting_set('notify_roles', in_array($_POST['notify_roles'] ?? '', ['none', 'admin', 'editor', 'member'], true) ? $_POST['notify_roles'] : 'none');
            $site = rtrim(trim((string) ($_POST['site_url'] ?? '')), '/');
            if ($site !== '' && !preg_match('#^https?://[^/\s]+(/[^\s]*)?$#i', $site)) {
                $rejected[$site] = 'URL du site invalide (ex. https://telechargements.exemple.be)';
                $site = (string) setting('site_url', '');
            }
            setting_set('site_url', $site);
            $from = trim((string) ($_POST['mail_from'] ?? ''));
            if ($from !== '' && !filter_var($from, FILTER_VALIDATE_EMAIL)) {
                $rejected[$from] = 'adresse d\'expéditeur invalide';
                $from = (string) setting('mail_from', '');
            }
            setting_set('mail_from', $from);
            setting_set('mail_from_name', mb_substr(trim((string) ($_POST['mail_from_name'] ?? '')), 0, 80));
            setting_set('mail_transport', ($_POST['mail_transport'] ?? '') === 'smtp' ? 'smtp' : 'mail');
            setting_set('smtp_host', trim((string) ($_POST['smtp_host'] ?? '')));
            setting_set('smtp_port', max(1, min(65535, (int) ($_POST['smtp_port'] ?? 587))));
            setting_set('smtp_secure', in_array($_POST['smtp_secure'] ?? '', ['starttls', 'ssl', 'none'], true) ? $_POST['smtp_secure'] : 'starttls');
            setting_set('smtp_user', trim((string) ($_POST['smtp_user'] ?? '')));
            if (($_POST['smtp_pass'] ?? '') !== '') {
                setting_set('smtp_pass', (string) $_POST['smtp_pass']);
            } elseif (isset($_POST['smtp_pass_clear'])) {
                setting_set('smtp_pass', '');
            }
            setting_set('smtp_insecure', isset($_POST['smtp_insecure']));
            flash('success', 'Réglages des notifications enregistrés.');
            $tab = 'notify';
            break;

        case 'test_mail':
            $to = trim((string) ($_POST['test_to'] ?? ''));
            $tab = 'notify';
            if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
                flash('error', 'Adresse de test invalide.');
                break;
            }
            try {
                $html = mail_layout('Test de notification', '<p>Si vous lisez ce message, l\'envoi d\'e-mails de <strong>' . e((string) cfg('app_name')) . '</strong> fonctionne.</p>'
                    . '<p style="color:#667584;font-size:13px">Transport : ' . e(setting('mail_transport', 'mail') === 'smtp' ? 'SMTP ' . setting('smtp_host') . ':' . setting('smtp_port') : 'mail() / sendmail') . '</p>');
                send_mail([$to], 'Test de notification — ' . cfg('app_name'), $html, "Test de notification : l'envoi d'e-mails fonctionne.");
                flash('success', 'E-mail de test envoyé à ' . e($to) . '. Vérifiez la réception (et le dossier indésirables).');
            } catch (Throwable $ex) {
                flash('error', 'Échec de l\'envoi : ' . e($ex->getMessage()));
            }
            break;
    }

    foreach ($rejected as $x => $why) {
        flash('error', 'Refusé : « ' . e((string) $x) . ' » — ' . e($why) . '.');
    }
    redirect('admin/settings.php' . (isset($tab) && $tab !== 'files' ? '?tab=' . $tab : ''));
}

$exts = allowed_extensions();
sort($exts);
$phpUpload = ini_bytes('upload_max_filesize');
$phpPost   = ini_bytes('post_max_size');
$maxMb     = (int) (max_upload_bytes() / 1048576);
$effective = max_upload_bytes(); // l'envoi par morceaux s'affranchit des limites PHP

$tabs = ['files' => 'Fichiers & aperçu', 'versions' => 'Versions', 'notify' => 'Notifications', 'crypto' => '🔒 Chiffrement'];
$tab = array_key_exists($_GET['tab'] ?? '', $tabs) ? $_GET['tab'] : 'files';

render_header('Réglages', 'settings');
?>
<div class="page-head">
  <div><h1>Réglages</h1><p class="muted">Types de fichiers, aperçu, versions, notifications et chiffrement</p></div>
</div>
<nav class="tabs">
  <?php foreach ($tabs as $k => $label): ?>
    <a href="?tab=<?= $k ?>"<?= $tab === $k ? ' class="active"' : '' ?>><?= e($label) ?></a>
  <?php endforeach; ?>
</nav>

<?php if ($tab === 'files'): ?>
<div class="layout-side reverse">
  <section>
    <div class="card">
      <h2>Extensions autorisées <span class="count"><?= count($exts) ?></span></h2>
      <div class="chips">
        <?php foreach ($exts as $x): ?>
          <form method="post" class="chip">
            <?= csrf_field() ?><input type="hidden" name="action" value="remove"><input type="hidden" name="ext" value="<?= e($x) ?>">
            .<?= e($x) ?><button title="Retirer .<?= e($x) ?>" aria-label="Retirer .<?= e($x) ?>">✕</button>
          </form>
        <?php endforeach; ?>
        <?php if (!$exts): ?><span class="muted">Aucune extension autorisée : seuls les fichiers sans extension pourront être envoyés (si activé).</span><?php endif; ?>
      </div>

      <form method="post" class="inline-form">
        <?= csrf_field() ?><input type="hidden" name="action" value="add">
        <input name="ext" placeholder="ex. md5sum, sha256sum, .sig" aria-label="Extensions à ajouter" required>
        <button>Ajouter</button>
      </form>
      <p class="hint" style="margin-top:.5rem">Plusieurs extensions possibles, séparées par des espaces ou des virgules. Le point initial est facultatif.</p>
    </div>

    <div class="card">
      <h2>Ajouter un groupe</h2>
      <div class="preset">
        <?php foreach ($presets as $key => [$label, $list]):
            $missing = array_diff($list, $exts); ?>
          <form method="post" class="inline">
            <?= csrf_field() ?><input type="hidden" name="action" value="preset"><input type="hidden" name="preset" value="<?= e($key) ?>">
            <button class="btn btn-ghost btn-sm" title=".<?= e(implode(' .', $list)) ?>"<?= $missing ? '' : ' disabled' ?>>
              + <?= e($label) ?><?= $missing ? ' (' . count($missing) . ')' : ' ✔' ?>
            </button>
          </form>
        <?php endforeach; ?>
      </div>
      <p class="hint">Survolez un groupe pour voir les extensions qu'il contient.</p>
    </div>

    <details class="card">
      <summary><strong>Édition en bloc</strong> <span class="muted small">— remplace toute la liste</span></summary>
      <form method="post" class="form" style="margin-top:.8rem">
        <?= csrf_field() ?><input type="hidden" name="action" value="replace">
        <label>Liste complète
          <textarea name="list" rows="6"><?= e(implode(' ', $exts)) ?></textarea>
        </label>
        <div class="form-actions">
          <button>Remplacer la liste</button>
        </div>
      </form>
      <form method="post" data-confirm="Revenir à la liste de config.php (+ sommes de contrôle) ?">
        <?= csrf_field() ?><input type="hidden" name="action" value="reset">
        <button class="btn btn-ghost btn-sm">Réinitialiser aux valeurs par défaut</button>
      </form>
    </details>
  </section>

  <aside>
    <div class="card">
      <h3>Général</h3>
      <form method="post" class="form">
        <?= csrf_field() ?><input type="hidden" name="action" value="general">
        <label class="check"><input type="checkbox" name="allow_noext" value="1"<?= allow_no_extension() ? ' checked' : '' ?>> Accepter les fichiers sans extension</label>
        <p class="hint">Ex. <code>SHA256SUMS</code>, <code>MD5SUMS</code>, <code>README</code>, <code>LICENSE</code>.</p>
        <label>Taille max. par fichier (Mo)
          <input type="number" name="max_upload_mb" min="1" max="1048576" value="<?= $maxMb ?>">
        </label>
        <p class="hint">Ex. 8192 pour 8 Go. Les gros fichiers sont envoyés par morceaux : les limites PHP ne s'appliquent qu'à un morceau.</p>
        <label>Taille des morceaux (Mo)
          <input type="number" name="chunk_mb" min="1" max="512" value="<?= (int) setting('chunk_mb', 32) ?>">
        </label>
        <p class="hint">Plafonnée automatiquement sous les limites PHP (actuellement <?= human_size(chunk_bytes()) ?>). Doit rester inférieure au <code>client_max_body_size</code> de Nginx.</p>
        <label class="check"><input type="checkbox" name="preview_enabled" value="1"<?= preview_enabled() ? ' checked' : '' ?>> Aperçu sur la fiche (images, PDF, audio, vidéo, texte)</label>
        <label>Aperçu texte limité à (Ko)
          <input type="number" name="preview_text_kb" min="16" max="4096" value="<?= (int) setting('preview_text_kb', 256) ?>">
        </label>
        <fieldset class="fs">
          <legend>Empreintes calculées à l'envoi <span class="muted small">(SHA-256 toujours)</span></legend>
          <?php foreach (gen_algos() as $a => $label): if ($a === 'sha256') continue; ?>
            <label class="check"><input type="checkbox" name="auto_hashes[]" value="<?= e($a) ?>"<?= in_array($a, auto_hashes(), true) ? ' checked' : '' ?>> <?= e($label) ?></label>
          <?php endforeach; ?>
          <p class="hint" style="margin:.3rem 0 0">Calculées juste après l'envoi, sans faire attendre. Les visiteurs peuvent ensuite générer les fichiers de sommes correspondants.</p>
        </fieldset>
        <button class="btn-block">Enregistrer</button>
      </form>
    </div>
    <div class="card">
      <h3>Limites effectives</h3>
      <dl class="meta">
        <dt>Application</dt><dd><?= human_size(max_upload_bytes()) ?></dd>
        <dt>upload_max_filesize</dt><dd><?= $phpUpload ? human_size($phpUpload) : '—' ?></dd>
        <dt>post_max_size</dt><dd><?= $phpPost ? human_size($phpPost) : '—' ?></dd>
        <dt>Morceaux</dt><dd><?= human_size(chunk_bytes()) ?></dd>
        <dt>Par fichier</dt><dd><strong><?= human_size($effective) ?></strong></dd>
        <dt>Disque libre</dt><dd><?= ($fr = @disk_free_space(storage_path())) !== false ? human_size($fr) : '—' ?></dd>
      </dl>
      <p class="hint" style="margin:.8rem 0 0">Envoi par morceaux avec reprise : seule la taille d'un morceau doit passer sous <code>upload_max_filesize</code>, <code>post_max_size</code> et <code>client_max_body_size</code>. Au-delà, utilisez <a href="<?= e(url('admin/import.php')) ?>">l'import depuis le serveur</a>.</p>
    </div>
    <?php
    // Diagnostic du stockage : fichiers absents du disque, mode d'envoi et droits
    $rowsF = q('SELECT id, title, stored_name FROM ' . t('files'))->fetchAll();
    $rowsV = q('SELECT v.file_id id, f.title, v.stored_name FROM ' . t('file_versions') . ' v JOIN ' . t('files') . ' f ON f.id = v.file_id')->fetchAll();
    $missingF = array_values(array_filter($rowsF, fn($r) => !is_file(storage_path($r['stored_name']))));
    $missingV = array_values(array_filter($rowsV, fn($r) => !is_file(storage_path($r['stored_name']))));
    $orphans = storage_orphans();
    $mode = (string) cfg('send_mode', 'php');
    $stDir = storage_path();
    $grp = function_exists('posix_getgrgid') && ($g = @posix_getgrgid((int) @filegroup($stDir))) ? $g['name'] : (string) @filegroup($stDir);
    $setgid = (bool) (@fileperms($stDir) & 02000);
    ?>
    <div class="card<?= $missingF || $orphans || ($mode !== 'php' && ($grp !== 'www-data' || !$setgid)) ? ' integrity-card bad' : '' ?>">
      <h3>Stockage</h3>
      <dl class="meta">
        <dt>Dossier</dt><dd class="small"><code><?= e($stDir) ?></code></dd>
        <dt>Groupe</dt><dd><?= e($grp) ?><?= $setgid ? ' (setgid)' : '' ?></dd>
        <dt>Envoi</dt><dd><code><?= e($mode) ?></code></dd>
        <dt>Fichiers</dt><dd><?= count($rowsF) - count($missingF) ?> / <?= count($rowsF) ?> présents</dd>
        <?php if ($rowsV): ?><dt>Versions</dt><dd><?= count($rowsV) - count($missingV) ?> / <?= count($rowsV) ?> présentes</dd><?php endif; ?>
      </dl>
      <?php if ($missingF || $missingV): ?>
        <p class="small" style="color:var(--err);margin:.8rem 0 .3rem"><strong>Absents du disque :</strong></p>
        <ul class="small" style="margin:0;padding-left:1.1rem">
          <?php foreach (array_slice(array_merge($missingF, $missingV), 0, 8) as $mf): ?>
            <li><a href="<?= e(url('file.php?id=' . $mf['id'])) ?>"><?= e($mf['title']) ?></a> <code><?= e(substr($mf['stored_name'], 0, 8)) ?>…</code></li>
          <?php endforeach; ?>
        </ul>
        <p class="hint" style="margin:.4rem 0 0">Le dossier de stockage a-t-il été remplacé ou déplacé (<code>storage_path</code> dans <code>config.php</code>) ?</p>
      <?php endif; ?>
      <?php if ($orphans): ?>
        <p class="small" style="margin:.8rem 0 .3rem"><strong>Fichiers orphelins</strong> <span class="muted">(sur le disque, sans fiche — ex. import interrompu)</span> :</p>
        <ul class="orphans">
          <?php foreach (array_slice($orphans, 0, 10) as $o): ?>
            <li>
              <span><?= human_size($o['size']) ?> · <?= e(date('d/m/Y H:i', $o['mtime'])) ?> · <code><?= e(ext_for_mime($o['mime'])) ?></code></span>
              <span class="gen-actions">
                <form method="post" class="inline"><?= csrf_field() ?><input type="hidden" name="action" value="orphan_recover"><input type="hidden" name="stored" value="<?= e($o['stored']) ?>"><button class="btn-sm" title="Déplacer vers le dossier d'import pour le réimporter">Récupérer</button></form>
                <form method="post" class="inline" data-confirm="Supprimer définitivement ce fichier de <?= e(human_size($o['size'])) ?> ?"><?= csrf_field() ?><input type="hidden" name="action" value="orphan_delete"><input type="hidden" name="stored" value="<?= e($o['stored']) ?>"><button class="icon-btn danger" title="Supprimer">✕</button></form>
              </span>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
      <?php if ($mode !== 'php'): ?>
        <p class="hint" style="margin:.8rem 0 0">Mode <code><?= e($mode) ?></code> : c'est le serveur web qui lit les fichiers. Il faut le bloc
          <code><?= $mode === 'accel' ? 'location ' . e((string) cfg('accel_prefix')) . ' { internal; alias …/storage/; }' : 'XSendFilePath' ?></code>
          et un dossier lisible par <code>www-data</code> (<code>chgrp -R www-data storage &amp;&amp; chmod 2750 storage &amp;&amp; chmod 640 storage/*</code>).
          <?php if ($grp !== 'www-data' || !$setgid): ?><strong style="color:var(--err)">Ce n'est pas le cas ici : les téléchargements échoueront.</strong><?php endif; ?>
          En cas de doute, revenez à <code>'send_mode' => 'php'</code>.</p>
      <?php endif; ?>
    </div>
    <div class="card">
      <h3>Intégrité</h3>
      <p class="hint" style="margin:0 0 .8rem">Les fichiers de sommes (<code>.sha256sum</code>, <code>.md5</code>, <code>SHA256SUMS</code>, <code>.sfv</code>…) sont analysés à l'envoi et comparés aux fichiers du même nom.</p>
      <form method="post" data-confirm="Réanalyser tous les fichiers de sommes ? Les empreintes MD5 / SHA-1 / SHA-512 peuvent prendre du temps sur les gros fichiers.">
        <?= csrf_field() ?><input type="hidden" name="action" value="reverify">
        <button class="btn btn-ghost btn-block">Tout revérifier</button>
      </form>
    </div>
    <div class="card">
      <h3>Toujours refusées</h3>
      <p class="hint" style="margin:0">.<?= e(implode(' .', FORBIDDEN_EXT)) ?> — ainsi que les noms du type <code>photo.php.jpg</code> et les fichiers de configuration serveur (<code>.htaccess</code>, <code>.user.ini</code>…).</p>
    </div>
  </aside>
</div>
<?php elseif ($tab === 'versions'):
    $vStats = q('SELECT COUNT(*) n, COALESCE(SUM(size),0) b, COUNT(DISTINCT file_id) f FROM ' . t('file_versions'))->fetch(); ?>
<div class="layout-side reverse">
  <section class="card">
    <h2>Historique des versions</h2>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="versions">
      <label>Nombre de versions précédentes conservées par fichier
        <input type="number" name="versions_keep" min="0" max="1000" value="<?= versions_keep() ?>">
      </label>
      <p class="hint">À chaque nouvelle version, la plus ancienne au-delà de cette limite est supprimée du disque. <strong>0</strong> désactive l'historique : un fichier remplacé est alors supprimé définitivement.</p>
      <label class="check"><input type="checkbox" name="versions_public" value="1"<?= versions_public() ? ' checked' : '' ?>> Les visiteurs voient et peuvent télécharger les versions précédentes</label>
      <p class="hint">Sinon, l'historique n'est visible que des éditeurs et administrateurs. Les droits d'accès du fichier (public, membres, masqué) s'appliquent dans tous les cas.</p>
      <div class="form-actions"><button>Enregistrer</button></div>
    </form>
  </section>
  <aside class="card">
    <h3>Occupation</h3>
    <dl class="meta">
      <dt>Versions archivées</dt><dd><?= (int) $vStats['n'] ?></dd>
      <dt>Fichiers concernés</dt><dd><?= (int) $vStats['f'] ?></dd>
      <dt>Espace utilisé</dt><dd><?= human_size(num($vStats['b'])) ?></dd>
    </dl>
  </aside>
</div>

<?php elseif ($tab === 'notify'):
    $ev = setting('notify_events', []) + ['new' => true, 'version' => true, 'mismatch' => true];
    $tr = setting('mail_transport', 'mail');
    $me = current_user(); ?>
<form method="post" class="layout-side reverse" id="notify-form">
  <?= csrf_field() ?><input type="hidden" name="action" value="notify">
  <section>
    <div class="card form">
      <h2>Notifications par e-mail</h2>
      <label class="check"><input type="checkbox" name="notify_enabled" value="1"<?= setting('notify_enabled', false) ? ' checked' : '' ?>> <strong>Activer les notifications</strong></label>
      <div class="grid-3">
        <label class="check"><input type="checkbox" name="ev_new" value="1"<?= $ev['new'] ? ' checked' : '' ?>> Nouveaux fichiers</label>
        <label class="check"><input type="checkbox" name="ev_version" value="1"<?= $ev['version'] ? ' checked' : '' ?>> Nouvelles versions</label>
        <label class="check"><input type="checkbox" name="ev_mismatch" value="1"<?= $ev['mismatch'] ? ' checked' : '' ?>> Somme de contrôle invalide</label>
      </div>
      <label>Destinataires
        <textarea name="notify_to" rows="3" placeholder="une adresse par ligne"><?= e((string) setting('notify_to', '')) ?></textarea>
      </label>
      <label>Prévenir aussi les comptes (ayant une adresse e-mail)
        <select name="notify_roles">
          <?php foreach (['none' => 'Aucun compte', 'admin' => 'Administrateurs', 'editor' => 'Éditeurs et administrateurs', 'member' => 'Tous les comptes (membres compris)'] as $k => $l): ?>
            <option value="<?= $k ?>"<?= setting('notify_roles', 'none') === $k ? ' selected' : '' ?>><?= e($l) ?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <p class="hint">Les membres ne sont jamais avertis des fichiers masqués ; les alertes d'intégrité ne vont qu'aux éditeurs, administrateurs et destinataires ci-dessus. L'auteur d'un envoi ne reçoit pas sa propre notification. Un envoi groupé donne un seul e-mail.</p>
      <label>URL publique du site <span class="muted small">(pour les liens des e-mails)</span>
        <input name="site_url" value="<?= e((string) setting('site_url', '')) ?>" placeholder="<?= e(site_base_url()) ?>">
      </label>
    </div>

    <div class="card form">
      <h2>Envoi</h2>
      <div class="grid-2">
        <label>Adresse d'expéditeur
          <input type="email" name="mail_from" value="<?= e((string) setting('mail_from', '')) ?>" placeholder="<?= e(mail_from()[0]) ?>">
        </label>
        <label>Nom d'expéditeur
          <input name="mail_from_name" value="<?= e((string) setting('mail_from_name', '')) ?>" placeholder="<?= e((string) cfg('app_name')) ?>">
        </label>
      </div>
      <label>Méthode
        <select name="mail_transport" data-transport>
          <option value="mail"<?= $tr === 'mail' ? ' selected' : '' ?>>Serveur local — fonction mail() de PHP (Postfix / sendmail)</option>
          <option value="smtp"<?= $tr === 'smtp' ? ' selected' : '' ?>>Serveur SMTP</option>
        </select>
      </label>
      <div data-smtp<?= $tr === 'smtp' ? '' : ' hidden' ?>>
        <div class="grid-3">
          <label>Hôte SMTP<input name="smtp_host" value="<?= e((string) setting('smtp_host', '')) ?>" placeholder="mail.exemple.be"></label>
          <label>Port<input type="number" name="smtp_port" value="<?= (int) setting('smtp_port', 587) ?>"></label>
          <label>Sécurité
            <select name="smtp_secure">
              <?php foreach (['starttls' => 'STARTTLS (587)', 'ssl' => 'SSL/TLS (465)', 'none' => 'Aucune (25, local)'] as $k => $l): ?>
                <option value="<?= $k ?>"<?= setting('smtp_secure', 'starttls') === $k ? ' selected' : '' ?>><?= e($l) ?></option>
              <?php endforeach; ?>
            </select>
          </label>
        </div>
        <div class="grid-2">
          <label>Identifiant<input name="smtp_user" value="<?= e((string) setting('smtp_user', '')) ?>" autocomplete="off"></label>
          <label>Mot de passe
            <input type="password" name="smtp_pass" autocomplete="new-password" placeholder="<?= setting('smtp_pass', '') !== '' ? '•••••••• (inchangé)' : '' ?>">
          </label>
        </div>
        <?php if (setting('smtp_pass', '') !== ''): ?><label class="check"><input type="checkbox" name="smtp_pass_clear" value="1"> Effacer le mot de passe enregistré</label><?php endif; ?>
        <label class="check"><input type="checkbox" name="smtp_insecure" value="1"<?= setting('smtp_insecure', false) ? ' checked' : '' ?>> Accepter un certificat auto-signé (serveur interne)</label>
      </div>
      <div class="form-actions"><button>Enregistrer</button></div>
    </div>
  </section>

  <aside>
    <div class="card form">
      <h3>Tester l'envoi</h3>
      <p class="hint" style="margin:0 0 .6rem">Enregistrez d'abord vos réglages.</p>
      <label>Adresse<input type="email" name="test_to" form="test-form" value="<?= e((string) ($me['email'] ?? '')) ?>" required></label>
      <button form="test-form" class="btn-block">Envoyer un e-mail de test</button>
    </div>
    <div class="card">
      <h3>État</h3>
      <dl class="meta">
        <dt>Dernier envoi</dt><dd><?= e(fr_date(setting('mail_last_ok'), true)) ?></dd>
        <dt>Dernière erreur</dt><dd class="small"><?= e((string) (setting('mail_last_error') ?: '—')) ?></dd>
      </dl>
      <p class="hint" style="margin:.8rem 0 0">Sur YunoHost, la méthode « Serveur local » passe par le Postfix de la machine ; en SMTP, utilisez le port 587 avec un compte de la messagerie.</p>
    </div>
  </aside>
</form>
<form method="post" id="test-form"><?= csrf_field() ?><input type="hidden" name="action" value="test_mail"></form>
<?php else:
    $inv = crypto_inventory();
    $present = array_filter($inv, fn($i) => $i['present']);
    $encItems = array_filter($present, fn($i) => $i['encrypted']);
    $plainItems = array_filter($present, fn($i) => !$i['encrypted']);
    $encBytes = array_sum(array_column($encItems, 'size'));
    $plainBytes = array_sum(array_column($plainItems, 'size'));
    $hasKey = master_key() !== null;
    $cst = crypto_state();
    $cRunning = ($cst['state'] ?? '') === 'running';
    $keyPath = encryption_key_path(); ?>
<?php if (!crypto_available()): ?>
  <div class="alert alert-error">L'extension PHP <strong>sodium</strong> est absente : le chiffrement n'est pas disponible. Sous Debian/YunoHost elle est fournie avec PHP (<code>php -m | grep sodium</code>).</div>
<?php elseif (!$hasKey && $encItems): ?>
  <div class="alert alert-error"><strong>Clé de chiffrement introuvable</strong> alors que <?= count($encItems) ?> fichier(s) sont chiffrés : ils ne peuvent plus être téléchargés.
    Restaurez la sauvegarde de la clé dans <code><?= e($keyPath) ?></code> (droits 0400). <strong>Ne créez pas de nouvelle clé</strong> : elle ne déchiffrerait pas les fichiers existants.</div>
<?php endif; ?>

<section class="card import-progress" data-crypto-progress data-url="<?= e(url('admin/settings.php?crypto_progress=1')) ?>"<?= $cRunning ? '' : ' hidden' ?>>
  <div class="ip-head"><h3 data-ip-title>Conversion en cours</h3><span class="ip-pct" data-ip-pct>0 %</span></div>
  <div class="progress ip-bar"><div class="bar" data-ip-bar></div></div>
  <div class="ip-info"><span data-ip-phase>Préparation…</span><span data-ip-stats></span></div>
  <div data-ip-messages></div>
  <div class="ip-actions" data-ip-actions hidden><a class="btn" href="?tab=crypto">Terminé — actualiser</a></div>
</section>

<div class="layout-side reverse">
  <section>
    <div class="card">
      <h2>Chiffrement des fichiers sur le serveur</h2>
      <p>Les fichiers sont chiffrés sur le disque avec <strong>XChaCha20-Poly1305</strong> (libsodium), chacun avec sa propre clé, elle-même protégée par la <strong>clé maîtresse</strong>.
        Le déchiffrement est transparent au téléchargement : liens publics, reprise, aperçu et sommes de contrôle continuent de fonctionner.</p>
      <ul class="checklist small">
        <li>✔ Protège contre : vol ou revente du disque, sauvegardes et snapshots (Proxmox, hébergeur), copie du dossier <code>storage</code>, autre utilisateur du serveur.</li>
        <li>✔ Toute altération d'un fichier chiffré est détectée (chiffrement authentifié).</li>
        <li>✖ Ne protège pas contre une personne qui contrôle entièrement le serveur (la clé y est présente pour pouvoir servir les fichiers).</li>
      </ul>
      <div class="tiles" style="margin:1rem 0 0">
        <div class="tile"><span class="tile-label">Chiffrés 🔒</span><strong><?= count($encItems) ?></strong><span class="muted small"><?= human_size($encBytes) ?></span></div>
        <div class="tile"><span class="tile-label">En clair</span><strong><?= count($plainItems) ?></strong><span class="muted small"><?= human_size($plainBytes) ?></span></div>
      </div>
    </div>

    <?php if ($hasKey): ?>
    <div class="card form">
      <h3>Nouveaux fichiers</h3>
      <form method="post">
        <?= csrf_field() ?><input type="hidden" name="action" value="crypto_toggle">
        <label class="check"><input type="checkbox" name="encrypt_new" value="1"<?= setting('encrypt_new', false) ? ' checked' : '' ?>> <strong>Chiffrer les nouveaux fichiers</strong> (envois, imports, sommes générées)</label>
        <p class="hint">Les envois par morceaux sont chiffrés à leur arrivée et l'import chiffre pendant sa lecture : le contenu en clair n'est jamais écrit dans le stockage.</p>
        <div class="form-actions"><button>Enregistrer</button></div>
      </form>
    </div>

    <div class="card">
      <h3>Fichiers existants</h3>
      <p class="hint" style="margin:0 0 .8rem">Conversion en arrière-plan, fichier par fichier, avec contrôle du SHA-256 avant de remplacer l'original : en cas de problème, le fichier est laissé intact. Le site reste utilisable pendant l'opération.</p>
      <div class="gen-actions">
        <form method="post" data-crypto-start><?= csrf_field() ?><input type="hidden" name="action" value="crypto_convert"><input type="hidden" name="mode" value="encrypt">
          <button<?= $plainItems && !$cRunning ? '' : ' disabled' ?>>🔒 Chiffrer les <?= count($plainItems) ?> fichier(s) en clair (<?= human_size($plainBytes) ?>)</button></form>
        <form method="post" data-crypto-start data-ask="Remettre en clair les <?= count($encItems) ?> fichier(s) chiffrés ?"><?= csrf_field() ?><input type="hidden" name="action" value="crypto_convert"><input type="hidden" name="mode" value="decrypt">
          <button class="btn-ghost"<?= $encItems && !$cRunning ? '' : ' disabled' ?>>Tout déchiffrer</button></form>
      </div>
    </div>
    <?php endif; ?>
  </section>

  <aside>
    <div class="card<?= $hasKey ? '' : ' integrity-card bad' ?>">
      <h3>Clé maîtresse</h3>
      <dl class="meta">
        <dt>sodium</dt><dd><?= crypto_available() ? '✔ disponible' : '✖ absent' ?></dd>
        <dt>Emplacement</dt><dd class="small"><code><?= e($keyPath) ?></code></dd>
        <dt>État</dt><dd><?= $hasKey ? '✔ présente' : '<strong style="color:var(--err)">absente</strong>' ?></dd>
        <?php if ($hasKey): ?><dt>Empreinte</dt><dd><code><?= e(key_fingerprint()) ?></code></dd><?php endif; ?>
      </dl>
      <?php if (!$hasKey && crypto_available() && !$encItems): ?>
        <form method="post" style="margin-top:.8rem"><?= csrf_field() ?><input type="hidden" name="action" value="crypto_genkey">
          <button class="btn-block">Créer la clé de chiffrement</button></form>
        <p class="hint" style="margin:.5rem 0 0">Hors du dossier web et du stockage. Pour un autre emplacement : <code>encryption_key_file</code> dans <code>config.php</code>.</p>
      <?php endif; ?>
    </div>
    <?php if ($hasKey): ?>
    <div class="card form">
      <h3>Sauvegarde de la clé</h3>
      <p class="hint" style="margin:0 0 .6rem"><strong>Sans la clé, les fichiers chiffrés sont définitivement perdus.</strong> Gardez-en une copie hors du serveur — et pensez-y en restaurant une sauvegarde ou en migrant.</p>
      <form method="post">
        <?= csrf_field() ?><input type="hidden" name="action" value="crypto_backup">
        <label>Votre mot de passe<input type="password" name="password" required autocomplete="current-password"></label>
        <button class="btn-block btn-ghost">⬇ Télécharger la clé</button>
      </form>
    </div>
    <?php endif; ?>
  </aside>
</div>
<script>
(function () {
  const box = document.querySelector('[data-crypto-progress]');
  if (!box) return;
  const $ = (s) => box.querySelector(s);
  const bar = $('[data-ip-bar]'), pct = $('[data-ip-pct]'), phase = $('[data-ip-phase]'), stats = $('[data-ip-stats]'), msgs = $('[data-ip-messages]'), actions = $('[data-ip-actions]'), title = $('[data-ip-title]');
  const human = (b) => { const u = ['o', 'Ko', 'Mo', 'Go', 'To']; let i = 0; b = +b || 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; } return (i ? b.toFixed(1).replace('.', ',') : Math.round(b)) + ' ' + u[i]; };
  const dur = (s) => s < 60 ? Math.max(1, Math.round(s)) + ' s' : s < 3600 ? Math.floor(s / 60) + ' min ' + String(Math.round(s % 60)).padStart(2, '0') + ' s' : (s / 3600).toFixed(1).replace('.', ',') + ' h';
  const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let timer = null;
  function render(st) {
    if (!st || st.state === 'idle') return;
    box.hidden = false;
    const verb = st.mode === 'decrypt' ? 'Déchiffrement' : 'Chiffrement';
    const total = +st.total || 0, done = Math.min(+st.done || 0, total);
    const p = total ? Math.floor(done / total * 1000) / 10 : (st.state === 'done' ? 100 : 0);
    bar.style.width = (st.state === 'done' ? 100 : p) + '%';
    pct.textContent = (st.state === 'done' ? '100' : p.toFixed(p < 10 ? 1 : 0).replace('.', ',')) + ' %';
    box.classList.toggle('is-running', st.state === 'running');
    box.classList.toggle('is-done', st.state === 'done' && !(+st.errors));
    if (st.state === 'running') {
      title.textContent = verb + ' en cours';
      phase.textContent = st.count ? 'Fichier ' + Math.min((+st.index || 0) + 1, st.count) + '/' + st.count + ' — ' + (st.current || '') : 'Inventaire…';
      const sp = +st.speed || 0;
      stats.textContent = human(done) + ' / ' + human(total) + (sp > 0 ? ' · ' + human(sp) + '/s · reste ' + dur((total - done) / sp) : '');
    } else {
      clearInterval(timer); timer = null;
      title.textContent = verb + (st.state === 'done' ? ' terminé' : ' interrompu');
      phase.textContent = ''; stats.textContent = st.elapsed ? human(total) + ' en ' + dur(+st.elapsed) : '';
      box.classList.toggle('ip-failed', st.state !== 'done' || +st.errors > 0);
      msgs.innerHTML = (st.messages || []).map((m) => '<div class="alert alert-' + (m[0] === 'error' ? 'error' : 'success') + '">' + esc(m[1]) + '</div>').join('');
      actions.hidden = false;
    }
  }
  function poll() { fetch(box.dataset.url, { credentials: 'same-origin', cache: 'no-store' }).then((r) => r.json()).then(render).catch(() => {}); }
  function start() { if (!timer) { poll(); timer = setInterval(poll, 1000); } }
  if (!box.hidden) start();
  document.querySelectorAll('form[data-crypto-start]').forEach((f) => f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (f.dataset.ask && !confirm(f.dataset.ask)) return;
    document.querySelectorAll('form[data-crypto-start] button').forEach((b) => (b.disabled = true));
    box.hidden = false; msgs.innerHTML = ''; actions.hidden = true; box.classList.remove('ip-failed', 'is-done');
    title.textContent = 'Conversion en cours'; phase.textContent = 'Démarrage…'; bar.style.width = '0'; pct.textContent = '0 %';
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setTimeout(start, 400);
    fetch(location.pathname, { method: 'POST', body: new FormData(f), credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } }).catch(() => {});
  }));
})();
</script>
<?php endif; ?>
<?php render_footer();
