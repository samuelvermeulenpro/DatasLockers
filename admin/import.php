<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('editor');

/*
 * Import de fichiers déposés directement sur le serveur (SFTP, scp, rsync, montage réseau…)
 * dans le dossier défini par 'import_path' (config.php). Aucune limite de taille.
 */

$dir = rtrim((string) cfg('import_path', ''), '/\\');
$dirOk = $dir !== '' && is_dir($dir) && is_readable($dir);

/** Fichiers importables du dossier (premier niveau, fichiers ordinaires, hors fichiers cachés) */
function import_list(string $dir): array
{
    $out = [];
    foreach (scandir($dir) ?: [] as $n) {
        $p = $dir . DIRECTORY_SEPARATOR . $n;
        if ($n[0] === '.' || !is_file($p) || is_link($p)) {
            continue;
        }
        $out[$n] = ['name' => $n, 'size' => fsize($p), 'mtime' => (int) filemtime($p),
                    'error' => check_extension(trim(preg_replace('/[\x00-\x1F\x7F]+/', '_', $n), ' .')), 'busy' => time() - (int) filemtime($p) < 30];
    }
    ksort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
}

/* ---------- Suivi de l'import en temps réel ----------
 * L'import tourne en arrière-plan (après la réponse HTTP) et écrit son avancement dans
 * storage/.chunks/import.json ; la page l'interroge chaque seconde (?progress=1).
 */
function import_state_path(): string
{
    return chunk_dir() . '/import.json';
}

function import_state(): ?array
{
    $p = import_state_path();
    $st = is_file($p) ? json_decode((string) @file_get_contents($p), true) : null;
    if (!is_array($st)) {
        return null;
    }
    // processus PHP arrêté en cours de route (redémarrage, délai dépassé…) : plus de nouvelles depuis 10 min
    if ($st['state'] === 'running' && (int) ($st['updated'] ?? 0) < time() - 600) {
        $st['state'] = 'error';
        $st['messages'][] = ['error', 'L\'import s\'est arrêté sans terminer (processus PHP interrompu ? voir request_terminate_timeout).'];
    }
    return $st;
}

function import_running(): bool
{
    return (import_state()['state'] ?? '') === 'running';
}

/** Écriture atomique de l'état (le navigateur ne lit jamais un fichier à moitié écrit) */
function import_state_save(array $st): void
{
    $st['updated'] = time();
    $tmp = import_state_path() . '.' . getmypid();
    file_put_contents($tmp, json_encode($st, JSON_UNESCAPED_UNICODE));
    @rename($tmp, import_state_path());
}

/** Journal des derniers imports */
function import_log(string $type, string $msg): void
{
    $log = (array) setting('import_log', []);
    array_unshift($log, ['t' => date('Y-m-d H:i:s'), 'type' => $type, 'msg' => $msg]);
    setting_set('import_log', array_slice($log, 0, 30));
}

/**
 * Importe les fichiers en tenant l'état à jour. Une seule lecture par fichier :
 * déplacement (ou copie) + SHA-256 + empreintes automatiques (MD5, SHA-1, SHA-512…).
 */
function import_job(string $dir, array $names, array $v, bool $keep, int $uid): void
{
    @set_time_limit(0);
    ignore_user_abort(true);
    $st = import_state();
    $available = import_list($dir);
    $algos = array_values(array_unique(array_merge(['sha256'], auto_hashes())));
    $doneBefore = 0;
    $newIds = [];
    $t0 = microtime(true);
    $lastWrite = 0.0;

    $tick = function (string $phase, int|float $fileDone, bool $force = false) use (&$st, &$doneBefore, $t0, &$lastWrite) {
        $now = microtime(true);
        if (!$force && $now - $lastWrite < 0.5) {
            return;
        }
        $lastWrite = $now;
        $st['phase'] = $phase;
        $st['done'] = $doneBefore + $fileDone;
        $st['files'][$st['current']]['done'] = $fileDone;
        $el = max(0.001, $now - $t0);
        $st['elapsed'] = round($el, 1);
        $st['speed'] = $st['done'] / $el;
        import_state_save($st);
    };

    foreach ($names as $i => $n) {
        $st['current'] = $i;
        $st['files'][$i]['status'] = 'running';
        $size = $available[$n]['size'] ?? 0;
        $src = $dir . DIRECTORY_SEPARATOR . $n;
        try {
            if (!isset($available[$n])) {
                throw new RuntimeException('fichier disparu du dossier d\'import');
            }
            $name = clean_upload_name($n);
            if (($err = check_extension($name)) !== null) {
                throw new RuntimeException($err);
            }
            $stored = bin2hex(random_bytes(16));
            $dest = storage_path($stored);
            $moved = false;
            if (encryption_enabled()) {
                // chiffrement pendant l'unique lecture (empreintes comprises) ; l'original est supprimé ensuite
                $tick('encrypt', 0, true);
                $digests = encrypt_into($src, $dest, $algos, fn($d) => $tick('encrypt', $d));
            } else {
                $tick('move', 0, true);
                $moved = !$keep && @rename($src, $dest);
                if ($moved) {
                    // même disque : déplacement instantané, puis une lecture pour les empreintes
                    $digests = multi_digest($dest, $algos, fn($d) => $tick('hash', $d));
                } else {
                    // autre disque (ou copie conservée) : copie + empreintes dans la même lecture
                    $out = @fopen($dest, 'wb');
                    if (!$out) {
                        throw new RuntimeException('copie impossible (droits sur le dossier de stockage ?)');
                    }
                    try {
                        $digests = multi_digest($src, $algos, fn($d) => $tick('copy', $d), $out);
                    } catch (RuntimeException $ex) {
                        fclose($out);
                        @unlink($dest);
                        throw $ex;
                    }
                    fclose($out);
                }
            }
            @chmod($dest, 0640);
            $tick('save', $size, true);
            try {
                $fid = insert_file([
                    'original_name' => $name,
                    'stored_name'   => $stored,
                    'mime'          => stored_mime($dest),
                    'size'          => stored_size($dest),
                    'sha256'        => $digests['sha256'],
                ], $v, $uid);
            } catch (Throwable $ex) {
                // l'enregistrement a échoué : le fichier retourne dans le dossier d'import (jamais d'orphelin)
                $moved ? @rename($dest, $src) : @unlink($dest);
                throw new RuntimeException('enregistrement impossible (' . $ex->getMessage() . ') — le fichier est resté dans le dossier d\'import', 0, $ex);
            }
            store_digests($fid, $digests);
            $newIds[] = $fid;
            if (!$moved && !$keep && !@unlink($src)) {
                $st['messages'][] = ['info', '« ' . $n . ' » importé, mais l\'original n\'a pas pu être supprimé du dossier d\'import (droits).'];
            }
            $st['files'][$i]['status'] = 'ok';
            $st['files'][$i]['id'] = $fid;
        } catch (Throwable $ex) {
            $st['files'][$i]['status'] = 'error';
            $st['files'][$i]['error'] = $ex->getMessage();
            $st['messages'][] = ['error', $n . ' : ' . $ex->getMessage() . '.'];
        }
        $doneBefore += $size;
        $tick('next', 0, true);
    }

    // Vérification des sommes (les empreintes sont déjà en cache : rapide)
    $st['phase'] = 'verify';
    import_state_save($st);
    $mismatch = [];
    foreach ($newIds as $nid) {
        $mismatch = array_merge($mismatch, integrity_process(file_row($nid)));
    }
    $summary = integrity_summary($newIds);
    foreach ($st['files'] as $k => $f) {
        if (!empty($f['id'])) {
            $st['files'][$k]['integrity'] = $summary[$f['id']] ?? null;
            $st['files'][$k]['url'] = url('file.php?id=' . $f['id']);
        }
    }
    if ($newIds) {
        $st['messages'][] = ['success', count($newIds) . ' fichier(s) importé(s) en ' . round(microtime(true) - $t0) . ' s.'];
    }
    foreach (array_unique(array_filter($mismatch)) as $bid) {
        if ($bf = file_row($bid)) {
            $st['messages'][] = ['error', '✖ « ' . $bf['title'] . ' » ne correspond pas à sa somme de contrôle.'];
        }
    }
    $st['state'] = 'done';
    $st['phase'] = 'done';
    $st['done'] = $st['total'];
    $st['finished'] = date('c');
    import_state_save($st);
    foreach ($st['messages'] as [$type, $msg]) {
        import_log($type, $msg);
    }
    if ($newIds) {
        notify_files(array_map(fn($nid) => ['file' => file_row($nid), 'type' => 'new'], $newIds), $mismatch, $uid);
    }
}

$v = ['description' => '', 'version' => '', 'version_notes' => '', 'category_id' => null, 'visibility' => 'public'];
$isAjax = ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest';

// Avancement (interrogé par la page chaque seconde)
if (isset($_GET['progress'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(import_state() ?? ['state' => 'idle'], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $dirOk) {
    csrf_check();
    $fail = function (string $msg) use ($isAjax): never {
        if ($isAjax) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
            exit;
        }
        flash('error', e($msg));
        redirect('admin/import.php');
    };
    if (import_running()) {
        $fail('Un import est déjà en cours : patientez jusqu\'à la fin.');
    }
    $v['version'] = mb_substr(trim((string) ($_POST['version'] ?? '')), 0, 40);
    $v['version_notes'] = trim((string) ($_POST['version_notes'] ?? ''));
    $v['description'] = trim((string) ($_POST['description'] ?? ''));
    $v['category_id'] = ($_POST['category_id'] ?? '') !== '' ? (int) $_POST['category_id'] : null;
    $v['visibility'] = in_array($_POST['visibility'] ?? '', ['public', 'private', 'hidden'], true) ? $_POST['visibility'] : 'public';
    $keep = isset($_POST['keep']);
    $uid = (int) $me['id'];

    $available = import_list($dir);
    $names = array_values(array_filter((array) ($_POST['names'] ?? []), fn($n) => is_string($n) && isset($available[$n]) && !$available[$n]['error']));
    if (!$names) {
        $fail('Sélectionnez au moins un fichier importable.');
    }
    $total = 0;
    $files = [];
    foreach ($names as $n) {
        $total += $available[$n]['size'];
        $files[] = ['name' => $n, 'size' => $available[$n]['size'], 'done' => 0, 'status' => 'waiting'];
    }
    import_state_save([
        'state' => 'running', 'phase' => 'start', 'started' => date('c'), 'by' => $me['username'],
        'total' => $total, 'done' => 0, 'speed' => 0, 'elapsed' => 0, 'current' => 0,
        'files' => $files, 'messages' => [],
    ]);
    // La réponse part tout de suite ; l'import continue sur le serveur (suivi en temps réel)
    defer_after_response(function () use ($dir, $names, $v, $keep, $uid) {
        try {
            import_job($dir, $names, $v, $keep, $uid);
        } catch (Throwable $ex) {
            $st = import_state() ?? [];
            $st['state'] = 'error';
            $st['messages'][] = ['error', 'Import interrompu : ' . $ex->getMessage()];
            import_state_save($st);
            import_log('error', 'Import interrompu : ' . $ex->getMessage());
        }
    });
    if ($isAjax) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }
    redirect('admin/import.php');
}

$list = $dirOk ? import_list($dir) : [];
$state = $dirOk ? import_state() : null;
$running = ($state['state'] ?? '') === 'running';
$locked = $running ? array_column($state['files'], 'name') : [];
$log = (array) setting('import_log', []);
render_header('Importer depuis le serveur', 'import');
?>
<div class="page-head">
  <div><h1>Importer depuis le serveur</h1>
  <p class="muted">Pour les très gros fichiers : déposez-les par SFTP / scp dans le dossier d'import, puis importez-les ici — sans limite de taille.</p></div>
  <a class="btn btn-ghost" href="<?= e(url('admin/upload.php')) ?>">Envoi par le navigateur</a>
</div>

<?php if (!$dirOk): ?>
  <div class="card">
    <h2>Dossier d'import non configuré</h2>
    <?php if ($dir !== ''): ?><div class="alert alert-error">Le dossier <code><?= e($dir) ?></code> n'existe pas ou n'est pas lisible par PHP.</div><?php endif; ?>
    <p>Ajoutez dans <code>config.php</code> :</p>
    <pre class="text-preview">'import_path' => '/var/lib/svpro-downloads/import',</pre>
    <p class="muted small">Le dossier doit être lisible (et, pour déplacer plutôt que copier, modifiable) par l'utilisateur de PHP — sur YunoHost, celui de l'application. Placé sur le même disque que le stockage, l'import est instantané.</p>
  </div>
<?php else: ?>
<section class="card import-progress" data-import-progress data-url="<?= e(url('admin/import.php?progress=1')) ?>"<?= $running ? '' : ' hidden' ?>>
  <div class="ip-head">
    <h3 data-ip-title>Import en cours</h3>
    <span class="ip-pct" data-ip-pct>0 %</span>
  </div>
  <div class="progress ip-bar"><div class="bar" data-ip-bar></div></div>
  <div class="ip-info">
    <span data-ip-phase>Préparation…</span>
    <span data-ip-stats></span>
  </div>
  <ul class="ip-files" data-ip-files></ul>
  <div data-ip-messages></div>
  <div class="ip-actions" data-ip-actions hidden>
    <a class="btn" href="<?= e(url('admin/import.php')) ?>">Terminé — actualiser la liste</a>
    <a class="btn btn-ghost" href="<?= e(url('admin/files.php')) ?>">Voir les fichiers</a>
  </div>
</section>

<form method="post" class="layout-side reverse" data-import-form>
  <?= csrf_field() ?>
  <section class="card table-card">
    <div class="card-head"><h3>Fichiers dans <code><?= e($dir) ?></code></h3><a class="btn btn-ghost btn-sm" href="">↻ Actualiser</a></div>
    <table class="table">
      <thead><tr><th class="w-check"><input type="checkbox" data-check-all-import aria-label="Tout sélectionner"></th><th>Fichier</th><th class="num">Taille</th><th class="hide-sm">Déposé le</th></tr></thead>
      <tbody>
      <?php if (!$list): ?><tr><td colspan="4" class="empty-row">Le dossier est vide.</td></tr><?php endif; ?>
      <?php foreach ($list as $it): ?>
        <tr<?= $it['error'] ? ' class="dim"' : '' ?>>
          <td class="w-check"><?php if (!$it['error'] && !in_array($it['name'], $locked, true)): ?><input type="checkbox" name="names[]" value="<?= e($it['name']) ?>" data-import-check><?php endif; ?></td>
          <td><div class="file-cell"><?= kind_badge($it['name']) ?><div><strong><?= e($it['name']) ?></strong>
            <?php if ($it['error']): ?><div class="small" style="color:var(--err)"><?= e($it['error']) ?></div><?php endif; ?>
            <?php if (in_array($it['name'], $locked, true)): ?><div class="small muted">⏳ import en cours…</div>
            <?php elseif ($it['busy']): ?><div class="small muted">⏳ modifié il y a moins de 30 s — transfert peut-être en cours</div><?php endif; ?></div></div></td>
          <td class="num"><?= human_size($it['size']) ?></td>
          <td class="hide-sm"><?= date('d/m/Y H:i', $it['mtime']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </section>

  <aside class="card form">
    <h3>Importer la sélection</h3>
    <label>Catégorie
      <select name="category_id"><option value="">— Sans catégorie —</option><?= category_options(null) ?></select>
    </label>
    <label>Accès
      <select name="visibility">
        <option value="public">Public</option><option value="private">Membres</option><option value="hidden">Masqué</option>
      </select>
    </label>
    <label>Version<input name="version" maxlength="40" placeholder="ex. 24.04.1"></label>
    <label>Notes de version<textarea name="version_notes" rows="3"></textarea></label>
    <label class="check"><input type="checkbox" name="keep" value="1"> Laisser une copie dans le dossier d'import</label>
    <button class="btn-block" data-confirm-import<?= $running ? ' disabled' : '' ?>>Importer</button>
    <p class="hint" style="margin-top:.6rem">Le titre est tiré du nom du fichier (modifiable ensuite). Les fichiers de sommes importés en même temps sont vérifiés aussitôt.</p>
  </aside>
</form>
<?php if ($log): ?>
  <section class="card">
    <h3>Derniers imports</h3>
    <ul class="checks-list">
      <?php foreach (array_slice($log, 0, 10) as $l): ?>
        <li class="check-<?= $l['type'] === 'error' ? 'mismatch' : ($l['type'] === 'success' ? 'ok' : '') ?>"><span class="muted small"><?= e(date('d/m H:i', strtotime($l['t']))) ?></span> — <?= e($l['msg']) ?></li>
      <?php endforeach; ?>
    </ul>
  </section>
<?php endif; ?>
<?php endif; ?>
<script>
(function () {
  const all = document.querySelector('[data-check-all-import]');
  const boxes = Array.from(document.querySelectorAll('[data-import-check]'));
  if (all) all.addEventListener('change', () => boxes.forEach((b) => (b.checked = all.checked)));
  const form = document.querySelector('[data-import-form]');
  const btn = document.querySelector('[data-confirm-import]');
  const box = document.querySelector('[data-import-progress]');
  if (!box) return;
  const $ = (s) => box.querySelector(s);
  const bar = $('[data-ip-bar]'), pct = $('[data-ip-pct]'), phase = $('[data-ip-phase]'), stats = $('[data-ip-stats]');
  const list = $('[data-ip-files]'), msgs = $('[data-ip-messages]'), actions = $('[data-ip-actions]'), title = $('[data-ip-title]');
  const human = (b) => { const u = ['o', 'Ko', 'Mo', 'Go', 'To']; let i = 0; b = +b || 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; } return (i ? b.toFixed(1).replace('.', ',') : Math.round(b)) + ' ' + u[i]; };
  const dur = (s) => s < 60 ? Math.max(1, Math.round(s)) + ' s' : s < 3600 ? Math.floor(s / 60) + ' min ' + String(Math.round(s % 60)).padStart(2, '0') + ' s' : (s / 3600).toFixed(1).replace('.', ',') + ' h';
  const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const PHASES = { start: 'Préparation…', move: 'Déplacement vers le stockage…', copy: 'Copie et calcul des empreintes…', encrypt: '🔒 Chiffrement et calcul des empreintes…', hash: 'Calcul des empreintes (SHA-256, MD5…)…', save: 'Enregistrement…', next: 'Fichier suivant…', verify: 'Vérification des sommes de contrôle…', done: 'Terminé' };
  const ICON = { waiting: '○', running: '◐', ok: '✔', error: '✖' };
  let timer = null, fails = 0;

  function render(st) {
    if (!st || st.state === 'idle') return;
    box.hidden = false;
    const total = +st.total || 0, done = Math.min(+st.done || 0, total);
    const p = total ? Math.floor(done / total * 1000) / 10 : (st.state === 'done' ? 100 : 0);
    bar.style.width = p + '%';
    pct.textContent = (st.state === 'done' ? 100 : p.toFixed(p < 10 ? 1 : 0)).toString().replace('.', ',') + ' %';
    const n = st.files.length, cur = (st.current || 0) + 1;
    phase.textContent = (st.state === 'running' && n > 1 ? 'Fichier ' + Math.min(cur, n) + '/' + n + ' — ' : '') + (PHASES[st.phase] || st.phase);
    const speed = +st.speed || 0;
    stats.textContent = st.state === 'running'
      ? human(done) + ' / ' + human(total) + (speed > 0 ? ' · ' + human(speed) + '/s · reste ' + dur((total - done) / speed) : '')
      : human(total) + ' en ' + dur(+st.elapsed || 0);
    list.innerHTML = st.files.map((f) => {
      const fp = f.size ? Math.min(100, Math.floor(f.done / f.size * 100)) : (f.status === 'ok' ? 100 : 0);
      const integ = f.integrity === 'ok' ? ' <span class="integrity ok">✔ vérifié</span>' : f.integrity === 'mismatch' ? ' <span class="integrity bad">✖ somme invalide</span>' : '';
      const name = f.url ? '<a href="' + esc(f.url) + '">' + esc(f.name) + '</a>' : esc(f.name);
      return '<li class="ip-' + f.status + '"><span class="ip-ico">' + ICON[f.status] + '</span><span class="ip-name">' + name + integ
        + (f.error ? '<span class="ip-err">' + esc(f.error) + '</span>' : '') + '</span>'
        + '<span class="ip-mini"><span style="width:' + (f.status === 'ok' ? 100 : fp) + '%"></span></span><span class="ip-size">' + human(f.size) + '</span></li>';
    }).join('');
    box.classList.toggle('is-running', st.state === 'running');
    box.classList.toggle('is-done', st.state === 'done' && !(st.messages || []).some((m) => m[0] === 'error'));
    if (st.state !== 'running') {
      clearInterval(timer); timer = null;
      box.classList.toggle('ip-failed', st.state === 'error' || (st.messages || []).some((m) => m[0] === 'error'));
      title.textContent = st.state === 'done' ? 'Import terminé' : 'Import interrompu';
      msgs.innerHTML = (st.messages || []).map((m) => '<div class="alert alert-' + (m[0] === 'error' ? 'error' : m[0] === 'success' ? 'success' : 'info') + '">' + esc(m[1]) + '</div>').join('');
      actions.hidden = false;
      if (btn) btn.disabled = false;
    } else {
      title.textContent = 'Import en cours' + (st.by ? ' (par ' + st.by + ')' : '');
      if (btn) btn.disabled = true;
    }
  }

  function poll() {
    fetch(box.dataset.url, { credentials: 'same-origin', cache: 'no-store' })
      .then((r) => r.json()).then((st) => { fails = 0; render(st); })
      .catch(() => { if (++fails > 5) phase.textContent = 'Connexion au serveur perdue — nouvel essai…'; });
  }
  function start() { if (!timer) { poll(); timer = setInterval(poll, 1000); } }

  if (!box.hidden) start(); // un import tourne déjà (page rouverte en cours de route)

  if (form) form.addEventListener('submit', (e) => {
    const n = boxes.filter((b) => b.checked).length;
    e.preventDefault();
    if (!n) { phase.textContent = ''; box.hidden = true; if (window.toast) toast('Sélectionnez au moins un fichier'); else alert('Sélectionnez au moins un fichier.'); return; }
    btn.disabled = true;
    msgs.innerHTML = ''; actions.hidden = true; box.classList.remove('ip-failed');
    box.hidden = false; bar.style.width = '0'; pct.textContent = '0 %'; phase.textContent = 'Démarrage…'; title.textContent = 'Import en cours';
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
    const fd = new FormData(form);
    // on suit l'avancement dès maintenant, même si le serveur garde la requête ouverte (Apache mod_php)
    setTimeout(start, 400);
    fetch(location.pathname, { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then((r) => r.json()).then((res) => {
        if (!res.ok) { clearInterval(timer); timer = null; btn.disabled = false; box.classList.add('ip-failed'); title.textContent = 'Import impossible'; phase.textContent = res.error; }
      }).catch(() => { /* la requête peut rester ouverte : le suivi continue */ });
  });
})();
</script>
<?php render_footer();
