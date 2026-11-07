<?php
declare(strict_types=1);

/**
 * Fichiers : réception des envois, versions, suppression.
 */

/** Nom de fichier assaini (caractères de contrôle et séparateurs retirés) ; exception si invalide */
function clean_upload_name(string $raw): string
{
    $name = trim(preg_replace('/[\x00-\x1F\x7F\/\\\\]+/', '_', $raw), " .");
    if ($name === '' || mb_strlen($name) > 255 || !mb_check_encoding($name, 'UTF-8')) {
        throw new RuntimeException('nom de fichier invalide');
    }
    return $name;
}

/** Valide et range un fichier envoyé (classique ou par morceaux) ; retourne les métadonnées ou lève une exception */
function store_upload(array $up, int|float $maxBytes): array
{
    if (isset($up['chunk'])) {
        return store_chunked($up['chunk'], $maxBytes);
    }
    if ($up['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException(match ($up['error']) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'fichier trop volumineux pour la configuration PHP',
            UPLOAD_ERR_PARTIAL  => 'envoi interrompu',
            UPLOAD_ERR_NO_FILE  => 'aucun fichier',
            default             => 'erreur d\'envoi (' . $up['error'] . ')',
        });
    }
    if (!is_uploaded_file($up['tmp_name'])) {
        throw new RuntimeException('envoi invalide');
    }
    $name = clean_upload_name((string) $up['name']);
    if (($err = check_extension($name)) !== null) {
        throw new RuntimeException($err);
    }
    if ($up['size'] > $maxBytes) {
        throw new RuntimeException('dépasse ' . human_size($maxBytes));
    }
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($up['tmp_name']) ?: 'application/octet-stream';
    $stored = bin2hex(random_bytes(16));
    $dest = storage_path($stored);
    if (encryption_enabled()) {
        // chiffré directement depuis le fichier temporaire de PHP : le clair n'arrive jamais dans le stockage
        $size = fsize($up['tmp_name']);
        $sha = encrypt_into($up['tmp_name'], $dest, ['sha256'])['sha256'];
    } else {
        if (!move_uploaded_file($up['tmp_name'], $dest)) {
            throw new RuntimeException('impossible d\'écrire dans le dossier de stockage');
        }
        $size = fsize($dest);
        $sha = hash_file('sha256', $dest);
    }
    @chmod($dest, 0640);
    return [
        'original_name' => $name,
        'stored_name'   => $stored,
        'mime'          => mb_substr($mime, 0, 120),
        'size'          => $size,
        'sha256'        => $sha,
    ];
}

/**
 * Copie chiffrée d'un fichier ordinaire vers le stockage, empreintes calculées dans la même lecture.
 * @return array<string,string> empreintes du contenu en clair
 */
function encrypt_into(string $srcPath, string $dest, array $algos, ?callable $progress = null): array
{
    $out = @fopen($dest, 'wb');
    if (!$out) {
        throw new RuntimeException('écriture impossible dans le dossier de stockage');
    }
    try {
        $digests = multi_digest($srcPath, $algos, $progress, new EncWriter($out, fsize($srcPath)));
        fclose($out);
        return $digests;
    } catch (Throwable $ex) {
        fclose($out);
        @unlink($dest);
        throw $ex instanceof RuntimeException ? $ex : new RuntimeException($ex->getMessage(), 0, $ex);
    }
}

/** Range un contenu produit par l'application (ex. fichier de sommes généré) */
function store_generated(string $name, string $content): array
{
    $stored = bin2hex(random_bytes(16));
    $dest = storage_path($stored);
    if (encryption_enabled()) {
        $fh = fopen($dest, 'wb');
        $w = new EncWriter($fh, strlen($content));
        $w->write($content);
        $w->finish();
        fclose($fh);
    } elseif (file_put_contents($dest, $content, LOCK_EX) === false) {
        throw new RuntimeException('impossible d\'écrire dans le dossier de stockage');
    }
    @chmod($dest, 0640);
    return [
        'original_name' => $name,
        'stored_name'   => $stored,
        'mime'          => 'text/plain',
        'size'          => strlen($content),
        'sha256'        => hash('sha256', $content),
    ];
}

/* ---------- Envoi par morceaux (gros fichiers) ---------- */

/** Taille d'un morceau : réglage, plafonné sous les limites PHP */
function chunk_bytes(): int
{
    $want = max(1, (int) setting('chunk_mb', 32)) * 1048576;
    $limits = array_filter([ini_bytes('upload_max_filesize'), ini_bytes('post_max_size')]);
    $cap = $limits ? min($limits) - 65536 : $want;   // marge pour les en-têtes multipart
    $v = max(262144, min($want, $cap));
    // multiple de 1 Mio : chaque morceau correspond à des blocs de chiffrement entiers
    return (int) ($v >= ENC_BLOCK ? floor($v / ENC_BLOCK) * ENC_BLOCK : $v);
}

function chunk_dir(): string
{
    $d = storage_path('.chunks');
    if (!is_dir($d)) {
        @mkdir($d, 0700, true);
        @file_put_contents($d . '/.htaccess', "Require all denied\n");
    }
    return $d;
}

function chunk_paths(string $id): array
{
    if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
        throw new RuntimeException('identifiant d\'envoi invalide');
    }
    $b = chunk_dir() . '/' . $id;
    return ['part' => $b . '.part', 'meta' => $b . '.json', 'hash' => $b . '.hash'];
}

/** Taille chiffrée attendue d'un envoi partiel ($received octets en clair reçus sur $size) */
function chunk_cipher_expected(int|float $received, int|float $size): int|float
{
    if (num_eq($received, $size)) {
        return enc_cipher_size($size);
    }
    return num(sprintf('%.0f', ENC_HEADER + $received + ($received / ENC_BLOCK) * ENC_TAG));
}

/** Écriture atomique des métadonnées d'un envoi */
function chunk_meta_save(string $path, array $meta): void
{
    unset($meta['paths']);
    $tmp = $path . '.' . getmypid();
    file_put_contents($tmp, json_encode($meta, JSON_UNESCAPED_UNICODE));
    rename($tmp, $path);
}

function chunk_meta(string $id, int $userId): array
{
    $p = chunk_paths($id);
    $meta = is_file($p['meta']) ? json_decode((string) file_get_contents($p['meta']), true) : null;
    if (!is_array($meta) || (int) $meta['user'] !== $userId) {
        throw new RuntimeException('envoi inconnu ou expiré — recommencez');
    }
    return $meta + ['paths' => $p];
}

/** Supprime les envois abandonnés depuis plus de 48 h */
function chunk_purge(): void
{
    foreach (glob(chunk_dir() . '/*.json') ?: [] as $m) {
        if (filemtime($m) < time() - 172800) {
            $b = substr($m, 0, -5);
            @unlink($b . '.part');
            @unlink($b . '.hash');
            @unlink($m);
        }
    }
}

function chunk_cancel(string $id, int $userId): void
{
    $m = chunk_meta($id, $userId);
    foreach ($m['paths'] as $f) {
        @unlink($f);
    }
}

/** Assemble un envoi par morceaux terminé et le range dans le stockage */
function store_chunked(string $id, int|float $maxBytes): array
{
    $uid = (int) (current_user()['id'] ?? 0);
    $m = chunk_meta($id, $uid);
    $p = $m['paths'];
    $enc = !empty($m['enc']);
    // chiffré : la quantité reçue (en clair) est tenue dans les métadonnées ; sinon, c'est la taille du fichier
    $size = $enc ? num($m['received'] ?? 0) : (is_file($p['part']) ? fsize($p['part']) : -1);
    if (!num_eq($size, $m['size'])) {
        throw new RuntimeException('envoi incomplet (' . human_size(max(0, $size)) . ' reçus sur ' . human_size(num($m['size'])) . ')');
    }
    if ($enc && !num_eq(fsize($p['part']), enc_cipher_size($size))) {
        throw new RuntimeException('fichier chiffré incomplet — recommencez l\'envoi');
    }
    $name = clean_upload_name((string) $m['name']);
    if (($err = check_extension($name)) !== null) {
        throw new RuntimeException($err);
    }
    if ($size > $maxBytes) {
        throw new RuntimeException('dépasse ' . human_size($maxBytes));
    }
    // SHA-256 calculé au fil des morceaux ; recalcul complet à défaut
    $sha = null;
    if (is_file($p['hash'])) {
        try {
            $st = unserialize((string) file_get_contents($p['hash']), ['allowed_classes' => [HashContext::class]]);
            if (is_array($st) && ($st['ctx'] ?? null) instanceof HashContext && num_eq($st['n'], $size)) {
                $sha = hash_final($st['ctx']);
            }
        } catch (Throwable) {
            $sha = null;
        }
    }
    @set_time_limit(0);
    $sha ??= $enc ? multi_digest(StoredReader::open($p['part']), ['sha256'])['sha256'] : hash_file('sha256', $p['part']);
    $mime = $enc ? (string) ($m['mime'] ?? 'application/octet-stream') : ((new finfo(FILEINFO_MIME_TYPE))->file($p['part']) ?: 'application/octet-stream');
    $stored = bin2hex(random_bytes(16));
    if (!@rename($p['part'], storage_path($stored))) {
        throw new RuntimeException('impossible de ranger le fichier dans le stockage');
    }
    @chmod(storage_path($stored), 0640);
    @unlink($p['meta']);
    @unlink($p['hash']);
    return [
        'original_name' => $name,
        'stored_name'   => $stored,
        'mime'          => mb_substr($mime, 0, 120),
        'size'          => $size,
        'sha256'        => $sha,
    ];
}

/** Envois par morceaux terminés transmis avec le formulaire (champ chunked[]) */
function chunked_list(): array
{
    $out = [];
    foreach ((array) ($_POST['chunked'] ?? []) as $cid) {
        if (is_string($cid) && preg_match('/^[a-f0-9]{32}$/', $cid)) {
            $meta = @json_decode((string) @file_get_contents(chunk_paths($cid)['meta']), true);
            $out[] = ['chunk' => $cid, 'name' => is_array($meta) ? (string) $meta['name'] : 'fichier'];
        }
    }
    return $out;
}

/** Enregistre une nouvelle fiche à partir d'un fichier rangé ; renvoie son identifiant */
function insert_file(array $m, array $v, int $userId, ?string $title = null): int
{
    $title ??= ucfirst(trim(str_replace(['_', '-'], ' ', pathinfo($m['original_name'], PATHINFO_FILENAME)))) ?: $m['original_name'];
    q('INSERT INTO ' . t('files') . ' (title, description, version, version_notes, original_name, stored_name, mime, size, sha256, category_id, visibility, uploaded_by, content_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())', [
        mb_substr($title, 0, 200), ($v['description'] ?? '') ?: null, ($v['version'] ?? '') ?: null, ($v['version_notes'] ?? '') ?: null,
        $m['original_name'], $m['stored_name'], $m['mime'], $m['size'], $m['sha256'],
        $v['category_id'] ?? null, $v['visibility'] ?? 'public', $userId,
    ]);
    return (int) db()->lastInsertId();
}

/** Réorganise $_FILES[$field] (multiple) en liste */
function uploaded_list(string $field): array
{
    if (empty($_FILES[$field]) || !is_array($_FILES[$field]['name'])) {
        return [];
    }
    $out = [];
    foreach ($_FILES[$field]['name'] as $i => $n) {
        if ($_FILES[$field]['error'][$i] === UPLOAD_ERR_NO_FILE) {
            continue;
        }
        $out[] = [
            'name' => $n, 'tmp_name' => $_FILES[$field]['tmp_name'][$i],
            'size' => $_FILES[$field]['size'][$i], 'error' => $_FILES[$field]['error'][$i],
        ];
    }
    return $out;
}

function file_row(int $id): ?array
{
    return q('SELECT * FROM ' . t('files') . ' WHERE id = ?', [$id])->fetch() ?: null;
}

/* ---------- Versions ---------- */

/** Nombre de versions précédentes conservées (0 = historique désactivé) */
function versions_keep(): int
{
    return max(0, (int) setting('versions_keep', 10));
}

function versions_public(): bool
{
    return (bool) setting('versions_public', true);
}

/** Archive le contenu actuel d'une fiche dans l'historique */
function archive_current(array $f): void
{
    q('INSERT INTO ' . t('file_versions') . ' (file_id, version, notes, original_name, stored_name, mime, size, sha256, uploaded_by, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)', [
        $f['id'], $f['version'], $f['version_notes'] ?? null, $f['original_name'], $f['stored_name'],
        $f['mime'], $f['size'], $f['sha256'], $f['uploaded_by'], $f['content_at'] ?? $f['created_at'],
    ]);
}

/** Supprime les versions les plus anciennes au-delà de la limite */
function prune_versions(int $fileId): int
{
    $keep = versions_keep();
    $old = q('SELECT id, stored_name FROM ' . t('file_versions') . ' WHERE file_id = ? ORDER BY archived_at DESC, id DESC', [$fileId])->fetchAll();
    $n = 0;
    foreach (array_slice($old, $keep) as $v) {
        delete_version($v);
        $n++;
    }
    return $n;
}

/** Supprime une version archivée et revérifie les sommes qui la désignaient */
function delete_version(array $v): void
{
    q('DELETE FROM ' . t('file_versions') . ' WHERE id = ?', [$v['id']]);
    @unlink(storage_path($v['stored_name']));
    foreach (q('SELECT * FROM ' . t('checksum_entries') . ' WHERE matched_version_id = ?', [$v['id']])->fetchAll() as $e) {
        checksum_verify_entry($e);
    }
}

/**
 * Remplace le contenu d'une fiche par un nouveau fichier stocké.
 * Selon les réglages, l'ancien contenu part dans l'historique ou est supprimé.
 */
function replace_content(array $f, array $new, ?string $version, ?string $notes, int $userId): void
{
    $keep = versions_keep();
    db()->beginTransaction();
    try {
        if ($keep > 0) {
            archive_current($f);
        }
        q('UPDATE ' . t('files') . ' SET original_name=?, stored_name=?, mime=?, size=?, sha256=?, version=?, version_notes=?,
             uploaded_by=?, content_at=NOW() WHERE id=?', [
            $new['original_name'], $new['stored_name'], $new['mime'], $new['size'], $new['sha256'],
            $version, $notes, $userId, $f['id'],
        ]);
        q('DELETE FROM ' . t('file_hashes') . ' WHERE file_id = ?', [$f['id']]);
        db()->commit();
    } catch (Throwable $ex) {
        db()->rollBack();
        @unlink(storage_path($new['stored_name']));
        throw $ex;
    }
    if ($keep > 0) {
        prune_versions((int) $f['id']);
    } else {
        @unlink(storage_path($f['stored_name']));
    }
}

/** Rétablit une version archivée comme version courante (l'actuelle est archivée) */
function restore_version(array $f, array $ver): void
{
    db()->beginTransaction();
    try {
        archive_current($f);
        q('DELETE FROM ' . t('file_versions') . ' WHERE id = ?', [$ver['id']]);
        q('UPDATE ' . t('files') . ' SET original_name=?, stored_name=?, mime=?, size=?, sha256=?, version=?, version_notes=?,
             uploaded_by=?, content_at=? WHERE id=?', [
            $ver['original_name'], $ver['stored_name'], $ver['mime'], $ver['size'], $ver['sha256'],
            $ver['version'], $ver['notes'], $ver['uploaded_by'], $ver['created_at'], $f['id'],
        ]);
        q('DELETE FROM ' . t('file_hashes') . ' WHERE file_id = ?', [$f['id']]);
        db()->commit();
    } catch (Throwable $ex) {
        db()->rollBack();
        throw $ex;
    }
}

function file_versions(int $fileId): array
{
    return q('SELECT v.*, u.username FROM ' . t('file_versions') . ' v LEFT JOIN ' . t('users') . ' u ON u.id = v.uploaded_by
              WHERE v.file_id = ? ORDER BY v.archived_at DESC, v.id DESC', [$fileId])->fetchAll();
}

/** Supprime définitivement des fiches, leurs versions et les fichiers sur disque */
function delete_files(array $ids): int
{
    $ids = array_values(array_filter(array_map('intval', $ids)));
    if (!$ids) {
        return 0;
    }
    $in = implode(',', array_fill(0, count($ids), '?'));
    $stored = array_merge(
        q('SELECT stored_name FROM ' . t('files') . " WHERE id IN ($in)", $ids)->fetchAll(PDO::FETCH_COLUMN),
        q('SELECT stored_name FROM ' . t('file_versions') . " WHERE file_id IN ($in)", $ids)->fetchAll(PDO::FETCH_COLUMN),
    );
    $n = q('DELETE FROM ' . t('files') . " WHERE id IN ($in)", $ids)->rowCount();
    foreach ($stored as $s) {
        @unlink(storage_path($s));
    }
    // les sommes qui visaient ces fichiers n'ont plus de cible
    q('UPDATE ' . t('checksum_entries') . " SET status = 'missing', matched_version_id = NULL WHERE target_file_id IS NULL AND status <> 'missing'");
    return $n;
}

/* ---------- Aperçu ---------- */

const PREVIEW_IMAGE = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp'];
const PREVIEW_VIDEO = ['video/mp4', 'video/webm', 'video/ogg'];
const TEXT_EXT = ['txt', 'md', 'log', 'csv', 'tsv', 'conf', 'cfg', 'ini', 'toml', 'yml', 'yaml', 'json', 'xml',
                  'sh', 'bash', 'ps1', 'bat', 'cmd', 'py', 'sql', 'env', 'nfo', 'diz', 'asc', 'sig', 'pem', 'pub'];

function preview_enabled(): bool
{
    return (bool) setting('preview_enabled', true);
}

/** Type d'aperçu possible pour un fichier : image | pdf | audio | video | text | null */
function preview_kind(array $f): ?string
{
    if (!preview_enabled()) {
        return null;
    }
    $mime = strtolower((string) $f['mime']);
    $ext  = file_ext($f['original_name']);
    return match (true) {
        in_array($mime, PREVIEW_IMAGE, true)    => 'image',
        $mime === 'application/pdf'              => 'pdf',
        str_starts_with($mime, 'audio/')         => 'audio',
        in_array($mime, PREVIEW_VIDEO, true)     => 'video',
        (str_starts_with($mime, 'text/') || in_array($mime, ['application/json', 'application/xml', 'application/x-empty'], true)
            || in_array($ext, TEXT_EXT, true) || is_checksum_file($f['original_name'])) && $mime !== 'text/html'
                                                 => 'text',
        default                                  => null,
    };
}

/** Début d'un fichier texte, converti en UTF-8 ; [texte, tronqué?] */
function preview_text(array $f): array
{
    $max = max(16, (int) setting('preview_text_kb', 256)) * 1024;
    try {
        $txt = stored_contents(storage_path($f['stored_name']), $max);
    } catch (RuntimeException) {
        return ['', false];
    }
    if (str_starts_with($txt, "\xEF\xBB\xBF")) {
        $txt = substr($txt, 3);
    }
    if (!mb_check_encoding($txt, 'UTF-8')) {
        // coupure au milieu d'un caractère multi-octets, ou fichier en Windows-1252
        $trim = mb_strcut($txt, 0, strlen($txt) - 3, 'UTF-8');
        $txt = mb_check_encoding($trim, 'UTF-8') ? $trim : mb_convert_encoding($txt, 'UTF-8', 'Windows-1252');
    }
    return [$txt, num($f['size']) > $max];
}

/* ---------- Fichiers orphelins (présents sur le disque, sans fiche) ---------- */

/** @return list<array{stored:string, size:int|float, mtime:int, mime:string}> */
function storage_orphans(): array
{
    $known = array_flip(array_merge(
        q('SELECT stored_name FROM ' . t('files'))->fetchAll(PDO::FETCH_COLUMN),
        q('SELECT stored_name FROM ' . t('file_versions'))->fetchAll(PDO::FETCH_COLUMN),
    ));
    $out = [];
    foreach (scandir(storage_path()) ?: [] as $n) {
        if (preg_match('/^[a-f0-9]{32}$/', $n) && !isset($known[$n]) && is_file(storage_path($n))) {
            $p = storage_path($n);
            $out[] = ['stored' => $n, 'size' => stored_size($p), 'mtime' => (int) filemtime($p),
                      'mime' => stored_mime($p), 'encrypted' => is_encrypted_file($p)];
        }
    }
    return $out;
}

/** Extension probable d'après le type MIME (pour nommer un fichier récupéré) */
function ext_for_mime(string $mime): string
{
    return [
        'application/x-iso9660-image' => 'iso', 'application/zip' => 'zip', 'application/gzip' => 'gz',
        'application/x-xz' => 'xz', 'application/x-bzip2' => 'bz2', 'application/x-tar' => 'tar',
        'application/x-7z-compressed' => '7z', 'application/zstd' => 'zst', 'application/pdf' => 'pdf',
        'application/vnd.debian.binary-package' => 'deb', 'application/x-rpm' => 'rpm',
        'image/png' => 'png', 'image/jpeg' => 'jpg', 'image/gif' => 'gif', 'image/webp' => 'webp',
        'video/mp4' => 'mp4', 'video/webm' => 'webm', 'audio/mpeg' => 'mp3', 'text/plain' => 'txt',
        'application/json' => 'json', 'application/x-qemu-disk' => 'qcow2',
    ][$mime] ?? 'bin';
}
