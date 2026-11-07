<?php
declare(strict_types=1);

/**
 * Vérification automatique des sommes de contrôle.
 *
 * Un « fichier de sommes » (ex. ubuntu.iso.sha256sum, SHA256SUMS, MD5SUMS, release.sfv)
 * est analysé à l'envoi : chaque ligne (nom de fichier + empreinte) est rapprochée d'un
 * fichier du gestionnaire portant ce nom, puis l'empreinte est recalculée et comparée.
 *
 * Formats reconnus :
 *   GNU coreutils   e3b0c442…  fichier.iso      (ou « *fichier.iso » en mode binaire)
 *   BSD / --tag     SHA256 (fichier.iso) = e3b0c442…
 *   Empreinte seule fichier.iso.sha256 ne contenant que « e3b0c442… »
 *   SFV             fichier.iso 1A2B3C4D
 *   Clairsigné PGP  (les en-têtes et la signature sont ignorés)
 */

/** Extensions de fichiers de sommes et algorithme suggéré */
const CHECKSUM_FILE_EXT = [
    'md5' => 'md5', 'md5sum' => 'md5', 'sha1' => 'sha1', 'sha1sum' => 'sha1',
    'sha224' => 'sha224', 'sha224sum' => 'sha224', 'sha256' => 'sha256', 'sha256sum' => 'sha256',
    'sha384' => 'sha384', 'sha384sum' => 'sha384', 'sha512' => 'sha512', 'sha512sum' => 'sha512',
    'b2' => 'blake2b', 'b2sum' => 'blake2b', 'b3' => 'blake3', 'b3sum' => 'blake3',
    'sfv' => 'crc32b', 'crc' => 'crc32b', 'crc32' => 'crc32b',
];

/** Au-delà (256 Mo), les calculs qui relisent tout le fichier passent en arrière-plan (évite les erreurs 504) */
const BIG_FILE = 268435456;

function is_big(array $f): bool
{
    return num($f['size']) > BIG_FILE;
}

/** Algorithmes demandés dont l'empreinte n'est pas encore connue */
function missing_digests(array $f, array $algos): array
{
    return array_values(array_filter($algos, fn($a) => cached_digest($f, $a) === null));
}

const HASH_LABELS = [
    'md5' => 'MD5', 'sha1' => 'SHA-1', 'sha224' => 'SHA-224', 'sha256' => 'SHA-256', 'sha384' => 'SHA-384',
    'sha512' => 'SHA-512', 'crc32b' => 'CRC32', 'blake3' => 'BLAKE3',
];

function hash_label(string $algo): string
{
    if (str_starts_with($algo, 'blake2b-')) {
        return 'BLAKE2b-' . substr($algo, 8);
    }
    return HASH_LABELS[$algo] ?? strtoupper($algo);
}

/** Algorithme suggéré par le nom du fichier de sommes, ou null s'il ne s'agit pas d'un fichier de sommes */
function checksum_hint(string $name): ?string
{
    $ext = file_ext($name);
    if (isset(CHECKSUM_FILE_EXT[$ext])) {
        return CHECKSUM_FILE_EXT[$ext];
    }
    // SHA256SUMS, sha256sums.txt, MD5SUMS, B2SUMS, CHECKSUMS, projet-1.2-SHA512SUMS…
    if (preg_match('/(?:^|[._-])(md5|sha1|sha224|sha256|sha384|sha512|b2|b3|blake2b?|check)sums?(?:\.txt)?$/i', $name, $m)) {
        return match (strtolower($m[1])) {
            'b2', 'blake2', 'blake2b' => 'blake2b',
            'b3'    => 'blake3',
            'check' => '',
            default => strtolower($m[1]),
        };
    }
    return null;
}

function is_checksum_file(string $name): bool
{
    return checksum_hint($name) !== null;
}

/** Algorithme déduit de la longueur d'une empreinte hexadécimale */
function algo_from_length(int $len, string $hint): ?string
{
    if ($hint === 'blake2b') {
        return in_array($len, [32, 40, 48, 56, 64, 96, 128], true) ? 'blake2b-' . ($len * 4) : null;
    }
    if ($hint === 'blake3') {
        return 'blake3';
    }
    if ($hint === 'crc32b') {
        return $len === 8 ? 'crc32b' : null;
    }
    $byLen = [8 => 'crc32b', 32 => 'md5', 40 => 'sha1', 56 => 'sha224', 64 => 'sha256', 96 => 'sha384', 128 => 'sha512'];
    $guess = $byLen[$len] ?? null;
    // l'indice du nom prime s'il est cohérent avec la longueur
    if ($hint !== '' && $guess !== null && $hint !== $guess) {
        return $guess; // ex. fichier .sha256 contenant en réalité du SHA-512 : la longueur fait foi
    }
    return $guess;
}

/**
 * Analyse le contenu d'un fichier de sommes.
 * @return list<array{line:int, filename:string, algo:string, expected:string}>
 */
function checksum_parse(string $content, string $sourceName): array
{
    $hint = checksum_hint($sourceName) ?? '';
    $content = str_replace(["\r\n", "\r"], "\n", $content);
    if (str_starts_with($content, "\xEF\xBB\xBF")) {
        $content = substr($content, 3);
    }

    // Message PGP clairsigné : on garde le corps
    if (str_contains($content, '-----BEGIN PGP SIGNED MESSAGE-----')) {
        $content = preg_replace('/^.*?-----BEGIN PGP SIGNED MESSAGE-----\n(?:[^\n]+\n)*\n/s', '', $content);
        $content = preg_replace('/-----BEGIN PGP SIGNATURE-----.*$/s', '', $content);
        $content = preg_replace('/^- /m', '', $content);
    }

    $out = [];
    $lines = explode("\n", $content);
    $meaningful = array_values(array_filter(array_map('trim', $lines), fn($l) => $l !== '' && $l[0] !== '#' && $l[0] !== ';'));

    // Fichier ne contenant qu'une empreinte : elle concerne le fichier du même nom sans l'extension
    if (count($meaningful) === 1 && preg_match('/^([0-9a-f]{8,128})$/i', $meaningful[0], $m)) {
        $target = preg_replace('/\.[^.]+$/', '', $sourceName);
        $algo = algo_from_length(strlen($m[1]), $hint);
        if ($algo && $target !== $sourceName && $target !== '') {
            return [['line' => 1, 'filename' => $target, 'algo' => $algo, 'expected' => strtolower($m[1])]];
        }
        return [];
    }

    foreach ($lines as $i => $raw) {
        $l = rtrim($raw);
        $t = ltrim($l);
        if ($t === '' || $t[0] === '#' || $t[0] === ';') {
            continue;
        }
        $name = $hex = $algo = null;

        if (preg_match('/^([A-Za-z0-9-]+)\s*\((.+)\)\s*=\s*([0-9a-fA-F]{8,128})$/', $t, $m)) {
            // BSD : SHA256 (fichier) = …
            $tag = strtolower(str_replace('-', '', $m[1]));
            $name = $m[2];
            $hex = $m[3];
            $algo = match (true) {
                in_array($tag, ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'], true) => $tag,
                str_starts_with($tag, 'blake2b') => 'blake2b-' . (strlen($hex) * 4),
                $tag === 'blake3' => 'blake3',
                $tag === 'crc32' => 'crc32b',
                default => null,
            };
        } elseif ($hint === 'crc32b' && preg_match('/^(.+?)\s+([0-9a-fA-F]{8})$/', $t, $m)) {
            // SFV : nom CRC
            [$name, $hex, $algo] = [$m[1], $m[2], 'crc32b'];
        } elseif (preg_match('/^\\\\?([0-9a-fA-F]{8,128})\s[ *]?(.+)$/', $t, $m)) {
            // GNU : empreinte  nom  (une barre oblique inverse initiale signale un nom échappé)
            $hex = $m[1];
            $name = str_starts_with($t, '\\') ? str_replace(['\\\\', '\\n'], ['\\', "\n"], $m[2]) : $m[2];
            $algo = algo_from_length(strlen($hex), $hint);
        }

        if ($name === null || $algo === null) {
            continue;
        }
        $name = basename(str_replace('\\', '/', preg_replace('#^\./#', '', trim($name))));
        if ($name === '' || mb_strlen($name) > 255) {
            continue;
        }
        $out[] = ['line' => $i + 1, 'filename' => $name, 'algo' => $algo, 'expected' => strtolower($hex)];
        if (count($out) >= 5000) {
            break;
        }
    }
    return $out;
}

/** Empreinte d'un fichier stocké pour un algorithme (avec cache), null si non pris en charge */
function file_digest(array $f, string $algo): ?string
{
    if ($algo === 'sha256') {
        return $f['sha256'];
    }
    $cached = q('SELECT hex FROM ' . t('file_hashes') . ' WHERE file_id = ? AND algo = ?', [$f['id'], $algo])->fetchColumn();
    if ($cached !== false) {
        return $cached;
    }
    $hex = path_digest(storage_path($f['stored_name']), $algo);
    if ($hex !== null) {
        q('INSERT INTO ' . t('file_hashes') . ' (file_id, algo, hex) VALUES (?,?,?) ON DUPLICATE KEY UPDATE hex = VALUES(hex)', [$f['id'], $algo, $hex]);
    }
    return $hex;
}

/**
 * Calcule plusieurs empreintes en UNE seule lecture du fichier (au lieu d'une lecture par algorithme).
 * $copyTo : flux où recopier les données au passage (import par copie).
 * $progress(octets lus depuis le début) est appelé à chaque bloc.
 * @return array<string,string> algorithme => empreinte hexadécimale (algorithmes non pris en charge omis)
 */
function multi_digest(StoredReader|string $src, array $algos, ?callable $progress = null, $copyTo = null): array
{
    $ctx = [];
    foreach (array_unique($algos) as $a) {
        if (in_array($a, ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'crc32b'], true)) {
            $ctx[$a] = ['h', hash_init($a)];
        } elseif (str_starts_with($a, 'blake2b-') && function_exists('sodium_crypto_generichash_init')) {
            $len = intdiv((int) substr($a, 8), 8);
            if ($len >= 16 && $len <= 64) {
                $ctx[$a] = ['s', sodium_crypto_generichash_init('', $len), $len];
            }
        }
    }
    // $src : lecteur d'un fichier stocké (clair ou chiffré), ou chemin d'un fichier ordinaire lu tel quel
    $reader = $src instanceof StoredReader ? $src : StoredReader::open($src, true);
    @set_time_limit(0);
    $done = 0;
    for (;;) {
        $buf = $reader->read(8 << 20);
        if ($buf === '') {
            break;
        }
        // $copyTo : flux (copie à l'identique) ou EncWriter (copie chiffrée)
        if ($copyTo instanceof EncWriter) {
            $copyTo->write($buf);
        } elseif ($copyTo !== null && fwrite($copyTo, $buf) !== strlen($buf)) {
            throw new RuntimeException('copie interrompue (disque plein ?)');
        }
        foreach ($ctx as $a => $c) {
            if ($c[0] === 'h') {
                hash_update($c[1], $buf);
            } else {
                sodium_crypto_generichash_update($ctx[$a][1], $buf);
            }
        }
        $done += strlen($buf);
        if ($progress) {
            $progress($done);
        }
    }
    if ($copyTo instanceof EncWriter) {
        $copyTo->finish();
    }
    $out = [];
    foreach ($ctx as $a => $c) {
        $out[$a] = $c[0] === 'h' ? hash_final($c[1]) : bin2hex(sodium_crypto_generichash_final($c[1], $c[2]));
    }
    return $out;
}

/** Enregistre des empreintes calculées dans le cache (SHA-256 vit dans la table files) */
function store_digests(int $fileId, array $digests): void
{
    foreach ($digests as $a => $hex) {
        if ($a !== 'sha256') {
            q('INSERT INTO ' . t('file_hashes') . ' (file_id, algo, hex) VALUES (?,?,?) ON DUPLICATE KEY UPDATE hex = VALUES(hex)', [$fileId, $a, $hex]);
        }
    }
}

/** Empreinte du contenu (en clair) d'un fichier stocké, null si non pris en charge */
function path_digest(string $path, string $algo): ?string
{
    if (!is_file($path)) {
        return null;
    }
    try {
        return multi_digest(StoredReader::open($path), [$algo])[$algo] ?? null;
    } catch (RuntimeException $ex) {
        error_log('[svpro-downloads] empreinte : ' . $ex->getMessage());
        return null;
    }
}

/** Retrouve le fichier concerné par une ligne de somme (même nom, de préférence même catégorie) */
function checksum_find_target(string $filename, array $source): ?array
{
    return q('SELECT * FROM ' . t('files') . ' WHERE original_name = ? AND id <> ?
              ORDER BY (category_id <=> ?) DESC, content_at DESC, id DESC LIMIT 1',
        [$filename, $source['id'], $source['category_id']])->fetch() ?: null;
}

/** (Re)vérifie une ligne ; renvoie le statut obtenu */
function checksum_verify_entry(array $entry): string
{
    $source = file_row((int) $entry['source_file_id']);
    if (!$source) {
        return 'missing';
    }
    $target = null;
    if ($entry['target_file_id']) {
        $target = file_row((int) $entry['target_file_id']);
        if ($target && mb_strtolower($target['original_name']) !== mb_strtolower($entry['filename'])) {
            $target = null; // le fichier visé a été remplacé par un autre nom
        }
    }
    $target ??= checksum_find_target($entry['filename'], $source);

    $matched = null;
    if (!$target) {
        $status = 'missing';
    } else {
        $digest = file_digest($target, $entry['algo']);
        $status = $digest === null ? 'unsupported' : (hash_equals(strtolower($digest), $entry['expected']) ? 'ok' : 'mismatch');
        if ($status === 'mismatch') {
            // La somme correspond-elle à une version archivée ? (fichier de sommes pas encore mis à jour)
            $vers = q('SELECT * FROM ' . t('file_versions') . ' WHERE file_id = ? ORDER BY archived_at DESC, id DESC LIMIT 10', [$target['id']])->fetchAll();
            foreach ($vers as $v) {
                $d = $entry['algo'] === 'sha256' ? $v['sha256'] : path_digest(storage_path($v['stored_name']), $entry['algo']);
                if ($d !== null && hash_equals(strtolower($d), $entry['expected'])) {
                    $status = 'outdated';
                    $matched = (int) $v['id'];
                    break;
                }
            }
        }
    }
    q('UPDATE ' . t('checksum_entries') . ' SET target_file_id = ?, status = ?, matched_version_id = ?, checked_at = NOW() WHERE id = ?',
        [$target['id'] ?? null, $status, $matched, $entry['id']]);
    return $status;
}

/**
 * Analyse un fichier (s'il s'agit d'un fichier de sommes) et vérifie chacune de ses lignes.
 * @return array{entries:int, mismatch:list<int>} identifiants des fichiers non conformes
 */
function integrity_index_source(array $f): array
{
    q('DELETE FROM ' . t('checksum_entries') . ' WHERE source_file_id = ?', [$f['id']]);
    $res = ['entries' => 0, 'mismatch' => []];
    if (!is_checksum_file($f['original_name']) || num($f['size']) > 4 * 1024 * 1024) {
        return $res;
    }
    try {
        $content = stored_contents(storage_path($f['stored_name']));
    } catch (RuntimeException) {
        return $res;
    }
    foreach (checksum_parse($content, $f['original_name']) as $row) {
        q('INSERT INTO ' . t('checksum_entries') . ' (source_file_id, line_no, filename, algo, expected) VALUES (?,?,?,?,?)',
            [$f['id'], $row['line'], $row['filename'], $row['algo'], $row['expected']]);
        $entry = q('SELECT * FROM ' . t('checksum_entries') . ' WHERE id = ?', [db()->lastInsertId()])->fetch();
        if (checksum_verify_entry($entry) === 'mismatch') {
            $res['mismatch'][] = (int) q('SELECT target_file_id FROM ' . t('checksum_entries') . ' WHERE id = ?', [$entry['id']])->fetchColumn();
        }
        $res['entries']++;
    }
    return $res;
}

/**
 * Revérifie toutes les sommes qui concernent (ou pourraient concerner) un fichier,
 * après son envoi ou son remplacement.
 * @return list<int> identifiants des fichiers non conformes
 */
function integrity_refresh_target(array $f): array
{
    $entries = q('SELECT * FROM ' . t('checksum_entries') . ' WHERE target_file_id = ? OR (filename = ? AND (target_file_id IS NULL OR status = \'missing\'))',
        [$f['id'], $f['original_name']])->fetchAll();
    $bad = [];
    foreach ($entries as $e) {
        if (checksum_verify_entry($e) === 'mismatch') {
            $bad[] = (int) $f['id'];
        }
    }
    return array_values(array_unique($bad));
}

/** Traitement complet après envoi / remplacement / restauration d'un fichier */
function integrity_process(array $f): array
{
    $a = integrity_index_source($f);
    $b = integrity_refresh_target($f);
    return array_values(array_unique(array_filter(array_merge($a['mismatch'], $b))));
}

/** Lignes de sommes qui vérifient ce fichier */
function integrity_for_target(int $fileId): array
{
    return q('SELECT e.*, s.title AS source_title, s.original_name AS source_name, s.visibility AS source_visibility, mv.version AS matched_version
              FROM ' . t('checksum_entries') . ' e JOIN ' . t('files') . ' s ON s.id = e.source_file_id
              LEFT JOIN ' . t('file_versions') . ' mv ON mv.id = e.matched_version_id
              WHERE e.target_file_id = ? ORDER BY e.status = \'mismatch\' DESC, e.algo', [$fileId])->fetchAll();
}

/** Lignes contenues dans un fichier de sommes */
function integrity_for_source(int $fileId): array
{
    return q('SELECT e.*, f.title AS target_title, f.visibility AS target_visibility, mv.version AS matched_version
              FROM ' . t('checksum_entries') . ' e LEFT JOIN ' . t('files') . ' f ON f.id = e.target_file_id
              LEFT JOIN ' . t('file_versions') . ' mv ON mv.id = e.matched_version_id
              WHERE e.source_file_id = ? ORDER BY e.line_no', [$fileId])->fetchAll();
}

/** Synthèse par fichier : [id => 'ok'|'mismatch'] */
function integrity_summary(array $ids): array
{
    $ids = array_values(array_filter(array_map('intval', $ids)));
    if (!$ids) {
        return [];
    }
    $in = implode(',', $ids);
    $rows = q('SELECT target_file_id id, MAX(status = \'mismatch\') bad, MAX(status = \'ok\') good, MAX(status = \'outdated\') old
               FROM ' . t('checksum_entries') . " WHERE target_file_id IN ($in) GROUP BY target_file_id")->fetchAll();
    $out = [];
    foreach ($rows as $r) {
        if ($r['bad']) {
            $out[$r['id']] = 'mismatch';
        } elseif ($r['good']) {
            $out[$r['id']] = 'ok';
        } elseif ($r['old']) {
            $out[$r['id']] = 'outdated';
        }
    }
    return $out;
}

function integrity_badge(?string $status, string $title = ''): string
{
    return match ($status) {
        'ok'       => '<span class="integrity ok" title="' . e($title ?: 'Somme de contrôle vérifiée') . '">✔ vérifié</span>',
        'mismatch' => '<span class="integrity bad" title="' . e($title ?: 'La somme de contrôle ne correspond pas') . '">✖ somme invalide</span>',
        'outdated' => '<span class="integrity old" title="' . e($title ?: 'Le fichier de sommes correspond à une version précédente : il reste à publier celui de la version actuelle') . '">≈ somme d\'une version précédente</span>',
        default    => '',
    };
}

const CHECK_STATUS_LABEL = [
    'ok'          => 'Conforme',
    'mismatch'    => 'Ne correspond pas',
    'outdated'    => 'Correspond à une version précédente',
    'missing'     => 'Fichier absent',
    'unsupported' => 'Algorithme non pris en charge',
];

/* =====================================================================
 * Génération de sommes de contrôle
 * ===================================================================== */

const GEN_FORMATS = [
    'gnu'  => 'GNU coreutils — sha256sum, md5sum…',
    'bsd'  => 'BSD / --tag — SHA256 (fichier) = …',
    'hash' => 'Empreinte seule',
    'sfv'  => 'SFV — CRC32',
];

/** Algorithmes proposés à la génération */
function gen_algos(): array
{
    $a = ['md5' => 'MD5', 'sha1' => 'SHA-1', 'sha256' => 'SHA-256', 'sha512' => 'SHA-512', 'crc32b' => 'CRC32'];
    if (function_exists('sodium_crypto_generichash_init')) {
        $a['blake2b-512'] = 'BLAKE2b-512';
    }
    return $a;
}

/** Empreintes calculées automatiquement après chaque envoi (en plus de SHA-256) */
function auto_hashes(): array
{
    $list = setting('auto_hashes', ['md5', 'sha1', 'sha512']);
    return array_values(array_intersect((array) $list, array_keys(gen_algos())));
}

/** Empreinte déjà connue (sans calcul) */
function cached_digest(array $f, string $algo): ?string
{
    if ($algo === 'sha256') {
        return $f['sha256'];
    }
    $hex = q('SELECT hex FROM ' . t('file_hashes') . ' WHERE file_id = ? AND algo = ?', [$f['id'], $algo])->fetchColumn();
    return $hex === false ? null : $hex;
}

/** Calcule les empreintes automatiques d'un fichier (appelé après la réponse HTTP) */
function precompute_hashes(int $fileId, ?callable $progress = null): void
{
    $f = file_row($fileId);
    if (!$f) {
        return;
    }
    $missing = missing_digests($f, auto_hashes());
    if ($missing) {
        try {
            store_digests($fileId, multi_digest(StoredReader::open(storage_path($f['stored_name'])), $missing, $progress));
        } catch (RuntimeException $ex) {
            error_log('[svpro-downloads] empreintes : ' . $ex->getMessage());
        }
    }
}

function algo_short(string $algo): string
{
    return ['md5' => 'md5', 'sha1' => 'sha1', 'sha256' => 'sha256', 'sha512' => 'sha512', 'crc32b' => 'crc', 'blake2b-512' => 'b2'][$algo] ?? $algo;
}

function bsd_tag(string $algo): string
{
    return ['md5' => 'MD5', 'sha1' => 'SHA1', 'sha256' => 'SHA256', 'sha512' => 'SHA512', 'crc32b' => 'CRC32', 'blake2b-512' => 'BLAKE2b'][$algo] ?? strtoupper($algo);
}

/**
 * Produit le contenu d'un fichier de sommes.
 * @param list<array> $files   lignes de la table files
 * @param list<string> $algos  algorithmes (plusieurs uniquement en format BSD)
 * @param bool $compute        calculer les empreintes manquantes (sinon : uniquement celles déjà connues)
 * @return array{0:string,1:string} [nom de fichier proposé, contenu]
 */
function checksum_generate(array $files, array $algos, string $format, bool $compute): array
{
    $valid = gen_algos();
    $algos = array_values(array_unique(array_intersect($algos, array_keys($valid))));
    if (!$files) {
        throw new RuntimeException('aucun fichier sélectionné');
    }
    if (!isset(GEN_FORMATS[$format])) {
        throw new RuntimeException('format inconnu');
    }
    if ($format === 'sfv') {
        $algos = ['crc32b'];
    }
    if (!$algos) {
        throw new RuntimeException('choisissez au moins un algorithme');
    }
    if ($format === 'gnu' && $algos === ['crc32b']) {
        $format = 'sfv'; // CRC32 n'existe pas au format coreutils : SFV est l'usage
    }
    if (in_array($format, ['gnu', 'hash'], true) && count($algos) > 1) {
        throw new RuntimeException('ce format ne contient qu\'un seul algorithme : choisissez le format BSD pour en combiner plusieurs');
    }
    if ($format === 'hash' && count($files) > 1) {
        throw new RuntimeException('le format « empreinte seule » ne concerne qu\'un fichier : choisissez GNU ou BSD');
    }

    $digest = function (array $f, string $algo) use ($compute, $valid): string {
        $hex = $compute ? file_digest($f, $algo) : cached_digest($f, $algo);
        if ($hex === null) {
            throw new RuntimeException('empreinte ' . $valid[$algo] . ' non disponible pour « ' . $f['original_name'] . ' »');
        }
        return strtolower($hex);
    };
    @set_time_limit(0);
    $lines = [];
    foreach ($files as $f) {
        $name = $f['original_name'];
        foreach ($algos as $algo) {
            $hex = $digest($f, $algo);
            $lines[] = match ($format) {
                // coreutils : un nom contenant « \ » ou un saut de ligne est échappé et la ligne préfixée par « \ »
                'gnu'  => (preg_match('/[\\\\\n]/', $name) ? '\\' . $hex . '  ' . str_replace(['\\', "\n"], ['\\\\', '\\n'], $name) : $hex . '  ' . $name),
                'bsd'  => bsd_tag($algo) . ' (' . $name . ') = ' . $hex,
                'hash' => $hex,
                'sfv'  => $name . ' ' . strtoupper($hex),
            };
        }
    }
    $content = implode("\n", $lines) . "\n";
    if ($format === 'sfv') {
        $content = '; Généré par ' . cfg('app_name', 'SV Pro Downloads') . ' le ' . date('d/m/Y H:i') . "\n" . $content;
    }

    $single = count($files) === 1 ? $files[0]['original_name'] : null;
    $short  = algo_short($algos[0]);
    $gnuExt = ['md5' => 'md5sum', 'sha1' => 'sha1sum', 'sha256' => 'sha256sum', 'sha512' => 'sha512sum', 'b2' => 'b2sum'];
    $filename = match (true) {
        $format === 'sfv' => ($single ?? 'checksums') . '.sfv',
        $format === 'hash' => $single . '.' . $short,
        $format === 'gnu' => $single !== null ? $single . '.' . $gnuExt[$short] : strtoupper($short) . 'SUMS',
        count($algos) > 1 => ($single !== null ? $single . '.' : '') . 'checksums.txt',
        default => $single !== null ? $single . '.' . $short : strtoupper($short) . 'SUMS.txt',
    };
    return [$filename, $content];
}

/**
 * Publie un fichier de sommes généré dans le gestionnaire.
 * S'il existe déjà un fichier du même nom dans la même catégorie, une nouvelle version en est publiée.
 * @return array{0:array,1:string} [fiche, 'new'|'version']
 */
function checksum_publish(array $sources, array $algos, string $filename, string $content, int $userId): array
{
    $cats = array_values(array_unique(array_map(fn($s) => $s['category_id'], $sources)));
    $cat  = count($cats) === 1 ? $cats[0] : null;
    $vis  = array_column($sources, 'visibility');
    $visibility = in_array('hidden', $vis, true) ? 'hidden' : (in_array('private', $vis, true) ? 'private' : 'public');
    $labels = implode(' + ', array_map(fn($a) => gen_algos()[$a] ?? $a, $algos));
    $version = count($sources) === 1 ? $sources[0]['version'] : null;
    $notes = 'Sommes ' . $labels . ' générées le ' . date('d/m/Y à H:i') . (count($sources) > 1 ? ' pour ' . count($sources) . ' fichiers.' : '.');

    $m = store_generated($filename, $content);
    $existing = q('SELECT * FROM ' . t('files') . ' WHERE original_name = ? AND category_id <=> ? ORDER BY id DESC LIMIT 1', [$filename, $cat])->fetch();
    if ($existing) {
        if ($existing['sha256'] === $m['sha256']) {
            @unlink(storage_path($m['stored_name']));
            return [$existing, 'same'];
        }
        replace_content($existing, $m, $version ?? $existing['version'], $notes, $userId);
        $row = file_row((int) $existing['id']);
        $type = 'version';
    } else {
        $title = count($sources) === 1
            ? $sources[0]['title'] . ' — ' . $labels
            : 'Sommes de contrôle ' . $labels . ' (' . count($sources) . ' fichiers)';
        q('INSERT INTO ' . t('files') . ' (title, description, version, version_notes, original_name, stored_name, mime, size, sha256, category_id, visibility, uploaded_by, content_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())', [
            mb_substr($title, 0, 200),
            count($sources) === 1 ? 'Sommes de contrôle de « ' . $sources[0]['original_name'] . ' ».' : 'Sommes de contrôle de : ' . mb_strimwidth(implode(', ', array_column($sources, 'original_name')), 0, 900, '…'),
            $version, $notes, $m['original_name'], $m['stored_name'], $m['mime'], $m['size'], $m['sha256'],
            $cat, $visibility, $userId,
        ]);
        $row = file_row((int) db()->lastInsertId());
        $type = 'new';
    }
    integrity_process($row);
    return [$row, $type];
}

/** Envoie un fichier de sommes généré au navigateur */
function send_checksum_text(string $filename, string $content): never
{
    session_write_close();
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    $fallback = preg_replace('/[^\x20-\x7E]|["\\\\]/u', '_', $filename);
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($filename));
    header('Content-Length: ' . strlen($content));
    header('Cache-Control: private, no-store');
    echo $content;
    exit;
}
