<?php
declare(strict_types=1);

/**
 * SV Pro Downloads — amorçage commun (config, session, BDD, sécurité, helpers)
 */

define('APP_ROOT', dirname(__DIR__));
define('APP_VERSION', '1.7.0');
define('APP_SOURCE_URL', 'https://github.com/samuelvermeulenpro/DatasLockers');

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    exit('PHP 8.1 ou supérieur requis.');
}

if (!is_file(APP_ROOT . '/config.php')) {
    $self = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    $base = preg_replace('#/admin$#', '', rtrim($self, '/'));
    header('Location: ' . $base . '/install.php');
    exit;
}

$GLOBALS['CONFIG'] = require APP_ROOT . '/config.php';

date_default_timezone_set('Europe/Brussels');
mb_internal_encoding('UTF-8');

/* ---------- Session ---------- */
$sessPath = (string) cfg('session_path', '');
if ($sessPath !== '') {
    if (!is_dir($sessPath)) {
        @mkdir($sessPath, 0700, true);
    }
    if (is_dir($sessPath) && is_writable($sessPath)) {
        session_save_path($sessPath);
        // Debian/Ubuntu désactivent le ramasse-miettes PHP (nettoyage par cron du dossier système) :
        // on le réactive pour ce dossier dédié.
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '100');
        ini_set('session.gc_maxlifetime', '7200');
    }
}
session_name('SVPRODL');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => (cfg('base_url') ?: '') . '/',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

header('X-Content-Type-Options: nosniff');

/* ---------- Config ---------- */
function cfg(string $key, mixed $default = null): mixed
{
    $v = $GLOBALS['CONFIG'];
    foreach (explode('.', $key) as $k) {
        if (!is_array($v) || !array_key_exists($k, $v)) {
            return $default;
        }
        $v = $v[$k];
    }
    return $v;
}

/* ---------- Base de données ---------- */
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            cfg('db.host'), (int) cfg('db.port', 3306), cfg('db.name'));
        $pdo = new PDO($dsn, cfg('db.user'), cfg('db.pass'), [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
        // aligne NOW() de MySQL sur le fuseau PHP (heure belge, été/hiver)
        $pdo->exec("SET time_zone = '" . date('P') . "'");
    }
    return $pdo;
}

/** Nom de table préfixé : t('files') -> dl_files */
function t(string $name): string
{
    return cfg('db.prefix', 'dl_') . $name;
}

function q(string $sql, array $params = []): PDOStatement
{
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st;
}

/* ---------- Helpers HTML / URL ---------- */
function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Adresse du code source (AGPL-3.0, art. 13) : 'source_url' de config.php, sinon le dépôt d'origine */
function source_url(): string
{
    return trim((string) cfg('source_url', APP_SOURCE_URL));
}

function url(string $path = ''): string
{
    return rtrim((string) cfg('base_url', ''), '/') . '/' . ltrim($path, '/');
}

/** Adresse publique du site, sans slash final (réglage « URL du site » ou déduite de la requête) */
function site_base_url(): string
{
    $set = rtrim(trim((string) setting('site_url', '')), '/');
    if ($set !== '') {
        return $set;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    $host = preg_replace('/[^a-z0-9.:\[\]-]/i', '', (string) ($_SERVER['HTTP_HOST'] ?? 'localhost'));
    return ($https ? 'https' : 'http') . '://' . $host . rtrim((string) cfg('base_url', ''), '/');
}

function abs_url(string $path = ''): string
{
    return site_base_url() . '/' . ltrim($path, '/');
}

/**
 * Exécute une tâche après l'envoi de la réponse au navigateur (e-mails…) :
 * l'utilisateur n'attend pas. Sous PHP-FPM, fastcgi_finish_request() libère la connexion.
 */
function defer_after_response(callable $task): void
{
    static $tasks = null;
    if ($tasks === null) {
        $tasks = [];
        register_shutdown_function(function () use (&$tasks) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_write_close();
            }
            if (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            }
            ignore_user_abort(true);
            @set_time_limit(300);
            foreach ($tasks as $t) {
                try {
                    $t();
                } catch (Throwable $ex) {
                    error_log('[svpro-downloads] tâche différée : ' . $ex->getMessage());
                }
            }
        });
    }
    $tasks[] = $task;
}

function redirect(string $path): never
{
    header('Location: ' . (str_starts_with($path, 'http') ? $path : url($path)));
    exit;
}

function flash(string $type, string $msg): void
{
    $_SESSION['flash'][] = [$type, $msg];
}

function take_flashes(): array
{
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

function human_size(int|float $bytes): string
{
    $u = ['o', 'Ko', 'Mo', 'Go', 'To'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($u) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return ($i === 0 ? (string) $bytes : number_format($bytes, 1, ',', ' ')) . ' ' . $u[$i];
}

/* ---------- Grands nombres : tailles > 2 Go sur un PHP 32 bits ----------
 * Sur un PHP 32 bits (Raspberry Pi OS armhf, i386…), les entiers plafonnent à 2 147 483 647 :
 * filesize() « déborde » (taille négative ou fausse) et fseek() se trompe au-delà de 2 Go.
 * Les tailles sont donc manipulées en int, ou en float (exact jusqu'à 9 Po) quand elles dépassent.
 */

/** Nombre entier depuis une valeur SQL / JSON / formulaire, sans plafonner à 2 Go */
function num(mixed $v): int|float
{
    if (is_int($v) || is_float($v)) {
        return $v;
    }
    $v = trim((string) $v);
    if (!preg_match('/^-?\d+(\.0+)?$/', $v)) {
        return 0;
    }
    $f = (float) $v;
    return ($f <= PHP_INT_MAX && $f >= PHP_INT_MIN) ? (int) $f : $f;
}

/** Égalité de deux tailles (int ou float) */
function num_eq(mixed $a, mixed $b): bool
{
    return (float) num($a) === (float) num($b);
}

/** Représentation texte exacte d'une taille (en-têtes HTTP, SQL) */
function num_str(int|float $v): string
{
    return is_int($v) ? (string) $v : sprintf('%.0f', $v);
}

/** Taille réelle d'un fichier, y compris au-delà de 2 Go sur un PHP 32 bits */
function fsize(string $path): int|float
{
    clearstatcache(true, $path);
    $s = @filesize($path);
    if ($s === false) {
        return 0;
    }
    if (PHP_INT_SIZE >= 8) {
        return $s;
    }
    // 32 bits : `stat` donne la vraie taille ; à défaut, lecture non signée (exacte jusqu'à 4 Go)
    static $exec = null;
    $exec ??= function_exists('exec') && !in_array('exec', array_map('trim', explode(',', (string) ini_get('disable_functions'))), true);
    if ($exec) {
        $out = [];
        $rc = 1;
        @exec('stat -c %s ' . escapeshellarg($path) . ' 2>/dev/null', $out, $rc);
        if ($rc === 0 && isset($out[0]) && preg_match('/^\d+$/', trim($out[0]))) {
            return num(trim($out[0]));
        }
    }
    return num(sprintf('%u', $s));
}

/**
 * Se place à $offset dans un fichier ouvert en lecture.
 * Sur PHP 32 bits, fseek() est faux au-delà de 2 Go : on y va par fseek() jusqu'à 2 Go, puis en lisant.
 */
function fseek_far($fh, int|float $offset): bool
{
    if (PHP_INT_SIZE >= 8 || $offset < 2000000000) {
        return fseek($fh, (int) $offset) === 0;
    }
    if (fseek($fh, 2000000000) !== 0) {
        return false;
    }
    $skip = $offset - 2000000000;
    while ($skip > 0) {
        $buf = fread($fh, (int) min($skip, 8388608));
        if ($buf === false || $buf === '') {
            return false;
        }
        $skip -= strlen($buf);
    }
    return true;
}

/** Valeur php.ini en octets (128M -> 134217728) */
function ini_bytes(string $key): int|float
{
    $v = trim((string) ini_get($key));
    if ($v === '') {
        return 0;
    }
    $n = (int) $v;
    return match (strtolower(substr($v, -1))) {
        'g' => $n * 1024 ** 3,
        'm' => $n * 1024 ** 2,
        'k' => $n * 1024,
        default => $n,
    };
}

function fr_date(?string $dt, bool $time = false): string
{
    if (!$dt) {
        return '—';
    }
    $ts = strtotime($dt);
    return $time ? date('d/m/Y H:i', $ts) : date('d/m/Y', $ts);
}

/** Icône / type lisible selon l'extension */
function file_kind(string $name): array
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $map = [
        'doc'   => ['pdf','doc','docx','odt','rtf','txt','md'],
        'sheet' => ['xls','xlsx','ods','csv'],
        'slide' => ['ppt','pptx','odp'],
        'arch'  => ['zip','7z','tar','gz','tgz','bz2','xz','rar'],
        'img'   => ['jpg','jpeg','png','gif','webp','svg'],
        'audio' => ['mp3','ogg','flac','wav','m4a'],
        'video' => ['mp4','webm','mkv'],
        'bin'   => ['iso','img','apk','exe','msi','deb','rpm'],
        'code'  => ['sh','ps1','json','xml','yml','yaml','conf'],
        'hash'  => array_merge(CHECKSUM_EXT, ['sha224', 'sha384', 'b3', 'crc32']),
    ];
    foreach ($map as $kind => $exts) {
        if (in_array($ext, $exts, true)) {
            return [$kind, strtoupper($ext)];
        }
    }
    if (is_checksum_file($name)) {
        return ['hash', 'SUM'];
    }
    return ['file', strtoupper($ext ?: 'FIC')];
}

/* ---------- Réglages en base (modifiables depuis l'administration) ---------- */

/** Extensions de sommes de contrôle / signatures, proposées par défaut */
const CHECKSUM_EXT = ['md5', 'md5sum', 'sha1', 'sha1sum', 'sha256', 'sha256sum', 'sha512', 'sha512sum',
                      'b2', 'b2sum', 'b3sum', 'crc', 'sfv', 'asc', 'sig', 'gpg', 'minisig', 'pem', 'pub'];

/**
 * Extensions toujours refusées, quels que soient les réglages : celles qu'un serveur
 * mal configuré pourrait exécuter si le dossier de stockage devenait accessible.
 */
const FORBIDDEN_EXT = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'phps', 'pht', 'pgif',
                       'shtml', 'htaccess', 'htpasswd', 'cgi', 'fcgi', 'asp', 'aspx', 'ashx', 'jsp', 'jspx'];

/** Noms de fichiers interdits (configuration serveur) */
const FORBIDDEN_NAMES = ['.htaccess', '.htpasswd', '.user.ini', 'htaccess', 'htpasswd', 'user.ini', 'php.ini', 'web.config'];

function settings_all(): array
{
    if (!isset($GLOBALS['SETTINGS'])) {
        $GLOBALS['SETTINGS'] = [];
        try {
            $rows = q('SELECT name, value FROM ' . t('settings'))->fetchAll(PDO::FETCH_KEY_PAIR);
        } catch (PDOException $ex) {
            // installation antérieure à la table des réglages : création à la volée
            db()->exec('CREATE TABLE IF NOT EXISTS ' . t('settings') . ' (
                name VARCHAR(64) NOT NULL PRIMARY KEY,
                value MEDIUMTEXT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci');
            $rows = [];
        }
        foreach ($rows as $k => $v) {
            $GLOBALS['SETTINGS'][$k] = json_decode((string) $v, true);
        }
    }
    return $GLOBALS['SETTINGS'];
}

function setting(string $key, mixed $default = null): mixed
{
    return settings_all()[$key] ?? $default;
}

function setting_set(string $key, mixed $value): void
{
    settings_all(); // garantit l'existence de la table
    q('INSERT INTO ' . t('settings') . ' (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
        [$key, json_encode($value, JSON_UNESCAPED_UNICODE)]);
    $GLOBALS['SETTINGS'][$key] = $value;
}

/** Liste effective des extensions autorisées (réglages > config.php) */
function allowed_extensions(): array
{
    $list = setting('allowed_ext');
    if (!is_array($list)) {
        $list = array_merge((array) cfg('allowed_ext', []), CHECKSUM_EXT);
    }
    return array_values(array_diff(array_unique(array_map('strtolower', $list)), FORBIDDEN_EXT));
}

function allow_no_extension(): bool
{
    return (bool) setting('allow_noext', true);
}

function max_upload_bytes(): int|float
{
    return (int) setting('max_upload_mb', cfg('max_upload_mb', 512)) * 1024 * 1024;
}

/** Extension d'un nom de fichier, telle qu'utilisée pour le contrôle */
function file_ext(string $name): string
{
    return strtolower(pathinfo($name, PATHINFO_EXTENSION));
}

/** Vérifie qu'un nom de fichier est acceptable ; renvoie un message d'erreur ou null */
function check_extension(string $name): ?string
{
    $ext = file_ext($name);
    if (in_array(strtolower($name), FORBIDDEN_NAMES, true)) {
        return 'nom de fichier réservé (« ' . $name . ' »)';
    }
    // doubles extensions piégées (ex. image.php.jpg, que certains Apache exécutent)
    foreach (array_slice(explode('.', strtolower($name)), 1) as $part) {
        if (in_array($part, ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phps'], true)) {
            return 'nom de fichier contenant une extension PHP (« .' . $part . ' »)';
        }
    }
    if ($ext === '') {
        return allow_no_extension() ? null : 'fichier sans extension non autorisé';
    }
    if (in_array($ext, FORBIDDEN_EXT, true)) {
        return 'extension « .' . $ext . ' » interdite pour des raisons de sécurité';
    }
    if (!in_array($ext, allowed_extensions(), true)) {
        return 'extension « .' . $ext . ' » non autorisée (à ajouter dans Réglages)';
    }
    return null;
}

function paginate(int $total, int $page, int $per): array
{
    $pages = max(1, (int) ceil($total / $per));
    $page  = min(max(1, $page), $pages);
    return [$page, $pages, ($page - 1) * $per];
}

/** Construit une query string en conservant les filtres courants */
function qs(array $override = []): string
{
    $p = array_merge($_GET, $override);
    $p = array_filter($p, fn($v) => $v !== null && $v !== '');
    return $p ? '?' . http_build_query($p) : '';
}

/* ---------- IP ---------- */
function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function log_ip(): string
{
    $ip = client_ip();
    if (!cfg('anonymize_ip', true)) {
        return $ip;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return preg_replace('/\.\d+$/', '.0', $ip);
    }
    $bin = @inet_pton($ip);
    if ($bin !== false && strlen($bin) === 16) {
        return inet_ntop(substr($bin, 0, 6) . str_repeat("\0", 10));
    }
    return '0.0.0.0';
}

/* ---------- CSRF ---------- */
function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">';
}

function csrf_check(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }
    $t = $_POST['_csrf'] ?? '';
    if (!is_string($t) || !hash_equals(csrf_token(), $t)) {
        http_response_code(400);
        exit('Jeton de sécurité invalide. Rechargez la page et réessayez.');
    }
}

/* ---------- Authentification ---------- */
function current_user(): ?array
{
    static $user = false;
    if ($user === false) {
        $user = null;
        if (!empty($_SESSION['uid'])) {
            $u = q('SELECT id, username, email, role, active FROM ' . t('users') . ' WHERE id = ?', [$_SESSION['uid']])->fetch();
            if ($u && $u['active']) {
                $user = $u;
            } else {
                unset($_SESSION['uid']);
            }
        }
    }
    return $user;
}

const ROLE_LEVEL = ['member' => 1, 'editor' => 2, 'admin' => 3];

function has_role(string $role): bool
{
    $u = current_user();
    return $u !== null && ROLE_LEVEL[$u['role']] >= ROLE_LEVEL[$role];
}

function require_role(string $role): array
{
    $u = current_user();
    if ($u === null) {
        $_SESSION['after_login'] = $_SERVER['REQUEST_URI'] ?? url();
        redirect('login.php');
    }
    if (!has_role($role)) {
        http_response_code(403);
        render_header('Accès refusé');
        echo '<div class="card empty"><h2>Accès refusé</h2><p>Votre compte n\'a pas les droits nécessaires.</p></div>';
        render_footer();
        exit;
    }
    return $u;
}

function role_label(string $r): string
{
    return ['admin' => 'Administrateur', 'editor' => 'Éditeur', 'member' => 'Membre'][$r] ?? $r;
}

function visibility_label(string $v): string
{
    return ['public' => 'Public', 'private' => 'Membres', 'hidden' => 'Masqué'][$v] ?? $v;
}

/** Un utilisateur peut-il voir ce fichier dans les listes / sa fiche ? */
function can_view_file(array $f): bool
{
    return match ($f['visibility']) {
        'public'  => true,
        'private' => current_user() !== null,
        default   => has_role('editor'),
    };
}

/* ---------- Catégories (structure › service) ---------- */
function categories_tree(): array
{
    $rows = q('SELECT id, parent_id, name, position FROM ' . t('categories') . ' ORDER BY position, name')->fetchAll();
    $tree = [];
    foreach ($rows as $r) {
        if ($r['parent_id'] === null) {
            $tree[$r['id']] = $r + ['children' => []];
        }
    }
    foreach ($rows as $r) {
        if ($r['parent_id'] !== null && isset($tree[$r['parent_id']])) {
            $tree[$r['parent_id']]['children'][$r['id']] = $r;
        }
    }
    return $tree;
}

/** <option> groupées pour un <select> de catégorie */
function category_options(?int $selected, bool $allowParents = true): string
{
    $html = '';
    foreach (categories_tree() as $s) {
        $sel = $selected === (int) $s['id'] ? ' selected' : '';
        $dis = $allowParents ? '' : ' disabled';
        $html .= '<option value="' . $s['id'] . '"' . $sel . $dis . '>' . e($s['name']) . '</option>';
        foreach ($s['children'] as $c) {
            $sel = $selected === (int) $c['id'] ? ' selected' : '';
            $html .= '<option value="' . $c['id'] . '"' . $sel . '>&nbsp;&nbsp;› ' . e($c['name']) . '</option>';
        }
    }
    return $html;
}

function storage_path(string $stored = ''): string
{
    $dir = rtrim((string) cfg('storage_path', APP_ROOT . '/storage'), '/\\');
    return $stored === '' ? $dir : $dir . DIRECTORY_SEPARATOR . $stored;
}

require __DIR__ . '/layout.php';
require __DIR__ . '/crypto.php';
require __DIR__ . '/files.php';
require __DIR__ . '/integrity.php';
require __DIR__ . '/mailer.php';
require __DIR__ . '/send.php';
require __DIR__ . '/migrate.php';

ensure_schema();
