<?php
declare(strict_types=1);

/**
 * Chiffrement des fichiers au repos (côté serveur, transparent).
 *
 * Algorithme : XChaCha20-Poly1305 (libsodium, chiffrement authentifié).
 * Enveloppe   : chaque fichier a sa propre clé aléatoire, chiffrée par la clé maîtresse
 *               (fichier hors du dossier web et hors du stockage).
 * Format      : en-tête de 108 octets puis blocs de 1 Mio chiffrés indépendamment
 *               => accès aléatoire (reprise d'un téléchargement au milieu d'un ISO),
 *               détection de toute altération, et de la troncature (drapeau « dernier bloc »).
 *
 *   en-tête  = MAGIC(8) | taille de bloc(4) | taille en clair(8) | nonce(24) | clé du fichier chiffrée(48) | base de nonce(16)
 *   bloc n   = AEAD(clair, ad = MAGIC|n|dernier?, nonce = base|n, clé du fichier)   (+16 octets)
 *
 * Compatible PHP 32 bits (positions et tailles en int|float).
 */

const ENC_MAGIC  = "SVPENC01";
const ENC_BLOCK  = 1048576;
const ENC_TAG    = 16;
const ENC_HEADER = 108;

function crypto_available(): bool
{
    return function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt');
}

/** Emplacement de la clé maîtresse : réglage config.php, sinon à côté (au-dessus) du dossier web */
function encryption_key_path(): string
{
    $p = trim((string) cfg('encryption_key_file', ''));
    if ($p === '') {
        return dirname(APP_ROOT) . DIRECTORY_SEPARATOR . 'svpro-downloads.key';
    }
    // un dossier est accepté : la clé est alors le fichier svpro-downloads.key qu'il contient
    if (is_dir($p) || str_ends_with($p, '/') || str_ends_with($p, '\\')) {
        return rtrim($p, '/\\') . DIRECTORY_SEPARATOR . 'svpro-downloads.key';
    }
    return $p;
}

function master_key(): ?string
{
    static $key = false;
    if ($key === false) {
        $key = null;
        $p = encryption_key_path();
        if (is_file($p) && is_readable($p)) {
            $raw = base64_decode(trim((string) file_get_contents($p)), true);
            if ($raw !== false && strlen($raw) === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
                $key = $raw;
            }
        }
    }
    return $key;
}

/** Empreinte courte de la clé (pour vérifier qu'une sauvegarde correspond) */
function key_fingerprint(): ?string
{
    $k = master_key();
    return $k === null ? null : implode(' ', str_split(strtoupper(substr(hash('sha256', 'svpro-key-fp' . $k), 0, 16)), 4));
}

/** Crée la clé maîtresse (jamais d'écrasement d'une clé existante) */
function generate_master_key(): string
{
    if (!crypto_available()) {
        throw new RuntimeException('l\'extension PHP sodium est absente');
    }
    $p = encryption_key_path();
    if (is_file($p)) {
        throw new RuntimeException('une clé existe déjà dans ' . $p . ' (elle n\'est pas écrasée) — si elle n\'est pas reconnue, vérifiez son contenu et ses droits de lecture');
    }
    if (file_exists($p)) {
        throw new RuntimeException($p . ' existe mais n\'est pas un fichier');
    }
    $dir = dirname($p);
    if (!is_dir($dir)) {
        throw new RuntimeException('le dossier ' . $dir . ' n\'existe pas');
    }
    if (!is_writable($dir)) {
        throw new RuntimeException('le dossier ' . $dir . ' n\'est pas accessible en écriture pour PHP (utilisateur ' . (function_exists('posix_geteuid') && function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?') . ')');
    }
    $real = realpath($dir) . DIRECTORY_SEPARATOR;
    $web = realpath(APP_ROOT) . DIRECTORY_SEPARATOR;
    if (str_starts_with($real, $web)) {
        throw new RuntimeException('la clé ne doit pas se trouver dans le dossier web de l\'application');
    }
    $key = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    $old = umask(0277);
    $ok = file_put_contents($p, base64_encode($key) . "\n", LOCK_EX);
    umask($old);
    if ($ok === false) {
        throw new RuntimeException('écriture de la clé impossible');
    }
    @chmod($p, 0400);
    return $p;
}

/** Les nouveaux fichiers doivent-ils être chiffrés ? */
function encryption_enabled(): bool
{
    return (bool) setting('encrypt_new', false) && crypto_available() && master_key() !== null;
}

/** Le fichier stocké est-il chiffré (signature en tête) ? */
function is_encrypted_file(string $path): bool
{
    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return false;
    }
    $head = (string) fread($fh, 8);
    fclose($fh);
    return $head === ENC_MAGIC;
}

/* ---------- Petits utilitaires binaires (sûrs en 32 bits) ---------- */

function enc_pack64(int|float $n): string
{
    $hi = (int) floor($n / 4294967296);
    $lo = $n - $hi * 4294967296;
    $lo = $lo >= 2147483648 ? (int) ($lo - 4294967296) : (int) $lo; // pack('N') attend un int signé en 32 bits
    return pack('NN', $hi, $lo);
}

function enc_unpack64(string $s): int|float
{
    $u = unpack('Nhi/Nlo', $s);
    $hi = $u['hi'] < 0 ? $u['hi'] + 4294967296 : $u['hi'];
    $lo = $u['lo'] < 0 ? $u['lo'] + 4294967296 : $u['lo'];
    return num(sprintf('%.0f', $hi * 4294967296 + $lo));
}

function enc_last_index(int|float $size): int|float
{
    return $size <= 0 ? 0 : num(sprintf('%.0f', ceil($size / ENC_BLOCK) - 1));
}

/** Taille chiffrée attendue pour une taille en clair */
function enc_cipher_size(int|float $plain): int|float
{
    $blocks = $plain <= 0 ? 1 : ceil($plain / ENC_BLOCK);
    return num(sprintf('%.0f', ENC_HEADER + $plain + $blocks * ENC_TAG));
}

function enc_block(string $key, string $nonceBase, int|float $index, string $plain, bool $final): string
{
    $idx = enc_pack64($index);
    return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, ENC_MAGIC . $idx . ($final ? "\x01" : "\x00"), $nonceBase . $idx, $key);
}

/** Nouvel en-tête : [octets, clé du fichier, base de nonce] */
function enc_header_new(int|float $size): array
{
    $master = master_key() ?? throw new RuntimeException('clé de chiffrement introuvable (' . encryption_key_path() . ')');
    $fileKey = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    $nonceBase = random_bytes(16);
    $fixed = ENC_MAGIC . pack('N', ENC_BLOCK) . enc_pack64($size);
    $wrapNonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($fileKey, $fixed, $wrapNonce, $master);
    return [$fixed . $wrapNonce . $wrapped . $nonceBase, $fileKey, $nonceBase];
}

/** Lecture d'un en-tête : [taille en clair, clé du fichier, base de nonce] */
function enc_header_parse(string $h): array
{
    if (strlen($h) !== ENC_HEADER || substr($h, 0, 8) !== ENC_MAGIC) {
        throw new RuntimeException('en-tête de chiffrement invalide');
    }
    if (unpack('N', substr($h, 8, 4))[1] !== ENC_BLOCK) {
        throw new RuntimeException('taille de bloc non prise en charge');
    }
    $master = master_key() ?? throw new RuntimeException('clé de chiffrement introuvable (' . encryption_key_path() . ')');
    $fileKey = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($h, 44, 48), substr($h, 0, 20), substr($h, 20, 24), $master);
    if ($fileKey === false) {
        throw new RuntimeException('impossible d\'ouvrir le fichier chiffré : la clé de chiffrement ne correspond pas');
    }
    return [enc_unpack64(substr($h, 12, 8)), $fileKey, substr($h, 92, 16)];
}

/**
 * Écriture chiffrée en flux : on lui passe le clair au fil de l'eau, elle écrit les blocs.
 * La taille totale doit être connue d'avance (elle figure dans l'en-tête).
 */
final class EncWriter
{
    private string $buf = '';
    private int|float $index = 0;
    private int|float $done = 0;
    private string $key;
    private string $nonceBase;

    public function __construct(private $fh, private int|float $size)
    {
        [$header, $this->key, $this->nonceBase] = enc_header_new($size);
        $this->out($header);
    }

    private function out(string $data): void
    {
        if (fwrite($this->fh, $data) !== strlen($data)) {
            throw new RuntimeException('écriture interrompue (disque plein ?)');
        }
    }

    public function write(string $data): void
    {
        $this->buf .= $data;
        while (strlen($this->buf) >= ENC_BLOCK) {
            $block = substr($this->buf, 0, ENC_BLOCK);
            $this->buf = substr($this->buf, ENC_BLOCK);
            $this->done += ENC_BLOCK;
            $this->out(enc_block($this->key, $this->nonceBase, $this->index, $block, $this->done >= $this->size));
            $this->index++;
        }
    }

    public function finish(): void
    {
        if ($this->buf !== '' || $this->index == 0) {
            $this->done += strlen($this->buf);
            $this->out(enc_block($this->key, $this->nonceBase, $this->index, $this->buf, true));
            $this->index++;
            $this->buf = '';
        }
        if (!num_eq($this->done, $this->size)) {
            throw new RuntimeException('taille inattendue (le fichier a changé pendant le traitement ?)');
        }
    }
}

/**
 * Lecture d'un fichier stocké, chiffré ou non, avec accès aléatoire.
 * $raw = true : lecture brute (fichier du dossier d'import, jamais interprété comme chiffré).
 */
final class StoredReader
{
    private $fh;
    private bool $enc = false;
    private int|float $size = 0;
    private string $key = '';
    private string $nonceBase = '';
    private int|float $next = 0;   // prochain bloc à déchiffrer
    private string $buf = '';

    public static function open(string $path, bool $raw = false): self
    {
        $r = new self();
        $r->fh = @fopen($path, 'rb');
        if (!$r->fh) {
            throw new RuntimeException('lecture impossible');
        }
        $head = $raw ? '' : (string) fread($r->fh, ENC_HEADER);
        if (!$raw && str_starts_with($head, ENC_MAGIC)) {
            [$r->size, $r->key, $r->nonceBase] = enc_header_parse($head);
            $r->enc = true;
        } else {
            $r->size = fsize($path);
            fseek($r->fh, 0);
        }
        return $r;
    }

    public function encrypted(): bool
    {
        return $this->enc;
    }

    /** Taille en clair */
    public function size(): int|float
    {
        return $this->size;
    }

    /** Jusqu'à $n octets en clair ('' en fin de fichier) */
    public function read(int $n): string
    {
        if (!$this->enc) {
            $s = fread($this->fh, $n);
            return $s === false ? '' : $s;
        }
        $last = enc_last_index($this->size);
        while (strlen($this->buf) < $n && $this->next <= $last) {
            $plainLen = (int) min(ENC_BLOCK, $this->size - $this->next * ENC_BLOCK);
            $want = $plainLen + ENC_TAG;
            $ct = '';
            while (strlen($ct) < $want) {
                $part = fread($this->fh, $want - strlen($ct));
                if ($part === false || $part === '') {
                    throw new RuntimeException('fichier chiffré tronqué');
                }
                $ct .= $part;
            }
            $idx = enc_pack64($this->next);
            $pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, ENC_MAGIC . $idx . ($this->next == $last ? "\x01" : "\x00"), $this->nonceBase . $idx, $this->key);
            if ($pt === false) {
                throw new RuntimeException('fichier chiffré altéré ou corrompu (bloc ' . num_str($this->next) . ')');
            }
            $this->buf .= $pt;
            $this->next++;
        }
        $out = substr($this->buf, 0, $n);
        $this->buf = (string) substr($this->buf, strlen($out));
        return $out;
    }

    /** Se place à une position en clair */
    public function seek(int|float $offset): bool
    {
        if (!$this->enc) {
            return fseek_far($this->fh, $offset);
        }
        $block = num(sprintf('%.0f', floor($offset / ENC_BLOCK)));
        if (!fseek_far($this->fh, ENC_HEADER + $block * (ENC_BLOCK + ENC_TAG))) {
            return false;
        }
        $this->next = $block;
        $this->buf = '';
        $skip = (int) ($offset - $block * ENC_BLOCK);
        if ($skip > 0) {
            $this->read($skip);
        }
        return true;
    }

    public function close(): void
    {
        if ($this->fh) {
            fclose($this->fh);
            $this->fh = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }
}

/** Contenu complet en clair d'un petit fichier stocké (fichiers de sommes, aperçu texte…) */
function stored_contents(string $path, int $max = 4194304): string
{
    $r = StoredReader::open($path);
    $out = '';
    while (strlen($out) < $max && ($s = $r->read(min(1048576, $max - strlen($out)))) !== '') {
        $out .= $s;
    }
    return $out;
}

/** Taille en clair d'un fichier stocké */
function stored_size(string $path): int|float
{
    if (!is_encrypted_file($path)) {
        return fsize($path);
    }
    $fh = fopen($path, 'rb');
    $h = (string) fread($fh, 20);
    fclose($fh);
    return enc_unpack64(substr($h, 12, 8));
}

/** Type MIME d'après le début (en clair) d'un fichier stocké */
function stored_mime(string $path): string
{
    try {
        $head = StoredReader::open($path)->read(65536);
    } catch (RuntimeException) {
        return 'application/octet-stream';
    }
    return mb_substr((new finfo(FILEINFO_MIME_TYPE))->buffer($head) ?: 'application/octet-stream', 0, 120);
}

/**
 * Chiffre (ou déchiffre) un fichier stocké sur place, de façon sûre :
 * écriture dans un fichier temporaire, contrôle du SHA-256 en clair, puis remplacement atomique.
 */
function crypto_convert_file(string $path, bool $encrypt, ?string $expectSha256, ?callable $progress = null): void
{
    $r = StoredReader::open($path);
    if ($r->encrypted() === $encrypt) {
        return; // déjà dans l'état voulu
    }
    $tmp = $path . '.tmp-' . getmypid();
    $out = fopen($tmp, 'wb');
    if (!$out) {
        throw new RuntimeException('écriture impossible dans le stockage');
    }
    try {
        $w = $encrypt ? new EncWriter($out, $r->size()) : null;
        $ctx = hash_init('sha256');
        $done = 0;
        while (($s = $r->read(8388608)) !== '') {
            hash_update($ctx, $s);
            if ($w) {
                $w->write($s);
            } elseif (fwrite($out, $s) !== strlen($s)) {
                throw new RuntimeException('écriture interrompue (disque plein ?)');
            }
            $done += strlen($s);
            if ($progress) {
                $progress($done);
            }
        }
        $w?->finish();
        fclose($out);
        $out = null;
        $sha = hash_final($ctx);
        if ($expectSha256 !== null && $expectSha256 !== '' && !hash_equals($expectSha256, $sha)) {
            throw new RuntimeException('contrôle SHA-256 en échec : le fichier d\'origine est peut-être corrompu, il n\'a pas été modifié');
        }
        $r->close();
        @chmod($tmp, 0640);
        if (!@rename($tmp, $path)) {
            throw new RuntimeException('remplacement impossible');
        }
    } finally {
        if ($out) {
            fclose($out);
        }
        if (is_file($tmp)) {
            @unlink($tmp);
        }
    }
}

/* =====================================================================
 * Conversion des fichiers existants (chiffrer / déchiffrer) en arrière-plan,
 * avec avancement en temps réel (storage/.chunks/crypto.json).
 * ===================================================================== */

function crypto_state_path(): string
{
    return chunk_dir() . '/crypto.json';
}

function crypto_state(): ?array
{
    $p = crypto_state_path();
    $st = is_file($p) ? json_decode((string) @file_get_contents($p), true) : null;
    if (!is_array($st)) {
        return null;
    }
    if ($st['state'] === 'running' && (int) ($st['updated'] ?? 0) < time() - 600) {
        $st['state'] = 'error';
        $st['messages'][] = ['error', 'La conversion s\'est arrêtée sans terminer (processus PHP interrompu). Relancez-la : les fichiers déjà traités sont conservés.'];
    }
    return $st;
}

function crypto_state_save(array $st): void
{
    $st['updated'] = time();
    $tmp = crypto_state_path() . '.' . getmypid();
    file_put_contents($tmp, json_encode($st, JSON_UNESCAPED_UNICODE));
    @rename($tmp, crypto_state_path());
}

/** Fichiers et versions stockés, avec leur état de chiffrement */
function crypto_inventory(): array
{
    $items = [];
    foreach (q('SELECT id, title, stored_name, size, sha256 FROM ' . t('files'))->fetchAll() as $r) {
        $items[] = $r + ['kind' => 'file'];
    }
    foreach (q('SELECT v.id, CONCAT(f.title, \' (v\', COALESCE(v.version, \'?\'), \')\') title, v.stored_name, v.size, v.sha256 FROM ' . t('file_versions') . ' v JOIN ' . t('files') . ' f ON f.id = v.file_id')->fetchAll() as $r) {
        $items[] = $r + ['kind' => 'version'];
    }
    foreach ($items as $k => $it) {
        $path = storage_path($it['stored_name']);
        $items[$k]['present'] = is_file($path);
        $items[$k]['encrypted'] = $items[$k]['present'] && is_encrypted_file($path);
        $items[$k]['size'] = num($it['size']);
    }
    return $items;
}

/** Chiffre (ou déchiffre) tout le stockage ; chaque fichier est contrôlé par son SHA-256 */
function crypto_job(bool $encrypt): void
{
    @set_time_limit(0);
    ignore_user_abort(true);
    $todo = array_values(array_filter(crypto_inventory(), fn($i) => $i['present'] && $i['encrypted'] !== $encrypt));
    $st = crypto_state() ?? [];
    $st['total'] = array_sum(array_column($todo, 'size'));
    $st['count'] = count($todo);
    $st['done'] = 0;
    $st['index'] = 0;
    $st['ok'] = 0;
    $st['errors'] = 0;
    crypto_state_save($st);
    $t0 = microtime(true);
    $before = 0;
    $last = 0.0;
    foreach ($todo as $i => $it) {
        $st['index'] = $i;
        $st['current'] = $it['title'];
        try {
            crypto_convert_file(storage_path($it['stored_name']), $encrypt, $it['sha256'], function ($d) use (&$st, &$before, &$last, $t0) {
                $now = microtime(true);
                if ($now - $last >= 0.5) {
                    $last = $now;
                    $st['done'] = $before + $d;
                    $st['speed'] = $st['done'] / max(0.001, $now - $t0);
                    crypto_state_save($st);
                }
            });
            $st['ok']++;
        } catch (Throwable $ex) {
            $st['errors']++;
            $st['messages'][] = ['error', $it['title'] . ' : ' . $ex->getMessage()];
        }
        $before += $it['size'];
        $st['done'] = $before;
        crypto_state_save($st);
    }
    $st['state'] = 'done';
    $st['elapsed'] = round(microtime(true) - $t0, 1);
    $st['messages'][] = [$st['errors'] ? 'error' : 'success',
        $st['ok'] . ' fichier(s) ' . ($encrypt ? 'chiffré(s)' : 'déchiffré(s)') . ($st['errors'] ? ', ' . $st['errors'] . ' en erreur (laissés intacts)' : '') . '.'];
    crypto_state_save($st);
}
