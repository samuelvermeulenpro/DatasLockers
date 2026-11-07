<?php
declare(strict_types=1);

/**
 * Mise à niveau automatique du schéma (idempotente).
 * Exécutée au premier accès après une mise à jour des fichiers.
 */
const SCHEMA_VERSION = 4;

function ensure_schema(): void
{
    if ((int) setting('schema', 1) >= SCHEMA_VERSION) {
        return;
    }
    $lock = storage_path('.migrate.lock');
    $fh = @fopen($lock, 'c');
    if ($fh) {
        flock($fh, LOCK_EX);
    }
    try {
        migrate_all();
        setting_set('schema', SCHEMA_VERSION);
    } finally {
        if ($fh) {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}

function column_exists(string $table, string $column): bool
{
    return (bool) q('SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
        [$table, $column])->fetchColumn();
}

function migrate_all(): void
{
    $p = cfg('db.prefix', 'dl_');
    $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

    // v3 — versions
    if (!column_exists($p . 'files', 'version_notes')) {
        db()->exec("ALTER TABLE {$p}files ADD version_notes TEXT NULL AFTER version");
    }
    if (!column_exists($p . 'files', 'content_at')) {
        db()->exec("ALTER TABLE {$p}files ADD content_at DATETIME NULL AFTER uploaded_by");
        db()->exec("UPDATE {$p}files SET content_at = created_at WHERE content_at IS NULL");
    }
    db()->exec("CREATE TABLE IF NOT EXISTS {$p}file_versions (
        id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        file_id       INT UNSIGNED NOT NULL,
        version       VARCHAR(40) NULL,
        notes         TEXT NULL,
        original_name VARCHAR(255) NOT NULL,
        stored_name   CHAR(32) NOT NULL UNIQUE,
        mime          VARCHAR(120) NOT NULL,
        size          BIGINT UNSIGNED NOT NULL,
        sha256        CHAR(64) NOT NULL,
        downloads     INT UNSIGNED NOT NULL DEFAULT 0,
        uploaded_by   INT UNSIGNED NULL,
        created_at    DATETIME NOT NULL,
        archived_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_{$p}ver_file (file_id),
        CONSTRAINT fk_{$p}ver_file FOREIGN KEY (file_id) REFERENCES {$p}files(id) ON DELETE CASCADE,
        CONSTRAINT fk_{$p}ver_user FOREIGN KEY (uploaded_by) REFERENCES {$p}users(id) ON DELETE SET NULL
    ) $opts");
    if (!column_exists($p . 'download_log', 'version_id')) {
        db()->exec("ALTER TABLE {$p}download_log ADD version_id INT UNSIGNED NULL AFTER link_id");
    }

    // v3 — intégrité
    db()->exec("CREATE TABLE IF NOT EXISTS {$p}checksum_entries (
        id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        source_file_id INT UNSIGNED NOT NULL,
        line_no        INT UNSIGNED NOT NULL DEFAULT 0,
        filename       VARCHAR(255) NOT NULL,
        algo           VARCHAR(20) NOT NULL,
        expected       VARCHAR(128) NOT NULL,
        target_file_id INT UNSIGNED NULL,
        status         ENUM('ok','mismatch','outdated','missing','unsupported') NULL,
        matched_version_id INT UNSIGNED NULL,
        checked_at     DATETIME NULL,
        KEY idx_{$p}ck_name (filename(191)),
        KEY idx_{$p}ck_target (target_file_id),
        CONSTRAINT fk_{$p}ck_source FOREIGN KEY (source_file_id) REFERENCES {$p}files(id) ON DELETE CASCADE,
        CONSTRAINT fk_{$p}ck_target FOREIGN KEY (target_file_id) REFERENCES {$p}files(id) ON DELETE SET NULL
    ) $opts");
    if (!column_exists($p . 'checksum_entries', 'matched_version_id')) {
        db()->exec("ALTER TABLE {$p}checksum_entries
            MODIFY status ENUM('ok','mismatch','outdated','missing','unsupported') NULL,
            ADD matched_version_id INT UNSIGNED NULL AFTER status");
    }
    db()->exec("CREATE TABLE IF NOT EXISTS {$p}file_hashes (
        file_id INT UNSIGNED NOT NULL,
        algo    VARCHAR(20) NOT NULL,
        hex     VARCHAR(128) NOT NULL,
        PRIMARY KEY (file_id, algo),
        CONSTRAINT fk_{$p}fh_file FOREIGN KEY (file_id) REFERENCES {$p}files(id) ON DELETE CASCADE
    ) $opts");

    // v4 — tailles réelles : corrige les tailles faussées par un PHP 32 bits (fichiers > 2 Go)
    repair_sizes();

    // Les fichiers de sommes déjà présents sont analysés une première fois
    foreach (q("SELECT * FROM {$p}files")->fetchAll() as $f) {
        if (is_checksum_file($f['original_name'])) {
            try {
                integrity_index_source($f);
            } catch (Throwable $ex) {
                error_log('[svpro-downloads] migration intégrité : ' . $ex->getMessage());
            }
        }
    }
}

/** Recalcule depuis le disque la taille des fichiers et versions ; renvoie le nombre de corrections */
function repair_sizes(): int
{
    $n = 0;
    foreach (['files', 'file_versions'] as $tbl) {
        foreach (q('SELECT id, stored_name, size FROM ' . t($tbl))->fetchAll() as $r) {
            $path = storage_path($r['stored_name']);
            if (!is_file($path)) {
                continue;
            }
            $real = stored_size($path); // taille en clair (fichier chiffré : lue dans l'en-tête)
            if (!num_eq($real, $r['size'])) {
                q('UPDATE ' . t($tbl) . ' SET size = ?' . ($tbl === 'files' ? ', updated_at = updated_at' : '') . ' WHERE id = ?', [num_str($real), $r['id']]);
                $n++;
            }
        }
    }
    return $n;
}
