<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

/*
 * Téléchargement sécurisé :
 *   download.php?id=12        -> version courante, selon la visibilité du fichier
 *   download.php?id=12&v=34   -> version archivée n° 34 de ce fichier
 *   download.php?s=<jeton>    -> lien de partage (expiration / quota), version courante
 */

$link = null;
$ver  = null;
$token = (string) ($_GET['s'] ?? '');

if ($token !== '') {
    if (!preg_match('/^[a-f0-9]{40}$/', $token)) {
        deny(404, 'Lien invalide.');
    }
    $link = q('SELECT * FROM ' . t('share_links') . ' WHERE token = ?', [$token])->fetch();
    if (!$link) {
        deny(404, 'Ce lien de partage n\'existe pas ou a été supprimé.');
    }
    if ($link['expires_at'] !== null && strtotime($link['expires_at']) < time()) {
        deny(410, 'Ce lien de partage a expiré.');
    }
    if ($link['max_downloads'] !== null && (int) $link['uses'] >= (int) $link['max_downloads']) {
        deny(410, 'Ce lien a atteint son nombre maximal de téléchargements.');
    }
    $f = file_row((int) $link['file_id']) ?? deny(404, 'Fichier introuvable.');
} else {
    $f = file_row((int) ($_GET['id'] ?? 0)) ?? deny(404, 'Fichier introuvable.');
    if (!can_view_file($f)) {
        if ($f['visibility'] === 'private' && !current_user()) {
            $_SESSION['after_login'] = url('file.php?id=' . $f['id']);
            flash('info', 'Ce fichier est réservé aux membres. Connectez-vous pour le télécharger.');
            redirect('login.php');
        }
        deny(404, 'Fichier introuvable.');
    }
    if (isset($_GET['v'])) {
        if (!versions_public() && !has_role('editor')) {
            deny(403, 'L\'historique des versions n\'est pas accessible.');
        }
        $ver = q('SELECT * FROM ' . t('file_versions') . ' WHERE id = ? AND file_id = ?', [(int) $_GET['v'], $f['id']])->fetch()
            ?: deny(404, 'Cette version n\'existe plus.');
    }
}

$item = $ver ?? $f; // contenu effectivement envoyé
$path = storage_path($item['stored_name']);
if (!is_file($path) || !is_readable($path)) {
    error_log('[svpro-downloads] fichier manquant sur disque : ' . $path);
    deny(500, has_role('editor')
        ? 'Le fichier est absent du stockage (' . $path . '). Voir Réglages › Fichiers › Stockage.'
        : 'Le fichier est momentanément indisponible.');
}

// Comptage : uniquement pour le premier morceau (une reprise n'est pas recomptée)
$isFirstChunk = !isset($_SERVER['HTTP_RANGE']) || preg_match('/^bytes=0-/', (string) $_SERVER['HTTP_RANGE']);
if ($isFirstChunk && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    $db = db();
    $db->beginTransaction();
    try {
        if ($link) {
            $st = q('UPDATE ' . t('share_links') . ' SET uses = uses + 1
                     WHERE id = ? AND (max_downloads IS NULL OR uses < max_downloads)', [$link['id']]);
            if ($st->rowCount() === 0) {
                $db->rollBack();
                deny(410, 'Ce lien a atteint son nombre maximal de téléchargements.');
            }
        }
        q('UPDATE ' . t('files') . ' SET downloads = downloads + 1, updated_at = updated_at WHERE id = ?', [$f['id']]);
        if ($ver) {
            q('UPDATE ' . t('file_versions') . ' SET downloads = downloads + 1 WHERE id = ?', [$ver['id']]);
        }
        q('INSERT INTO ' . t('download_log') . ' (file_id, user_id, link_id, version_id, ip, user_agent) VALUES (?,?,?,?,?,?)', [
            $f['id'],
            current_user()['id'] ?? null,
            $link['id'] ?? null,
            $ver['id'] ?? null,
            log_ip(),
            mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
        ]);
        $db->commit();
    } catch (Throwable $ex) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        error_log('[svpro-downloads] journalisation : ' . $ex->getMessage());
    }

    $ret = (int) cfg('log_retention_days', 365);
    if ($ret > 0 && random_int(1, 100) === 1) {
        q('DELETE FROM ' . t('download_log') . ' WHERE created_at < (NOW() - INTERVAL ? DAY)', [$ret]);
    }
}

send_stored_file($path, $item['original_name'], $item['mime'], false, substr($item['sha256'], 0, 32));
