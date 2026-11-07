<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

/*
 * Génération d'un fichier de sommes pour un fichier :
 *   GET  checksum.php?id=12&algo=sha256&format=gnu          -> téléchargement (empreintes déjà calculées)
 *   POST action=download|publish|compute (éditeurs, jeton)  -> calcule au besoin, télécharge ou publie
 */

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
if ($isPost) {
    csrf_check();
    $me = require_role('editor');
}
$in = $isPost ? $_POST : $_GET;

$f = file_row((int) ($in['id'] ?? 0));
if (!$f || !can_view_file($f)) {
    deny(404, 'Fichier introuvable.');
}
$back = 'file.php?id=' . $f['id'] . '#empreintes';
$action = $isPost ? (string) ($in['action'] ?? 'download') : 'download';
$format = (string) ($in['format'] ?? 'gnu');
$algo   = (string) ($in['algo'] ?? 'sha256');
$algos  = $algo === 'all' ? array_keys(gen_algos()) : [$algo];

// Calcul d'une empreinte manquante (éditeurs)
if ($action === 'compute') {
    if (!isset(gen_algos()[$algo])) {
        deny(400, 'Algorithme inconnu.');
    }
    if (is_big($f) && cached_digest($f, $algo) === null) {
        $fid = (int) $f['id'];
        defer_after_response(fn() => file_digest(file_row($fid), $algo));
        flash('info', 'Calcul de l\'empreinte ' . e(gen_algos()[$algo]) . ' lancé en arrière-plan (' . human_size(num($f['size'])) . ') — actualisez la page dans quelques instants.');
        redirect($back);
    }
    $hex = file_digest($f, $algo);
    flash($hex ? 'success' : 'error', $hex ? 'Empreinte ' . e(gen_algos()[$algo]) . ' calculée.' : 'Calcul impossible pour cet algorithme.');
    redirect($back);
}

// Gros fichier dont une empreinte manque : calcul lancé en arrière-plan plutôt que dans la requête
if ($isPost && is_big($f)) {
    $missing = missing_digests($f, $format === 'sfv' ? ['crc32b'] : array_intersect($algos, array_keys(gen_algos())));
    if ($missing) {
        $fid = (int) $f['id'];
        defer_after_response(function () use ($fid, $missing) {
            foreach ($missing as $a) {
                file_digest(file_row($fid), $a);
            }
        });
        flash('info', 'Calcul de ' . e(implode(', ', array_map(fn($a) => gen_algos()[$a], $missing))) . ' lancé en arrière-plan — relancez la génération dans quelques instants.');
        redirect($back);
    }
}

try {
    // Visiteurs : uniquement les empreintes déjà connues (pas de calcul lourd à la demande)
    [$filename, $content] = checksum_generate([$f], $algos, $format, $isPost);
} catch (RuntimeException $ex) {
    if ($isPost) {
        flash('error', 'Génération impossible : ' . e($ex->getMessage()) . '.');
        redirect($back);
    }
    deny(400, 'Génération impossible : ' . $ex->getMessage() . '.');
}

if ($action === 'publish') {
    [$row, $type] = checksum_publish([$f], $format === 'sfv' ? ['crc32b'] : $algos, $filename, $content, (int) $me['id']);
    if ($type === 'same') {
        flash('info', '« ' . e($filename) . ' » est déjà publié avec un contenu identique.');
    } else {
        flash('success', '« ' . e($filename) . ' » ' . ($type === 'version' ? 'mis à jour (nouvelle version)' : 'publié') . ' — vérifié ✔');
        $uid = (int) $me['id'];
        defer_after_response(fn() => notify_files([['file' => $row, 'type' => $type]], [], $uid));
    }
    redirect('file.php?id=' . $row['id']);
}

send_checksum_text($filename, $content);
