<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

/*
 * Affichage en ligne (aperçu) : images, PDF, audio, vidéo.
 * Mêmes droits que la fiche, n'est pas compté comme un téléchargement.
 */

$f = file_row((int) ($_GET['id'] ?? 0));
if (!$f || !can_view_file($f)) {
    http_response_code(404);
    exit('Introuvable.');
}
$kind = preview_kind($f);
if (!in_array($kind, ['image', 'pdf', 'audio', 'video'], true)) {
    http_response_code(415);
    exit('Aperçu non disponible pour ce type de fichier.');
}
$path = storage_path($f['stored_name']);
if (!is_file($path)) {
    http_response_code(404);
    exit('Fichier indisponible.');
}

// Cache navigateur court ; l'ETag change avec le contenu
$etag = substr($f['sha256'], 0, 32);
if (trim((string) ($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''), '"') === $etag && !isset($_SERVER['HTTP_RANGE'])) {
    http_response_code(304);
    exit;
}
send_stored_file($path, $f['original_name'], $f['mime'], true, $etag);
