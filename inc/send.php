<?php
declare(strict_types=1);

/**
 * Envoi d'un fichier stocké au navigateur (téléchargement ou affichage),
 * avec reprise (Range), HEAD, et délégation possible à Apache / Nginx.
 */
function send_stored_file(string $path, string $name, string $mime, bool $inline, string $etag): never
{
    try {
        $reader = StoredReader::open($path);
    } catch (RuntimeException $ex) {
        error_log('[svpro-downloads] ' . $ex->getMessage() . ' : ' . $path);
        deny(500, has_role('editor') ? 'Lecture impossible : ' . $ex->getMessage() . '.' : 'Le fichier est momentanément indisponible.');
    }
    $size  = $reader->size();
    $start = 0;
    $end   = $size - 1;
    $partial = false;
    // un fichier chiffré est forcément déchiffré par PHP (le serveur web ne connaît pas la clé)
    $mode = $reader->encrypted() ? 'php' : (string) cfg('send_mode', 'php');

    if (isset($_SERVER['HTTP_RANGE']) && $mode === 'php' && $size > 0) {
        if (preg_match('/^bytes=(\d*)-(\d*)$/', trim($_SERVER['HTTP_RANGE']), $m) && ($m[1] !== '' || $m[2] !== '')) {
            if ($m[1] === '') {                       // bytes=-500 : les 500 derniers octets
                $start = max(0, $size - num($m[2]));
            } else {
                $start = num($m[1]);
                $end   = $m[2] !== '' ? min(num($m[2]), $size - 1) : $size - 1;
            }
            if ($start > $end || $start >= $size) {
                header('Content-Range: bytes */' . num_str($size));
                http_response_code(416);
                exit;
            }
            $partial = true;
        }
    }

    session_write_close();
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    $fallback = preg_replace('/[^\x20-\x7E]|["\\\\]/u', '_', $name);
    header('Content-Type: ' . ($inline ? $mime : 'application/octet-stream'));
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, no-transform');
    header('Accept-Ranges: bytes');
    header('ETag: "' . $etag . '"');
    if ($inline && $mime !== 'application/pdf') {
        // un média ouvert directement ne peut exécuter aucun script
        header("Content-Security-Policy: default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox");
    }

    if ($mode === 'xsendfile') {
        header('X-Sendfile: ' . $path);
        exit;
    }
    if ($mode === 'accel') {
        header('X-Accel-Redirect: ' . rtrim((string) cfg('accel_prefix'), '/') . '/' . basename($path));
        exit;
    }

    if ($partial) {
        http_response_code(206);
        header('Content-Range: bytes ' . num_str($start) . '-' . num_str($end) . '/' . num_str($size));
    }
    $length = $end - $start + 1;
    header('Content-Length: ' . num_str(max(0, $length)));

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD' || $size == 0) {
        exit;
    }

    @set_time_limit(0);
    try {
        if ($start > 0 && !$reader->seek($start)) {
            exit;
        }
        while ($length > 0 && connection_status() === CONNECTION_NORMAL) {
            $buf = $reader->read((int) min(262144, $length));
            if ($buf === '') {
                break;
            }
            echo $buf;
            flush();
            $length -= strlen($buf);
        }
    } catch (RuntimeException $ex) {
        // bloc altéré en cours d'envoi : on coupe (le navigateur signalera un téléchargement incomplet)
        error_log('[svpro-downloads] ' . $ex->getMessage() . ' : ' . $path);
    }
    $reader->close();
    exit;
}

/** Page d'erreur de téléchargement */
function deny(int $code, string $msg): never
{
    http_response_code($code);
    render_header('Téléchargement impossible');
    echo '<div class="card empty"><h2>Téléchargement impossible</h2><p>' . e($msg) . '</p><p><a class="btn btn-ghost" href="' . e(url()) . '">Retour à la liste</a></p></div>';
    render_footer();
    exit;
}
