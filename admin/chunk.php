<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';

/*
 * Réception des gros fichiers par morceaux (contourne upload_max_filesize / post_max_size).
 *   op=init   name, size, fp   -> { id, offset, chunk }  (offset > 0 : reprise d'un envoi interrompu)
 *   op=put    id, offset, chunk (fichier)   -> { offset }
 *   op=status id                -> { offset }
 *   op=cancel id
 * La fiche est créée ensuite par admin/upload.php avec le champ chunked[] = id.
 */

$me = require_role('editor');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function out(array $data, int $code = 200): never
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    out(['ok' => false, 'error' => 'méthode non autorisée'], 405);
}
if (empty($_POST) && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
    out(['ok' => false, 'error' => 'morceau trop volumineux pour post_max_size (' . ini_get('post_max_size') . ')'], 413);
}
$t = $_POST['_csrf'] ?? '';
if (!is_string($t) || !hash_equals(csrf_token(), $t)) {
    out(['ok' => false, 'error' => 'jeton de sécurité expiré : rechargez la page'], 400);
}
session_write_close(); // plusieurs requêtes en parallèle ne se bloquent pas sur la session

$uid = (int) $me['id'];
$op = (string) ($_POST['op'] ?? '');

try {
    switch ($op) {
        case 'init':
            $name = clean_upload_name((string) ($_POST['name'] ?? ''));
            $size = num($_POST['size'] ?? -1);
            $fp   = mb_substr((string) ($_POST['fp'] ?? ''), 0, 200);
            if (($err = check_extension($name)) !== null) {
                out(['ok' => false, 'error' => $name . ' : ' . $err]);
            }
            if ($size < 0) {
                out(['ok' => false, 'error' => 'taille invalide']);
            }
            if ($size > max_upload_bytes()) {
                out(['ok' => false, 'error' => $name . ' : dépasse la taille maximale autorisée (' . human_size(max_upload_bytes()) . ', voir Réglages)']);
            }
            if (random_int(1, 20) === 1) {
                chunk_purge();
            }
            // même utilisateur + même fichier (nom, taille, date) => même identifiant : reprise possible
            $id = substr(hash('sha256', $uid . '|' . $name . '|' . $size . '|' . $fp), 0, 32);
            $p = chunk_paths($id);
            $offset = 0;
            $enc = encryption_enabled();
            $meta = null;
            if (is_file($p['meta']) && is_file($p['part'])) {
                $old = json_decode((string) file_get_contents($p['meta']), true);
                if (is_array($old) && (int) $old['user'] === $uid && num_eq($old['size'], $size)) {
                    $meta = $old;
                    $enc = !empty($old['enc']); // une reprise garde le mode de départ
                    $offset = $enc ? num($old['received'] ?? 0) : min(fsize($p['part']), $size);
                    if ($enc && !num_eq(fsize($p['part']), chunk_cipher_expected($offset, $size))) {
                        $offset = 0; // fichier partiel incohérent (coupure brutale) : on repart de zéro
                        $meta = null;
                    }
                }
            }
            if ($enc && chunk_bytes() < ENC_BLOCK && $size > chunk_bytes()) {
                out(['ok' => false, 'error' => 'limites PHP trop basses pour l\'envoi chiffré (post_max_size doit dépasser 1 Mo)']);
            }
            $free = @disk_free_space(chunk_dir());
            if ($free !== false && $free < ($size - $offset) + 100 * 1048576) {
                out(['ok' => false, 'error' => 'espace disque insuffisant sur le serveur (' . human_size($free) . ' libres)']);
            }
            if ($offset == 0) {
                // chiffré : l'en-tête (clé du fichier enveloppée) est écrit d'emblée, les blocs suivront
                $head = '';
                if ($enc) {
                    [$head, $k, $nb] = enc_header_new($size);
                    if ($size == 0) {
                        $head .= enc_block($k, $nb, 0, '', true); // fichier vide : un bloc final vide
                    }
                }
                file_put_contents($p['part'], $head);
                try {
                    file_put_contents($p['hash'], serialize(['n' => 0, 'ctx' => hash_init('sha256')]));
                } catch (Throwable) {
                    @unlink($p['hash']);
                }
                $meta = ['name' => $name, 'size' => $size, 'user' => $uid, 'started' => date('c'), 'enc' => $enc, 'received' => 0, 'mime' => null];
            }
            chunk_meta_save($p['meta'], $meta);
            out(['ok' => true, 'id' => $id, 'offset' => $offset, 'chunk' => chunk_bytes(), 'resumed' => $offset > 0, 'encrypted' => $enc]);

        case 'put':
            $id = (string) ($_POST['id'] ?? '');
            $meta = chunk_meta($id, $uid);
            $p = $meta['paths'];
            $up = $_FILES['chunk'] ?? null;
            if (!$up || $up['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($up['tmp_name'])) {
                out(['ok' => false, 'error' => 'morceau non reçu (code ' . ($up['error'] ?? '?') . ')', 'retry' => true]);
            }
            $offset = num($_POST['offset'] ?? -1);
            $len = num($up['size']);

            // ajout en fin de fichier : fiable au-delà de 2 Go, même sur PHP 32 bits (pas de fseek)
            $fh = fopen($p['part'], 'ab');
            if (!$fh || !flock($fh, LOCK_EX)) {
                out(['ok' => false, 'error' => 'fichier temporaire verrouillé', 'retry' => true]);
            }
            $release = function () use ($fh) {
                flock($fh, LOCK_UN);
                fclose($fh);
            };
            $meta = chunk_meta($id, $uid); // relu sous verrou
            $enc = !empty($meta['enc']);
            $size = num($meta['size']);
            $cipherBefore = fsize($p['part']);
            $current = $enc ? num($meta['received'] ?? 0) : $cipherBefore;
            if (!num_eq($offset, $current)) {
                // le navigateur et le serveur ne sont plus d'accord (morceau déjà reçu…) : on resynchronise
                $release();
                out(['ok' => false, 'resync' => true, 'offset' => $current]);
            }
            if ($len > chunk_bytes() + 1024 || $current + $len > $size) {
                $release();
                out(['ok' => false, 'error' => 'morceau de taille incohérente'], 400);
            }
            if ($enc && ($current + $len < $size) && fmod((float) $len, ENC_BLOCK) != 0) {
                $release();
                out(['ok' => false, 'error' => 'morceau non aligné sur les blocs de chiffrement'], 400);
            }
            if ($enc && !num_eq($cipherBefore, chunk_cipher_expected($current, $size))) {
                $release();
                foreach ($p as $tmp) {
                    @unlink($tmp);
                }
                out(['ok' => false, 'error' => 'fichier partiel incohérent — l\'envoi doit être recommencé']);
            }

            try {
                if ($enc) {
                    // chiffrement du morceau, bloc par bloc (1 Mio), sans le garder en mémoire
                    $hfh = fopen($p['part'], 'rb');
                    [, $fileKey, $nonceBase] = enc_header_parse((string) fread($hfh, ENC_HEADER));
                    fclose($hfh);
                    $in = fopen($up['tmp_name'], 'rb');
                    $index = num(sprintf('%.0f', $current / ENC_BLOCK));
                    $pos = $current;
                    $first = true;
                    do {
                        $block = (string) fread($in, ENC_BLOCK);
                        if ($first && $current == 0) {
                            $meta['mime'] = mb_substr((new finfo(FILEINFO_MIME_TYPE))->buffer(substr($block, 0, 65536)) ?: 'application/octet-stream', 0, 120);
                        }
                        $first = false;
                        $pos += strlen($block);
                        if ($block === '') {
                            break;
                        }
                        $ct = enc_block($fileKey, $nonceBase, $index, $block, $pos >= $size);
                        if (fwrite($fh, $ct) !== strlen($ct)) {
                            throw new RuntimeException('écriture incomplète (disque plein ?)');
                        }
                        $index++;
                    } while ($pos < $current + $len);
                    fclose($in);
                } else {
                    $in = fopen($up['tmp_name'], 'rb');
                    $written = stream_copy_to_stream($in, $fh);
                    fclose($in);
                    if ($written !== $len) {
                        throw new RuntimeException('écriture incomplète (disque plein ?)');
                    }
                }
                fflush($fh);
            } catch (RuntimeException $ex) {
                if (is_int($cipherBefore)) {
                    ftruncate($fh, $cipherBefore); // on annule le morceau partiel
                    $release();
                    out(['ok' => false, 'error' => $ex->getMessage(), 'retry' => true]);
                }
                // au-delà de 2 Go sur PHP 32 bits, impossible de tronquer : on repart de zéro
                $release();
                foreach ($p as $tmp) {
                    @unlink($tmp);
                }
                out(['ok' => false, 'error' => $ex->getMessage() . ' — l\'envoi doit être recommencé']);
            }
            // SHA-256 (du clair) mis à jour avec ce morceau (abandonné en cas de décalage : recalcul complet à la fin)
            if (is_file($p['hash'])) {
                try {
                    $st = unserialize((string) file_get_contents($p['hash']), ['allowed_classes' => [HashContext::class]]);
                    if (is_array($st) && ($st['ctx'] ?? null) instanceof HashContext && num_eq($st['n'], $current)
                        && hash_update_file($st['ctx'], $up['tmp_name'])) {
                        file_put_contents($p['hash'], serialize(['n' => $current + $len, 'ctx' => $st['ctx']]), LOCK_EX);
                    } else {
                        @unlink($p['hash']);
                    }
                } catch (Throwable) {
                    @unlink($p['hash']);
                }
            }
            $meta['received'] = $current + $len;
            unset($meta['paths']);
            chunk_meta_save($p['meta'], $meta);
            $release();
            out(['ok' => true, 'offset' => $current + $len]);

        case 'status':
            $meta = chunk_meta((string) ($_POST['id'] ?? ''), $uid);
            $off = !empty($meta['enc']) ? num($meta['received'] ?? 0) : fsize($meta['paths']['part']);
            out(['ok' => true, 'offset' => $off, 'size' => num($meta['size'])]);

        case 'cancel':
            chunk_cancel((string) ($_POST['id'] ?? ''), $uid);
            out(['ok' => true]);
    }
    out(['ok' => false, 'error' => 'opération inconnue'], 400);
} catch (RuntimeException $ex) {
    out(['ok' => false, 'error' => $ex->getMessage()]);
}
