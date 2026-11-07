<?php
declare(strict_types=1);

/**
 * Envoi d'e-mails sans dépendance : fonction mail() de PHP (sendmail / Postfix local)
 * ou SMTP direct (STARTTLS, SSL/TLS, authentification PLAIN / LOGIN).
 */

function mail_from(): array
{
    $host = parse_url(site_base_url(), PHP_URL_HOST) ?: 'localhost';
    $email = trim((string) setting('mail_from', ''));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $email = 'noreply@' . preg_replace('/^www\./', '', $host);
    }
    $name = trim((string) setting('mail_from_name', '')) ?: (string) cfg('app_name', 'SV Pro Downloads');
    return [$email, $name];
}

function mime_header(string $s): string
{
    return preg_match('/[^\x20-\x7E]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
}

/** Construit en-têtes + corps MIME (texte + HTML) */
function mail_build(string $to, string $subject, string $html, string $text): array
{
    [$fromEmail, $fromName] = mail_from();
    $boundary = 'svpro_' . bin2hex(random_bytes(12));
    $domain = substr(strrchr($fromEmail, '@'), 1) ?: 'localhost';
    $headers = [
        'Date: ' . date('r'),
        'From: ' . mime_header($fromName) . ' <' . $fromEmail . '>',
        'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $domain . '>',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'X-Mailer: SV Pro Downloads ' . APP_VERSION,
        'Auto-Submitted: auto-generated',
    ];
    $body = "--$boundary\r\n"
        . "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($text), 76, "\r\n")
        . "--$boundary\r\n"
        . "Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($html), 76, "\r\n")
        . "--$boundary--\r\n";
    return [$headers, $body, $fromEmail];
}

/**
 * Envoie un message à une liste de destinataires (chacun reçoit un message individuel
 * ou, en SMTP, une copie cachée : les adresses ne sont jamais exposées entre elles).
 * Lève une RuntimeException en cas d'échec.
 */
function send_mail(array $recipients, string $subject, string $html, string $text): void
{
    $recipients = array_values(array_unique(array_filter($recipients, fn($r) => filter_var($r, FILTER_VALIDATE_EMAIL))));
    if (!$recipients) {
        throw new RuntimeException('aucun destinataire valide');
    }
    try {
        if (setting('mail_transport', 'mail') === 'smtp') {
            [$headers, $body, $from] = mail_build('', $subject, $html, $text);
            $data = implode("\r\n", array_merge(
                ['To: undisclosed-recipients:;', 'Subject: ' . mime_header($subject)], $headers)) . "\r\n\r\n" . $body;
            smtp_send($from, $recipients, $data);
        } else {
            foreach ($recipients as $r) {
                [$headers, $body, $from] = mail_build($r, $subject, $html, $text);
                if (!@mail($r, mime_header($subject), $body, implode("\r\n", $headers), '-f' . $from)) {
                    $err = error_get_last()['message'] ?? 'mail() a renvoyé false (sendmail/Postfix absent ou refus)';
                    throw new RuntimeException($err);
                }
            }
        }
        setting_set('mail_last_ok', date('Y-m-d H:i:s'));
        setting_set('mail_last_error', '');
    } catch (Throwable $ex) {
        setting_set('mail_last_error', date('Y-m-d H:i:s') . ' — ' . $ex->getMessage());
        throw $ex instanceof RuntimeException ? $ex : new RuntimeException($ex->getMessage(), 0, $ex);
    }
}

function smtp_send(string $from, array $rcpts, string $data): void
{
    $host   = trim((string) setting('smtp_host', 'localhost'));
    $port   = (int) setting('smtp_port', 587);
    $secure = (string) setting('smtp_secure', 'starttls');
    $user   = (string) setting('smtp_user', '');
    $pass   = (string) setting('smtp_pass', '');
    $verify = !setting('smtp_insecure', false);

    $ctx = stream_context_create(['ssl' => [
        'verify_peer' => $verify, 'verify_peer_name' => $verify, 'allow_self_signed' => !$verify,
        'peer_name' => $host, 'SNI_enabled' => true,
    ]]);
    $fp = @stream_socket_client(($secure === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) {
        throw new RuntimeException("connexion SMTP impossible à $host:$port ($errstr)");
    }
    stream_set_timeout($fp, 30);

    $read = function () use ($fp): string {
        $resp = '';
        while (($line = fgets($fp, 2048)) !== false) {
            $resp .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }
        return $resp;
    };
    $cmd = function (?string $c, array $ok, string $label = '') use ($fp, $read): string {
        if ($c !== null) {
            fwrite($fp, $c . "\r\n");
        }
        $r = $read();
        if (!in_array((int) substr($r, 0, 3), $ok, true)) {
            throw new RuntimeException('SMTP ' . ($label ?: strtok((string) $c, ' ')) . ' : ' . trim($r ?: 'pas de réponse'));
        }
        return $r;
    };

    try {
        $cmd(null, [220], 'accueil');
        $me = preg_replace('/[^a-z0-9.-]/i', '', (string) (parse_url(site_base_url(), PHP_URL_HOST) ?: gethostname() ?: 'localhost'));
        $ehlo = $cmd('EHLO ' . $me, [250]);
        if ($secure === 'starttls') {
            $cmd('STARTTLS', [220]);
            $method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0);
            if (!@stream_socket_enable_crypto($fp, true, $method)) {
                throw new RuntimeException('échec de la négociation TLS (certificat ?)');
            }
            $ehlo = $cmd('EHLO ' . $me, [250]);
        }
        if ($user !== '') {
            if (preg_match('/AUTH[ =][^\r\n]*PLAIN/i', $ehlo)) {
                $cmd('AUTH PLAIN ' . base64_encode("\0" . $user . "\0" . $pass), [235], 'authentification');
            } else {
                $cmd('AUTH LOGIN', [334], 'authentification');
                $cmd(base64_encode($user), [334], 'authentification');
                $cmd(base64_encode($pass), [235], 'authentification');
            }
        }
        $cmd('MAIL FROM:<' . $from . '>', [250]);
        foreach ($rcpts as $r) {
            $cmd('RCPT TO:<' . $r . '>', [250, 251], 'destinataire ' . $r);
        }
        $cmd('DATA', [354]);
        $data = preg_replace('/^\./m', '..', str_replace(["\r\n", "\n"], ["\n", "\r\n"], $data));
        fwrite($fp, rtrim($data, "\r\n") . "\r\n.\r\n");
        $cmd(null, [250], 'envoi');
        @fwrite($fp, "QUIT\r\n");
    } finally {
        fclose($fp);
    }
}

/* ---------- Notifications ---------- */

function notify_enabled(string $event): bool
{
    return (bool) setting('notify_enabled', false) && (bool) (setting('notify_events', [])[$event] ?? true);
}

/** Adresses saisies librement dans les réglages */
function notify_extra(): array
{
    return array_values(array_filter(
        preg_split('/[\s,;]+/', (string) setting('notify_to', ''), -1, PREG_SPLIT_NO_EMPTY),
        fn($a) => filter_var($a, FILTER_VALIDATE_EMAIL)
    ));
}

/** Comptes destinataires (actifs, avec e-mail) ayant au moins le rôle donné */
function notify_accounts(string $minRole, ?int $excludeUser): array
{
    $roles = array_keys(array_filter(ROLE_LEVEL, fn($l) => $l >= ROLE_LEVEL[$minRole]));
    $in = implode(',', array_fill(0, count($roles), '?'));
    $rows = q('SELECT id, email FROM ' . t('users') . " WHERE active = 1 AND email IS NOT NULL AND email <> '' AND role IN ($in)", $roles)->fetchAll();
    return array_values(array_map(fn($r) => $r['email'], array_filter($rows, fn($r) => (int) $r['id'] !== $excludeUser)));
}

/** Gabarit HTML des e-mails, aux couleurs SV Pro */
function mail_layout(string $title, string $inner): string
{
    $app = e((string) cfg('app_name', 'SV Pro Downloads'));
    $base = e(site_base_url());
    return '<!doctype html><html lang="fr"><body style="margin:0;background:#f3f6f9;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1b2a38">'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f6f9;padding:24px 0"><tr><td align="center">'
        . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#fff;border:1px solid #dde4ea;border-radius:8px;overflow:hidden">'
        . '<tr><td style="padding:16px 20px;border-bottom:3px solid #5bb8e8"><a href="' . $base . '/" style="text-decoration:none;color:#0c3c65;font-weight:700;font-size:18px">' . $app . '</a>'
        . '<div style="font-size:12px;color:#667584">Samuel Vermeulen — Consultant Informatique &amp; Internet</div></td></tr>'
        . '<tr><td style="padding:20px"><h1 style="margin:0 0 14px;font-size:20px;color:#0c3c65">' . e($title) . '</h1>' . $inner . '</td></tr>'
        . '<tr><td style="padding:14px 20px;background:#f3f6f9;font-size:12px;color:#667584;text-align:center">Message automatique envoyé par ' . $app
        . ' — <a href="' . $base . '/" style="color:#0c3c65">' . e(parse_url(site_base_url(), PHP_URL_HOST) ?: '') . '</a></td></tr>'
        . '</table></td></tr></table></body></html>';
}

/**
 * Notifie l'arrivée de nouveaux fichiers / nouvelles versions et les sommes non conformes.
 * $items : [['file' => row, 'type' => 'new'|'version']] ; $mismatch : ids de fichiers non conformes.
 * Appelé après la réponse HTTP (voir defer_after_response).
 */
function notify_files(array $items, array $mismatch, ?int $uploaderId): void
{
    $items = array_values(array_filter($items, fn($it) => notify_enabled($it['type'])));
    $roleSetting = (string) setting('notify_roles', 'none');
    $extra = notify_extra();

    if ($items) {
        // Destinataires et fichiers qu'ils peuvent voir (les membres ne sont pas avertis des fichiers masqués)
        $groups = [];
        $addGroup = function (array $emails, array $its) use (&$groups) {
            if (!$emails || !$its) {
                return;
            }
            $key = implode(',', array_map(fn($i) => $i['file']['id'] . $i['type'], $its));
            $groups[$key]['items'] = $its;
            $groups[$key]['to'] = array_merge($groups[$key]['to'] ?? [], $emails);
        };
        $addGroup($extra, $items);
        if ($roleSetting !== 'none') {
            $editors = notify_accounts($roleSetting === 'member' ? 'editor' : $roleSetting, $uploaderId);
            $addGroup($editors, $items);
            if ($roleSetting === 'member') {
                $members = array_diff(notify_accounts('member', $uploaderId), $editors);
                $addGroup(array_values($members), array_values(array_filter($items, fn($i) => $i['file']['visibility'] !== 'hidden')));
            }
        }
        $summary = integrity_summary(array_map(fn($i) => $i['file']['id'], $items));
        foreach ($groups as $g) {
            [$subject, $html, $text] = notify_message($g['items'], $summary);
            try {
                send_mail(array_unique($g['to']), $subject, $html, $text);
            } catch (Throwable $ex) {
                error_log('[svpro-downloads] notification : ' . $ex->getMessage());
            }
        }
    }

    $mismatch = array_values(array_unique(array_filter($mismatch)));
    if ($mismatch && notify_enabled('mismatch')) {
        $to = $extra;
        if ($roleSetting !== 'none') {
            $to = array_merge($to, notify_accounts('editor', null));
        }
        $files = array_filter(array_map('file_row', $mismatch));
        if ($to && $files) {
            $rows = '';
            $txt = '';
            foreach ($files as $f) {
                $link = site_base_url() . '/file.php?id=' . $f['id'];
                $rows .= '<li style="margin-bottom:6px"><a href="' . e($link) . '" style="color:#b91c1c;font-weight:600">' . e($f['title']) . '</a> <span style="color:#667584">(' . e($f['original_name']) . ')</span></li>';
                $txt .= '- ' . $f['title'] . ' (' . $f['original_name'] . ") : $link\n";
            }
            $title = count($files) > 1 ? count($files) . ' fichiers ne correspondent pas à leur somme de contrôle' : 'Somme de contrôle non conforme';
            $html = mail_layout($title, '<p>La vérification automatique a détecté une empreinte différente de celle annoncée par le fichier de sommes :</p><ul>' . $rows . '</ul>'
                . '<p style="color:#667584;font-size:13px">Le fichier a peut-être été altéré pendant l\'envoi, ou le fichier de sommes concerne une autre version.</p>');
            try {
                send_mail(array_unique($to), '⚠ ' . $title, $html, $title . "\n\n" . $txt);
            } catch (Throwable $ex) {
                error_log('[svpro-downloads] alerte intégrité : ' . $ex->getMessage());
            }
        }
    }
}

/** Sujet, HTML et texte d'une notification d'envoi */
function notify_message(array $items, array $summary): array
{
    $n = count($items);
    $first = $items[0];
    $subject = $n === 1
        ? ($first['type'] === 'version' ? 'Nouvelle version : ' : 'Nouveau fichier : ') . $first['file']['title']
            . ($first['file']['version'] ? ' (v' . $first['file']['version'] . ')' : '')
        : $n . ' nouveaux fichiers disponibles';

    $rows = '';
    $text = $subject . "\n\n";
    foreach ($items as $it) {
        $f = $it['file'];
        $link = site_base_url() . '/file.php?id=' . $f['id'];
        $cat = $f['category_id'] ? q('SELECT CONCAT(COALESCE(CONCAT(p.name, \' › \'), \'\'), c.name) FROM ' . t('categories') . ' c LEFT JOIN ' . t('categories') . ' p ON p.id = c.parent_id WHERE c.id = ?', [$f['category_id']])->fetchColumn() : '';
        $state = $summary[$f['id']] ?? null;
        $badge = $state === 'ok' ? ' <span style="color:#15803d">✔ somme vérifiée</span>' : ($state === 'mismatch' ? ' <span style="color:#b91c1c;font-weight:700">✖ somme invalide</span>' : '');
        $rows .= '<tr><td style="padding:10px 0;border-bottom:1px solid #dde4ea">'
            . '<a href="' . e($link) . '" style="color:#0c3c65;font-weight:600;font-size:15px;text-decoration:none">' . e($f['title']) . '</a>'
            . ($f['version'] ? ' <span style="font-size:12px;color:#667584;border:1px solid #dde4ea;border-radius:4px;padding:0 4px">v' . e($f['version']) . '</span>' : '')
            . ($it['type'] === 'version' ? ' <span style="font-size:12px;background:#5bb8e8;color:#fff;border-radius:999px;padding:1px 7px">nouvelle version</span>' : '')
            . '<div style="font-size:13px;color:#667584">' . e($f['original_name']) . ' · ' . e(human_size(num($f['size'])))
            . ($cat ? ' · ' . e($cat) : '') . ' · ' . e(visibility_label($f['visibility'])) . $badge . '</div>'
            . (!empty($f['version_notes']) ? '<div style="font-size:13px;margin-top:6px;white-space:pre-line">' . e(mb_strimwidth($f['version_notes'], 0, 600, '…')) . '</div>' : '')
            . '</td></tr>';
        $text .= '- ' . $f['title'] . ($f['version'] ? ' v' . $f['version'] : '') . ' (' . $f['original_name'] . ', ' . human_size(num($f['size'])) . ")\n  $link\n";
    }
    $btn = $n === 1
        ? '<p style="margin:18px 0 0"><a href="' . e(site_base_url() . '/file.php?id=' . $first['file']['id']) . '" style="display:inline-block;background:#0c3c65;color:#fff;padding:9px 18px;border-radius:6px;text-decoration:none">Voir le fichier</a></p>'
        : '<p style="margin:18px 0 0"><a href="' . e(site_base_url() . '/') . '" style="display:inline-block;background:#0c3c65;color:#fff;padding:9px 18px;border-radius:6px;text-decoration:none">Voir les téléchargements</a></p>';
    $html = mail_layout($subject, '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">' . $rows . '</table>' . $btn);
    return [$subject, $html, $text];
}
