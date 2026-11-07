<?php
declare(strict_types=1);
/**
 * SV Pro Downloads — installeur
 * Crée config.php, les tables et le premier administrateur.
 * À SUPPRIMER après installation.
 */

if (PHP_VERSION_ID < 80100) {
    exit('PHP 8.1 ou supérieur requis (version actuelle : ' . PHP_VERSION . ').');
}

$root = __DIR__;
$h = fn(?string $s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');

if (is_file("$root/config.php")) {
    http_response_code(403);
    exit('Déjà installé : config.php existe. Supprimez install.php du serveur.');
}

$checks = [
    'PHP ≥ 8.1'                       => PHP_VERSION_ID >= 80100,
    'Extension pdo_mysql'              => extension_loaded('pdo_mysql'),
    'Extension fileinfo'               => extension_loaded('fileinfo'),
    'Extension mbstring'               => extension_loaded('mbstring'),
    'Dossier racine accessible en écriture (config.php)' => is_writable($root),
    'Dossier install/ accessible en écriture (jeton)'   => is_writable("$root/install"),
];

/*
 * Jeton anti-rejeu conservé dans un fichier (et non en session) :
 * l'installation fonctionne même si les sessions PHP du serveur ne sont pas
 * enregistrables (session.save_path non accessible au pool PHP-FPM, ex. YunoHost).
 */
$tokFile = "$root/install/.install_token";
$token = is_file($tokFile) ? trim((string) file_get_contents($tokFile)) : '';
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    $token = bin2hex(random_bytes(16));
    if (@file_put_contents($tokFile, $token, LOCK_EX) === false) {
        $token = '';
    }
}

// Diagnostic des sessions PHP (information : l'application utilisera storage/sessions)
$sessDir = session_save_path();
$sessDir = $sessDir !== '' ? substr($sessDir, (int) strrpos($sessDir, ';') + ((str_contains($sessDir, ';')) ? 1 : 0)) : sys_get_temp_dir();
$sessOk  = is_dir($sessDir) && is_writable($sessDir);

$v = [
    'app_name' => 'SV Pro Downloads', 'base_url' => rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/'),
    'db_host' => 'localhost', 'db_port' => '3306', 'db_name' => 'svpro_downloads', 'db_user' => '', 'db_pass' => '', 'db_prefix' => 'dl_',
    'storage' => $root . '/storage', 'admin_user' => 'admin', 'admin_email' => '', 'demo' => '1',
];
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($token === '' || !hash_equals($token, (string) ($_POST['_csrf'] ?? ''))) {
        http_response_code(400);
        exit('Jeton invalide : rechargez la page install.php (sans renvoyer le formulaire) puis recommencez. '
           . 'Si le problème persiste, vérifiez que le dossier install/ est accessible en écriture par PHP.');
    }
    foreach ($v as $k => $_) {
        $v[$k] = trim((string) ($_POST[$k] ?? ''));
    }
    $v['db_pass'] = (string) ($_POST['db_pass'] ?? '');
    $v['demo'] = isset($_POST['demo']) ? '1' : '';
    $pass  = (string) ($_POST['admin_pass'] ?? '');
    $pass2 = (string) ($_POST['admin_pass2'] ?? '');

    if (!preg_match('/^[a-z0-9_]{0,20}$/i', $v['db_prefix'])) $errors[] = 'Préfixe de table invalide (lettres, chiffres, _).';
    if (!preg_match('/^[\w.@-]{3,60}$/u', $v['admin_user']))   $errors[] = 'Identifiant administrateur invalide (3 à 60 caractères).';
    if (strlen($pass) < 10)                                     $errors[] = 'Mot de passe administrateur : 10 caractères minimum.';
    if ($pass !== $pass2)                                       $errors[] = 'Les deux mots de passe ne correspondent pas.';
    if ($v['admin_email'] !== '' && !filter_var($v['admin_email'], FILTER_VALIDATE_EMAIL)) $errors[] = 'E-mail invalide.';
    if ($v['base_url'] !== '' && !preg_match('#^(/[\w.~-]+)+$#', $v['base_url'])) $errors[] = 'Sous-dossier invalide (ex. /downloads, ou vide).';

    $storage = rtrim($v['storage'], '/\\');
    if (!is_dir($storage) && !@mkdir($storage, 0750, true)) {
        $errors[] = 'Impossible de créer le dossier de stockage : ' . $storage;
    } elseif (!is_writable($storage)) {
        $errors[] = 'Dossier de stockage non accessible en écriture : ' . $storage;
    }

    if (!$errors) {
        try {
            $pdo = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $v['db_host'], (int) $v['db_port'], $v['db_name']),
                $v['db_user'], $v['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        } catch (PDOException $ex) {
            $errors[] = 'Connexion MySQL impossible : ' . $ex->getMessage();
        }
    }

    if (!$errors) {
        try {
            $p   = $v['db_prefix'];
            $sql = str_replace('{p}', $p, file_get_contents("$root/install/schema.sql"));
            $sql = preg_replace('/^--.*$/m', '', $sql);
            foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
                $pdo->exec($stmt);
            }
            $pdo->prepare("INSERT INTO {$p}users (username, email, password_hash, role) VALUES (?,?,?, 'admin')")
                ->execute([$v['admin_user'], $v['admin_email'] ?: null, password_hash($pass, PASSWORD_DEFAULT)]);

            if ($v['demo']) {
                $ins = $pdo->prepare("INSERT INTO {$p}categories (parent_id, name, position) VALUES (?,?,?)");
                $pos = 0;
                foreach (['Logiciels' => ['Windows', 'Linux', 'Android'], 'Documentation' => ['Guides', 'Procédures'], 'Clients' => []] as $name => $kids) {
                    $ins->execute([null, $name, $pos++]);
                    $pid = (int) $pdo->lastInsertId();
                    foreach ($kids as $j => $k) {
                        $ins->execute([$pid, $k, $j]);
                    }
                }
            }

            $sessPath = $storage . '/sessions';
            if (!is_dir($sessPath)) {
                @mkdir($sessPath, 0700, true);
            }
            $cfg = [
                'app_name' => $v['app_name'] ?: 'SV Pro Downloads',
                'base_url' => $v['base_url'],
                'db' => ['host' => $v['db_host'], 'port' => (int) $v['db_port'], 'name' => $v['db_name'],
                         'user' => $v['db_user'], 'pass' => $v['db_pass'], 'prefix' => $p],
                'storage_path' => $storage,
                'session_path' => is_dir($sessPath) && is_writable($sessPath) ? $sessPath : '',
            ];
            $sample = require "$root/config.sample.php";
            $final  = array_replace_recursive($sample, $cfg);
            $php = "<?php\n// Généré par install.php le " . date('d/m/Y H:i') . "\nreturn " . var_export($final, true) . ";\n";
            if (file_put_contents("$root/config.php", $php, LOCK_EX) === false) {
                throw new RuntimeException('Écriture de config.php impossible.');
            }
            @chmod("$root/config.php", 0640);
            if (!is_file("$storage/.htaccess")) {
                @file_put_contents("$storage/.htaccess", "Require all denied\n");
            }
            @unlink($tokFile);
            $done = true;
        } catch (Throwable $ex) {
            $errors[] = 'Erreur pendant l\'installation : ' . $ex->getMessage();
        }
    }
}
?><!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Installation — SV Pro Downloads</title>
<link rel="icon" href="assets/favicon.png">
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="topbar"><div class="wrap topbar-inner">
  <span class="brand"><img src="assets/logo.png" alt="" width="48" height="48">
  <span class="brand-text"><strong>SV Pro Downloads</strong><small>Installation</small></span></span>
</div></header>
<main class="wrap main narrow">
<?php if (!empty($done)): ?>
  <div class="card">
    <h1>Installation terminée ✔</h1>
    <p>Le gestionnaire est prêt. Pensez à :</p>
    <ul class="checklist">
      <li><strong>supprimer <code>install.php</code></strong> du serveur ;</li>
      <li>vérifier que <code>storage/</code> n'est pas accessible depuis le web (ou le déplacer hors de la racine, puis ajuster <code>storage_path</code> dans <code>config.php</code>) ;</li>
      <li>ajuster <code>upload_max_filesize</code> et <code>post_max_size</code> dans php.ini.</li>
    </ul>
    <p><a class="btn btn-primary" href="login.php">Se connecter</a></p>
  </div>
<?php else: ?>
  <h1>Installation</h1>
  <div class="card">
    <h3>Prérequis</h3>
    <ul class="checks">
      <?php foreach ($checks as $label => $ok): ?>
        <li class="<?= $ok ? 'ok' : 'ko' ?>"><?= $ok ? '✔' : '✖' ?> <?= $h($label) ?></li>
      <?php endforeach; ?>
      <li class="<?= $sessOk ? 'ok' : 'ko' ?>"><?= $sessOk ? '✔' : 'ℹ' ?> Sessions PHP (<?= $h($sessDir) ?>)<?= $sessOk ? '' : ' non inscriptible — l\'application utilisera storage/sessions' ?></li>
    </ul>
  </div>
  <?php foreach ($errors as $err): ?><div class="alert alert-error"><?= $h($err) ?></div><?php endforeach; ?>
  <form method="post" class="card form">
    <input type="hidden" name="_csrf" value="<?= $h($token) ?>">
    <h3>Application</h3>
    <div class="grid-2">
      <label>Nom<input name="app_name" value="<?= $h($v['app_name']) ?>"></label>
      <label>Sous-dossier (vide si racine)<input name="base_url" value="<?= $h($v['base_url']) ?>" placeholder="/downloads"></label>
    </div>
    <label>Dossier de stockage (idéalement hors racine web)<input name="storage" value="<?= $h($v['storage']) ?>"></label>

    <h3>Base MySQL / MariaDB</h3>
    <div class="grid-2">
      <label>Hôte<input name="db_host" value="<?= $h($v['db_host']) ?>" required></label>
      <label>Port<input name="db_port" value="<?= $h($v['db_port']) ?>" required></label>
      <label>Base<input name="db_name" value="<?= $h($v['db_name']) ?>" required></label>
      <label>Préfixe des tables<input name="db_prefix" value="<?= $h($v['db_prefix']) ?>"></label>
      <label>Utilisateur<input name="db_user" value="<?= $h($v['db_user']) ?>" required autocomplete="off"></label>
      <label>Mot de passe<input type="password" name="db_pass" autocomplete="new-password"></label>
    </div>

    <h3>Administrateur</h3>
    <div class="grid-2">
      <label>Identifiant<input name="admin_user" value="<?= $h($v['admin_user']) ?>" required></label>
      <label>E-mail<input type="email" name="admin_email" value="<?= $h($v['admin_email']) ?>"></label>
      <label>Mot de passe (10 car. min.)<input type="password" name="admin_pass" required minlength="10" autocomplete="new-password"></label>
      <label>Confirmation<input type="password" name="admin_pass2" required minlength="10" autocomplete="new-password"></label>
    </div>
    <label class="check"><input type="checkbox" name="demo" value="1"<?= $v['demo'] ? ' checked' : '' ?>> Créer quelques catégories d'exemple (structures › services)</label>
    <button class="btn btn-primary btn-lg"<?= in_array(false, $checks, true) ? ' disabled' : '' ?>>Installer</button>
  </form>
<?php endif; ?>
</main>
</body>
</html>
