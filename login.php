<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

if (current_user()) {
    redirect('index.php');
}

$error = '';
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    q('DELETE FROM ' . t('login_attempts') . ' WHERE created_at < (NOW() - INTERVAL 1 DAY)');
    $recent = (int) q('SELECT COUNT(*) FROM ' . t('login_attempts') . ' WHERE ip = ? AND created_at > (NOW() - INTERVAL 15 MINUTE)', [client_ip()])->fetchColumn();

    if ($recent >= (int) cfg('login_max_attempts', 5)) {
        $error = 'Trop de tentatives. Réessayez dans 15 minutes.';
    } else {
        $u = q('SELECT * FROM ' . t('users') . ' WHERE username = ? OR email = ?', [$username, $username])->fetch();
        if ($u && $u['active'] && password_verify($password, $u['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['uid'] = (int) $u['id'];
            if (password_needs_rehash($u['password_hash'], PASSWORD_DEFAULT)) {
                q('UPDATE ' . t('users') . ' SET password_hash = ? WHERE id = ?', [password_hash($password, PASSWORD_DEFAULT), $u['id']]);
            }
            q('UPDATE ' . t('users') . ' SET last_login = NOW() WHERE id = ?', [$u['id']]);
            q('DELETE FROM ' . t('login_attempts') . ' WHERE ip = ?', [client_ip()]);
            $to = $_SESSION['after_login'] ?? null;
            unset($_SESSION['after_login']);
            // redirection interne uniquement
            if (is_string($to) && str_starts_with($to, '/') && !str_starts_with($to, '//')) {
                header('Location: ' . $to);
                exit;
            }
            redirect(in_array($u['role'], ['admin', 'editor'], true) ? 'admin/index.php' : 'index.php');
        }
        q('INSERT INTO ' . t('login_attempts') . ' (ip) VALUES (?)', [client_ip()]);
        usleep(400000);
        $error = 'Identifiant ou mot de passe incorrect.';
    }
}

render_header('Connexion');
?>
<div class="auth-box card">
  <img src="<?= e(url('assets/logo.png')) ?>" alt="SV Pro" class="auth-logo" width="96" height="96">
  <h1>Connexion</h1>
  <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
  <form method="post" class="form">
    <?= csrf_field() ?>
    <label>Identifiant ou e-mail
      <input name="username" value="<?= e($username) ?>" required autofocus autocomplete="username">
    </label>
    <label>Mot de passe
      <input type="password" name="password" required autocomplete="current-password">
    </label>
    <button class="btn btn-primary btn-block">Se connecter</button>
  </form>
  <p class="muted small center"><a href="<?= e(url()) ?>">← Retour aux téléchargements</a></p>
</div>
<?php render_footer();
