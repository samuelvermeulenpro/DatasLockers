<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

/*
 * Mon compte : chaque utilisateur connecté peut modifier son profil
 * (identifiant, e-mail), changer son mot de passe ou supprimer son compte.
 * Toute modification exige le mot de passe actuel.
 */

$me = require_role('member');
$U  = t('users');

$errors  = ['profile' => [], 'password' => [], 'delete' => []];
$form    = ['username' => $me['username'], 'email' => (string) ($me['email'] ?? '')];

/** Vérifie le mot de passe actuel de l'utilisateur connecté */
function account_check_password(int $id, string $pass): bool
{
    $hash = q('SELECT password_hash FROM ' . t('users') . ' WHERE id = ?', [$id])->fetchColumn();
    if (!is_string($hash) || !password_verify($pass, $hash)) {
        usleep(400000);
        return false;
    }
    return true;
}

/** Nombre d'administrateurs actifs autres que $id */
function other_active_admins(int $id): int
{
    return (int) q('SELECT COUNT(*) FROM ' . t('users') . " WHERE role = 'admin' AND active = 1 AND id <> ?", [$id])->fetchColumn();
}

$myId    = (int) $me['id'];
$isAdmin = $me['role'] === 'admin';
$lastAdmin = $isAdmin && other_active_admins($myId) === 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action  = (string) ($_POST['action'] ?? '');
    $current = (string) ($_POST['current_password'] ?? '');

    if ($action === 'profile') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $form     = ['username' => $username, 'email' => $email];
        $err      = &$errors['profile'];

        if (!preg_match('/^[\w.@-]{3,60}$/u', $username)) $err[] = 'Identifiant invalide (3 à 60 caractères : lettres, chiffres, . _ - @).';
        if ($email !== '' && (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190)) $err[] = 'E-mail invalide.';
        if (!$err && q("SELECT 1 FROM $U WHERE (username = ? OR (email IS NOT NULL AND email = ?)) AND id <> ?", [$username, $email ?: '#', $myId])->fetchColumn()) {
            $err[] = 'Identifiant ou e-mail déjà utilisé.';
        }
        if (!$err && !account_check_password($myId, $current)) {
            $err[] = 'Mot de passe actuel incorrect.';
        }
        if (!$err) {
            q("UPDATE $U SET username = ?, email = ? WHERE id = ?", [$username, $email ?: null, $myId]);
            flash('success', 'Profil mis à jour.');
            redirect('account.php');
        }
        unset($err);
    }

    if ($action === 'password') {
        $new     = (string) ($_POST['new_password'] ?? '');
        $confirm = (string) ($_POST['confirm_password'] ?? '');
        $err     = &$errors['password'];

        if (strlen($new) < 10) $err[] = 'Nouveau mot de passe : 10 caractères minimum.';
        if ($new !== $confirm) $err[] = 'La confirmation ne correspond pas au nouveau mot de passe.';
        if (!$err && !account_check_password($myId, $current)) {
            $err[] = 'Mot de passe actuel incorrect.';
        }
        if (!$err) {
            q("UPDATE $U SET password_hash = ? WHERE id = ?", [password_hash($new, PASSWORD_DEFAULT), $myId]);
            session_regenerate_id(true);
            flash('success', 'Mot de passe modifié.');
            redirect('account.php');
        }
        unset($err);
    }

    if ($action === 'delete') {
        $err = &$errors['delete'];
        if ($lastAdmin) {
            $err[] = 'Vous êtes le seul administrateur actif : nommez d\'abord un autre administrateur avant de supprimer votre compte.';
        }
        if (!isset($_POST['confirm_delete'])) {
            $err[] = 'Cochez la case de confirmation.';
        }
        if (!$err && !account_check_password($myId, $current)) {
            $err[] = 'Mot de passe incorrect.';
        }
        if (!$err) {
            $pdo = db();
            $pdo->beginTransaction();
            try {
                // le journal des téléchargements est conservé, mais anonymisé (RGPD)
                q('UPDATE ' . t('download_log') . ' SET user_id = NULL WHERE user_id = ?', [$myId]);
                // fichiers, versions et liens créés sont conservés (clés étrangères ON DELETE SET NULL)
                q("DELETE FROM $U WHERE id = ?", [$myId]);
                $pdo->commit();
            } catch (Throwable $ex) {
                $pdo->rollBack();
                throw $ex;
            }
            $_SESSION = [];
            session_regenerate_id(true);
            session_destroy();
            session_start();
            flash('success', 'Votre compte a été supprimé.');
            redirect('index.php');
        }
        unset($err);
    }
}

$info = q("SELECT created_at, last_login FROM $U WHERE id = ?", [$myId])->fetch() ?: [];

function account_errors(array $list): void
{
    foreach ($list as $msg) {
        echo '<div class="alert alert-error">' . e($msg) . '</div>';
    }
}

render_header('Mon compte', 'account');
?>
<div class="page-head">
  <div>
    <h1>Mon compte</h1>
    <p class="muted"><?= e(role_label($me['role'])) ?> · inscrit le <?= fr_date($info['created_at'] ?? null) ?> · dernière connexion <?= fr_date($info['last_login'] ?? null, true) ?></p>
  </div>
</div>

<div class="grid-2">
  <section class="card">
    <h3>Profil</h3>
    <?php account_errors($errors['profile']); ?>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="profile">
      <label>Identifiant<input name="username" value="<?= e($form['username']) ?>" required maxlength="60" autocomplete="username"></label>
      <label>E-mail <span class="muted small">(facultatif — sert aussi à se connecter et aux notifications)</span>
        <input type="email" name="email" value="<?= e($form['email']) ?>" maxlength="190" autocomplete="email"></label>
      <label>Mot de passe actuel<input type="password" name="current_password" required autocomplete="current-password"></label>
      <button class="btn btn-primary btn-block">Enregistrer le profil</button>
    </form>
  </section>

  <section class="card">
    <h3>Mot de passe</h3>
    <?php account_errors($errors['password']); ?>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="password">
      <input type="text" name="username" value="<?= e($me['username']) ?>" autocomplete="username" hidden>
      <label>Mot de passe actuel<input type="password" name="current_password" required autocomplete="current-password"></label>
      <label>Nouveau mot de passe <span class="muted small">(10 caractères minimum)</span>
        <input type="password" name="new_password" required minlength="10" autocomplete="new-password"></label>
      <label>Confirmer le nouveau mot de passe
        <input type="password" name="confirm_password" required minlength="10" autocomplete="new-password"></label>
      <button class="btn btn-primary btn-block">Changer le mot de passe</button>
    </form>
  </section>
</div>

<section class="card danger-zone">
  <h3>Supprimer mon compte</h3>
  <p class="small">La suppression est <strong>définitive</strong>. Votre compte est effacé et vos téléchargements
    passés ne sont plus rattachés à votre nom dans le journal.
    <?php if (has_role('editor')): ?>Les fichiers, versions et liens de partage que vous avez publiés sont conservés.<?php endif; ?></p>
  <?php account_errors($errors['delete']); ?>
  <?php if ($lastAdmin): ?>
    <div class="alert alert-warn">Vous êtes le seul administrateur actif : nommez d'abord un autre administrateur
      (<a href="<?= e(url('admin/users.php')) ?>">Utilisateurs</a>) pour pouvoir supprimer votre compte.</div>
  <?php else: ?>
  <form method="post" class="form" data-confirm="Supprimer définitivement votre compte ?">
    <?= csrf_field() ?><input type="hidden" name="action" value="delete">
    <input type="text" name="username" value="<?= e($me['username']) ?>" autocomplete="username" hidden>
    <label>Mot de passe<input type="password" name="current_password" required autocomplete="current-password"></label>
    <label class="check"><input type="checkbox" name="confirm_delete" value="1" required> Je comprends que cette action est irréversible.</label>
    <div><button class="btn btn-danger">Supprimer mon compte</button></div>
  </form>
  <?php endif; ?>
</section>
<?php render_footer();
