<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
$me = require_role('admin');

$U = t('users');
$errors = [];
$editId = (int) ($_GET['edit'] ?? 0);
$edit = $editId ? q("SELECT * FROM $U WHERE id = ?", [$editId])->fetch() : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    $id = (int) ($_POST['id'] ?? 0);

    if ($action === 'save') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $role     = in_array($_POST['role'] ?? '', ['admin', 'editor', 'member'], true) ? $_POST['role'] : 'member';
        $active   = isset($_POST['active']) ? 1 : 0;
        $pass     = (string) ($_POST['password'] ?? '');

        if (!preg_match('/^[\w.@-]{3,60}$/u', $username)) $errors[] = 'Identifiant invalide (3 à 60 caractères : lettres, chiffres, . _ - @).';
        if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'E-mail invalide.';
        if (!$id && strlen($pass) < 10) $errors[] = 'Mot de passe : 10 caractères minimum.';
        if ($id && $pass !== '' && strlen($pass) < 10) $errors[] = 'Nouveau mot de passe : 10 caractères minimum.';
        if (q("SELECT 1 FROM $U WHERE (username = ? OR (email IS NOT NULL AND email = ?)) AND id <> ?", [$username, $email ?: '#', $id])->fetchColumn()) {
            $errors[] = 'Identifiant ou e-mail déjà utilisé.';
        }
        if ($id === (int) $me['id'] && ($role !== 'admin' || !$active)) {
            $errors[] = 'Vous ne pouvez pas retirer vos propres droits d\'administrateur ni désactiver votre compte.';
        }

        if (!$errors) {
            if ($id) {
                q("UPDATE $U SET username=?, email=?, role=?, active=? WHERE id=?", [$username, $email ?: null, $role, $active, $id]);
                if ($pass !== '') {
                    q("UPDATE $U SET password_hash=? WHERE id=?", [password_hash($pass, PASSWORD_DEFAULT), $id]);
                }
                flash('success', 'Utilisateur « ' . e($username) . ' » mis à jour.');
            } else {
                q("INSERT INTO $U (username, email, password_hash, role, active) VALUES (?,?,?,?,?)",
                    [$username, $email ?: null, password_hash($pass, PASSWORD_DEFAULT), $role, $active]);
                flash('success', 'Utilisateur « ' . e($username) . ' » créé.');
            }
            redirect('admin/users.php');
        }
        $edit = ['id' => $id, 'username' => $username, 'email' => $email, 'role' => $role, 'active' => $active];
    }

    if ($action === 'delete') {
        if ($id === (int) $me['id']) {
            flash('error', 'Impossible de supprimer votre propre compte.');
        } else {
            q("DELETE FROM $U WHERE id = ?", [$id]);
            flash('success', 'Utilisateur supprimé (ses fichiers sont conservés).');
        }
        redirect('admin/users.php');
    }
}

$users = q("SELECT u.*, (SELECT COUNT(*) FROM " . t('files') . " f WHERE f.uploaded_by = u.id) nfiles FROM $U u ORDER BY u.role = 'admin' DESC, u.username")->fetchAll();
$e = $edit ?? ['id' => 0, 'username' => '', 'email' => '', 'role' => 'member', 'active' => 1];

render_header('Utilisateurs', 'users');
?>
<div class="page-head">
  <div><h1>Utilisateurs</h1>
  <p class="muted"><strong>Membre</strong> : accès aux fichiers réservés · <strong>Éditeur</strong> : gère fichiers, catégories et liens · <strong>Administrateur</strong> : tout, y compris les comptes</p></div>
</div>

<div class="layout-side reverse">
  <section class="card table-card">
    <table class="table">
      <thead><tr><th>Utilisateur</th><th>Rôle</th><th class="hide-sm">Dernière connexion</th><th class="num hide-sm">Fichiers</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($users as $u): ?>
        <tr<?= $u['active'] ? '' : ' class="dim"' ?>>
          <td><div class="file-cell"><span class="avatar"><?= e(mb_strtoupper(mb_substr($u['username'], 0, 1))) ?></span>
            <div><strong><?= e($u['username']) ?></strong><?= $u['active'] ? '' : ' <span class="badge badge-hidden">désactivé</span>' ?><div class="muted small"><?= e($u['email'] ?? '') ?></div></div></div></td>
          <td><span class="badge badge-role-<?= e($u['role']) ?>"><?= e(role_label($u['role'])) ?></span></td>
          <td class="hide-sm"><?= fr_date($u['last_login'], true) ?></td>
          <td class="num hide-sm"><?= (int) $u['nfiles'] ?></td>
          <td class="actions nowrap">
            <a class="btn btn-ghost btn-sm" href="?edit=<?= $u['id'] ?>">Modifier</a>
            <?php if ((int) $u['id'] !== (int) $me['id']): ?>
            <form method="post" class="inline" data-confirm="Supprimer le compte « <?= e($u['username']) ?> » ?"><?= csrf_field() ?><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $u['id'] ?>"><button class="icon-btn danger" title="Supprimer">✕</button></form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </section>

  <aside class="card">
    <h3><?= $e['id'] ? 'Modifier « ' . e($e['username']) . ' »' : 'Nouvel utilisateur' ?></h3>
    <?php foreach ($errors as $err): ?><div class="alert alert-error"><?= e($err) ?></div><?php endforeach; ?>
    <form method="post" class="form">
      <?= csrf_field() ?><input type="hidden" name="action" value="save"><input type="hidden" name="id" value="<?= (int) $e['id'] ?>">
      <label>Identifiant<input name="username" value="<?= e($e['username']) ?>" required maxlength="60" autocomplete="off"></label>
      <label>E-mail<input type="email" name="email" value="<?= e($e['email'] ?? '') ?>"></label>
      <label>Rôle
        <select name="role">
          <?php foreach (['member', 'editor', 'admin'] as $r): ?><option value="<?= $r ?>"<?= $e['role'] === $r ? ' selected' : '' ?>><?= role_label($r) ?></option><?php endforeach; ?>
        </select>
      </label>
      <label><?= $e['id'] ? 'Nouveau mot de passe <span class="muted small">(vide = inchangé)</span>' : 'Mot de passe' ?>
        <input type="password" name="password" minlength="10" autocomplete="new-password"<?= $e['id'] ? '' : ' required' ?>>
      </label>
      <label class="check"><input type="checkbox" name="active" value="1"<?= $e['active'] ? ' checked' : '' ?>> Compte actif</label>
      <button class="btn btn-primary btn-block"><?= $e['id'] ? 'Enregistrer' : 'Créer' ?></button>
      <?php if ($e['id']): ?><a class="btn btn-ghost btn-block" href="?">Annuler</a><?php endif; ?>
    </form>
  </aside>
</div>
<?php render_footer();
