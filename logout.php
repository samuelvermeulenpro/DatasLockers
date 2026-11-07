<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

// Jeton requis pour éviter une déconnexion forcée par lien externe
if (hash_equals(csrf_token(), (string) ($_GET['t'] ?? ''))) {
    $_SESSION = [];
    session_regenerate_id(true);
    session_destroy();
    session_start();
    flash('success', 'Vous êtes déconnecté.');
}
redirect('index.php');
