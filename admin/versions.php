<?php
declare(strict_types=1);
require dirname(__DIR__) . '/inc/bootstrap.php';
require_role('editor');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('admin/files.php');
}
csrf_check();

$ver = q('SELECT * FROM ' . t('file_versions') . ' WHERE id = ?', [(int) ($_POST['id'] ?? 0)])->fetch();
if (!$ver) {
    flash('error', 'Version introuvable.');
    redirect('admin/files.php');
}
$f = file_row((int) $ver['file_id']);
$label = $ver['version'] ? 'v' . $ver['version'] : 'la version du ' . fr_date($ver['created_at']);

switch ((string) ($_POST['action'] ?? '')) {
    case 'restore':
        if (!is_file(storage_path($ver['stored_name']))) {
            flash('error', 'Le fichier de cette version est absent du stockage.');
            break;
        }
        restore_version($f, $ver);
        $bad = integrity_process(file_row((int) $f['id']));
        $fid = (int) $f['id'];
        defer_after_response(fn() => precompute_hashes($fid));
        flash('success', e($label) . ' rétablie comme version actuelle. L\'ancienne version actuelle est conservée dans l\'historique.');
        if ($bad) {
            flash('error', 'Attention : la somme de contrôle de la version rétablie ne correspond pas.');
        }
        break;

    case 'delete':
        delete_version($ver);
        flash('success', 'Version ' . e($label) . ' supprimée.');
        break;
}
redirect('file.php?id=' . $f['id'] . '#versions');
