<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';

/*
 * Page « À propos » : explique le fonctionnement du gestionnaire.
 * Le contenu s'adapte au profil (visiteur, membre, éditeur, administrateur)
 * et reprend les réglages en vigueur (taille max., chiffrement, versions…).
 */

$u        = current_user();
$app      = (string) cfg('app_name', 'SV Pro Downloads');
$maxMb    = (int) setting('max_upload_mb', cfg('max_upload_mb', 512));
$keep     = (int) setting('versions_keep', 10);
$preview  = (bool) setting('preview_enabled', true);
$crypted  = encryption_enabled();
$isEditor = has_role('editor');
$isAdmin  = has_role('admin');
$anonIp   = (bool) cfg('anonymize_ip', true);
$keepDays = (int) cfg('log_retention_days', 365);

render_header('À propos', 'about');
?>
<div class="page-head">
  <div>
    <h1>À propos</h1>
    <p class="muted"><?= e($app) ?> — comment fonctionne ce gestionnaire de téléchargements</p>
  </div>
</div>

<div class="card highlight prose">
  <p>
    <strong><?= e($app) ?></strong> met à disposition des fichiers (logiciels, images ISO, documents…)
    de façon simple et sûre : chaque fichier est rangé dans une catégorie, accompagné de sa description,
    de son numéro de version et de son <strong>empreinte SHA-256</strong>, qui permet de vérifier qu'il
    n'a pas été altéré pendant le téléchargement.
  </p>
</div>

<h2>Trouver et télécharger un fichier</h2>
<div class="grid-3">
  <div class="card">
    <h3>1. Parcourir</h3>
    <p class="small">La page <a href="<?= e(url('index.php')) ?>">Téléchargements</a> liste les fichiers.
      Filtrez par catégorie (structure › service), recherchez par nom ou description et triez par date,
      nom, popularité ou taille.</p>
  </div>
  <div class="card">
    <h3>2. Consulter la fiche</h3>
    <p class="small">Cliquez sur un titre pour ouvrir sa fiche : description, taille, date, empreintes,
      <?= $preview ? 'aperçu (images, PDF, audio, vidéo, texte), ' : '' ?>historique des versions et
      état de vérification des sommes de contrôle.</p>
  </div>
  <div class="card">
    <h3>3. Télécharger</h3>
    <p class="small">Le bouton <strong>⬇ Télécharger</strong> lance le transfert. Un téléchargement
      interrompu peut être <strong>repris</strong> par votre navigateur ou gestionnaire de
      téléchargements ; il n'est compté qu'une fois.</p>
  </div>
</div>

<h2>Qui peut voir quoi ?</h2>
<div class="card table-card">
  <table class="table">
    <thead><tr><th>Accès</th><th>Visible par</th></tr></thead>
    <tbody>
      <tr><td><?= vis_badge('public') ?></td><td>Tout le monde, sans connexion.</td></tr>
      <tr><td><?= vis_badge('private') ?></td><td>Les personnes connectées avec un compte (membre, éditeur, administrateur).</td></tr>
      <tr><td><?= vis_badge('hidden') ?></td><td>N'apparaît dans aucune liste : accessible uniquement par un <strong>lien de partage</strong>.</td></tr>
    </tbody>
  </table>
</div>
<div class="card prose">
  <h3>Liens de partage</h3>
  <p class="small">Un lien de partage donne accès à un fichier précis sans compte. Il peut avoir une
    <strong>date d'expiration</strong> (de 24 heures à illimité) et un <strong>nombre maximal de
    téléchargements</strong> ; il peut être révoqué à tout moment. Une fois expiré ou épuisé, le lien
    ne fonctionne plus.</p>
  <?php if (!$u): ?>
    <p class="small muted">Vous avez un compte ? <a href="<?= e(url('login.php')) ?>">Connectez-vous</a> pour voir les fichiers réservés aux membres.</p>
  <?php endif; ?>
</div>

<h2>Vérifier l'intégrité d'un fichier</h2>
<div class="card prose">
  <p class="small">Chaque fiche affiche l'empreinte <strong>SHA-256</strong> du fichier (et, selon les
    réglages, MD5, SHA-1, SHA-512, CRC32 ou BLAKE2b) — cliquez dessus pour la copier. Vous pouvez aussi
    télécharger un fichier de sommes prêt à l'emploi (format GNU <code>sha256sum</code>, BSD, SFV…).
    Après le téléchargement, comparez :</p>
  <ul class="small">
    <li>Linux : <code>sha256sum -c fichier.iso.sha256sum</code></li>
    <li>macOS : <code>shasum -a 256 -c fichier.iso.sha256sum</code></li>
    <li>Windows (PowerShell) : <code>Get-FileHash fichier.iso -Algorithm SHA256</code></li>
  </ul>
  <p class="small">Lorsqu'un fichier de sommes publié (<code>SHA256SUMS</code>, <code>.sha256sum</code>,
    <code>.md5</code>, <code>.sfv</code>…) mentionne d'autres fichiers du site, ceux-ci sont vérifiés
    automatiquement : <strong>✔ conforme</strong>, <strong>✖ non conforme</strong> ou
    <strong>≈ correspond à une version précédente</strong>.</p>
</div>

<h2>Versions</h2>
<div class="card prose">
  <p class="small">Quand un fichier est mis à jour, la nouvelle version remplace l'ancienne sur la fiche,
    avec ses notes de version.<?php if ($keep > 0): ?> Les <?= $keep ?> versions précédentes au plus
    restent consultables dans l'historique de la fiche<?= setting('versions_public', true) ? ' et téléchargeables' : '' ?>.<?php endif; ?></p>
</div>

<h2>Sécurité et confidentialité</h2>
<div class="grid-2">
  <div class="card">
    <h3>Stockage</h3>
    <ul class="small">
      <li>Les fichiers sont stockés sous un nom aléatoire, hors de portée directe, et ne sont servis
        qu'après contrôle des droits d'accès.</li>
      <li>Seules certaines extensions sont acceptées ; les scripts exécutables côté serveur sont
        toujours refusés.</li>
      <?php if ($crypted): ?>
        <li>Les fichiers sont <strong>chiffrés sur le serveur</strong> (XChaCha20-Poly1305), de façon
          transparente pour vous.</li>
      <?php endif; ?>
    </ul>
  </div>
  <div class="card">
    <h3>Vos données</h3>
    <ul class="small">
      <li>Le journal des téléchargements conserve la date, le fichier et l'adresse IP<?= $anonIp ? ' <strong>tronquée</strong>' : '' ?><?= $keepDays > 0 ? ' ; il est purgé automatiquement après ' . $keepDays . ' jours' : '' ?>.</li>
      <li>Les mots de passe sont stockés sous forme hachée ; les tentatives de connexion sont limitées.</li>
      <li>Un seul cookie de session, indispensable au fonctionnement, sans traceur publicitaire.</li>
    </ul>
  </div>
</div>

<?php if ($isEditor): ?>
<h2>Pour les éditeurs</h2>
<div class="grid-2">
  <div class="card">
    <h3>Publier</h3>
    <ul class="small">
      <li><a href="<?= e(url('admin/upload.php')) ?>">Envoyer</a> : glisser-déposer un ou plusieurs
        fichiers (jusqu'à <?= e(human_size($maxMb * 1048576)) ?> chacun). Les gros fichiers partent
        par morceaux et l'envoi reprend après une coupure ; resélectionner le même fichier n'envoie
        que le reste.</li>
      <li><a href="<?= e(url('admin/import.php')) ?>">Importer</a> : les fichiers déposés par SFTP /
        rsync dans le dossier d'import sont ajoutés en un clic, sans limite de taille, avec suivi en
        temps réel.</li>
      <li>Envoyer un fichier sur une fiche existante publie une <strong>nouvelle version</strong>.</li>
    </ul>
  </div>
  <div class="card">
    <h3>Organiser et partager</h3>
    <ul class="small">
      <li><a href="<?= e(url('admin/categories.php')) ?>">Catégories</a> sur deux niveaux, réordonnables.</li>
      <li><a href="<?= e(url('admin/files.php')) ?>">Fichiers</a> : modifier, changer l'accès, actions
        groupées (génération d'un <code>SHA256SUMS</code>, revérification…).</li>
      <li><a href="<?= e(url('admin/links.php')) ?>">Liens de partage</a> : créer, suivre, révoquer.</li>
      <li><a href="<?= e(url('admin/logs.php')) ?>">Journal</a> des téléchargements, filtrable et exportable en CSV.</li>
    </ul>
  </div>
</div>
<?php endif; ?>

<?php if ($isAdmin): ?>
<h2>Pour les administrateurs</h2>
<div class="card prose">
  <ul class="small">
    <li><a href="<?= e(url('admin/users.php')) ?>">Utilisateurs</a> : trois rôles —
      <strong>Membre</strong> (voit les fichiers réservés), <strong>Éditeur</strong> (publie et gère les
      fichiers), <strong>Administrateur</strong> (comptes et réglages).</li>
    <li><a href="<?= e(url('admin/settings.php')) ?>">Réglages</a> : extensions autorisées, taille
      maximale, empreintes calculées automatiquement, versions conservées, aperçus, notifications par
      e-mail (local ou SMTP) et chiffrement des fichiers.</li>
    <li>Chiffrement : <strong><?= $crypted ? 'activé pour les nouveaux fichiers' : 'désactivé' ?></strong>.
      Sans la clé maîtresse, les fichiers chiffrés sont irrécupérables : sauvegardez-la hors du serveur.</li>
  </ul>
</div>
<?php endif; ?>

<h2>Licence et code source</h2>
<div class="card prose">
  <p class="small"><?= e($app) ?> est un logiciel libre distribué sous licence
    <strong>GNU Affero General Public License v3.0</strong> (AGPL-3.0) : vous pouvez l'utiliser,
    l'étudier, le modifier et le redistribuer. Une version modifiée proposée en ligne doit mettre son
    code source à disposition de ses utilisateurs.</p>
  <?php if (source_url() !== ''): ?>
    <p class="small"><a class="btn btn-light btn-sm" href="<?= e(source_url()) ?>" rel="noopener">Voir le code source</a></p>
  <?php endif; ?>
</div>

<p class="muted small center"><?= e($app) ?> v<?= APP_VERSION ?> — SV Pro, Samuel Vermeulen, Consultant Informatique &amp; Internet</p>
<?php render_footer();
