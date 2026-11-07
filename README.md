# SV Pro Downloads

Gestionnaire de téléchargements de fichiers — PHP 8.1+ / MySQL ou MariaDB, aux couleurs SV Pro,
dans la même famille que Taskman (liste publique, administration authentifiée, catégories structure › service).

## Fonctionnalités

- **Liste publique** : recherche, tri (récents, nom, téléchargements, taille), filtre par catégorie, fiche détaillée avec empreinte SHA-256.
- **Trois niveaux d'accès par fichier** : *Public* · *Membres* (connexion requise) · *Masqué* (uniquement via lien de partage).
- **Liens de partage** : expiration (24 h → jamais), quota de téléchargements, libellé, révocation, purge des liens expirés.
- **Envoi multiple** par glisser-déposer avec barre de progression, débit et temps restant.
- **Gros fichiers (ISO de plusieurs Go)** : envoi **par morceaux** (32 Mo par défaut) — les limites PHP
  `upload_max_filesize` / `post_max_size` ne s'appliquent plus qu'à un morceau. Reprise automatique après
  une coupure (nouvel essai) et reprise manuelle (resélectionner le même fichier : seul le reste est envoyé).
  SHA-256 calculé au fil des morceaux, extension, taille et espace disque contrôlés avant le premier octet.
- **Import depuis le serveur** : fichiers déposés par SFTP / scp / rsync dans un dossier d'import,
  importés en un clic, sans aucune limite de taille, avec **avancement en temps réel** (barre, %,
  fichier en cours, étape, débit, temps restant, état de chaque fichier) — la page peut être fermée
  et rouverte, le suivi reprend. Une seule lecture par fichier calcule SHA-256 et les empreintes
  automatiques (MD5, SHA-1, SHA-512…) : environ 4 fois plus rapide qu'une lecture par algorithme.
- **Catégories** sur deux niveaux, réordonnables.
- **Réglages** (administrateur) : extensions autorisées modifiables à la volée (ajout libre, groupes prédéfinis,
  retrait d'un clic), fichiers sans extension (`SHA256SUMS`, `README`…), taille max. Sommes de contrôle
  et signatures (`.md5sum`, `.sha256sum`, `.asc`, `.sig`…) acceptées par défaut.
- **Historique des versions** : envoyer un fichier sur une fiche existante publie une nouvelle version
  (avec ses notes de version) ; les précédentes restent téléchargeables, peuvent être rétablies ou
  supprimées. Nombre de versions conservées réglable (0 = pas d'historique).
- **Aperçu** sur la fiche : images, PDF, audio, vidéo et fichiers texte (journaux, sommes, configs…),
  sans compter de téléchargement. Les SVG et HTML ne sont jamais affichés (sécurité).
- **Vérification automatique des sommes de contrôle** : un fichier `.sha256sum`, `.md5`, `.sha512`,
  `SHA256SUMS`, `MD5SUMS`, `.sfv`, `B2SUMS`… est analysé à l'envoi (formats GNU, BSD `--tag`,
  empreinte seule, SFV, clairsigné PGP) et chaque fichier du même nom est vérifié :
  ✔ conforme · ✖ non conforme (alerte) · ≈ correspond à une version précédente (somme à republier).
  Revérification à la demande (actions groupées ou Réglages).
- **Génération de sommes de contrôle** : sur chaque fiche, empreintes MD5, SHA-1, SHA-256, SHA-512,
  CRC32 et BLAKE2b-512 (copiables) et fichier de sommes au format GNU coreutils (`sha256sum -c`),
  BSD `--tag` (plusieurs algorithmes dans un fichier), empreinte seule ou SFV. Téléchargement direct,
  ou publication dans le gestionnaire (même catégorie et accès que le fichier ; nouvelle version si le
  fichier de sommes existe déjà) — il est alors vérifié aussitôt. En action groupée : un `SHA256SUMS`,
  `MD5SUMS`, `CHECKSUMS.txt` ou `.sfv` pour toute une sélection.
- **Notifications par e-mail** : nouveaux fichiers, nouvelles versions, sommes non conformes.
  Destinataires libres et/ou comptes par rôle (les membres ne sont jamais avertis des fichiers masqués),
  un seul e-mail par envoi groupé, envoi après la réponse (l'utilisateur n'attend pas).
  Transport `mail()` (Postfix local) ou SMTP (STARTTLS / SSL, authentification), e-mail de test.
- **Chiffrement des fichiers sur le serveur** (*Réglages › Chiffrement*) : XChaCha20-Poly1305
  (libsodium), une clé par fichier protégée par une clé maîtresse rangée hors du dossier web et du
  stockage. Transparent : liens publics, reprise, aperçu, sommes et versions fonctionnent à l'identique.
  Le contenu en clair n'est jamais écrit dans le stockage (envois chiffrés à l'arrivée, import chiffré
  pendant sa lecture). Altération et troncature détectées. Conversion de l'existant dans les deux sens,
  en arrière-plan avec progression, chaque fichier contrôlé par son SHA-256.
- **Comptes** : Membre / Éditeur / Administrateur.
- **Journal** des téléchargements filtrable, export CSV (compatible Excel), IP tronquées (RGPD) et purge automatique.
- **Tableau de bord** : volumes, espace disque, histogramme 14 jours, top fichiers.

## Sécurité

- Fichiers stockés sous un nom aléatoire, sans extension, servis uniquement par `download.php`.
- Liste blanche d'extensions + refus systématique des scripts (`.php`, `.phtml`, `.phar`…), type MIME détecté par `finfo`.
- Requêtes préparées PDO, jetons CSRF sur tous les formulaires (et la déconnexion), sessions `HttpOnly` / `SameSite`.
- `password_hash()` avec rehash automatique, limitation des tentatives de connexion par IP.
- Reprise de téléchargement (`Range`) ; un téléchargement n'est compté qu'une fois, même repris.

## Installation

1. Copier le dossier sur le serveur (racine ou sous-dossier).
2. Créer une base et un utilisateur MySQL :
   ```sql
   CREATE DATABASE svpro_downloads CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'svpro'@'localhost' IDENTIFIED BY 'mot-de-passe';
   GRANT ALL ON svpro_downloads.* TO 'svpro'@'localhost';
   ```
3. Ouvrir `https://votre-site/install.php`, remplir le formulaire.
4. **Supprimer `install.php`**.
5. Ajuster `php.ini` pour les gros fichiers :
   ```ini
   upload_max_filesize = 512M
   post_max_size = 520M
   max_execution_time = 300
   ```

Extensions PHP requises : `pdo_mysql`, `fileinfo`, `mbstring`.

### Dossier de stockage

Par défaut `storage/`, protégé par `.htaccess` (Apache). **Recommandé** : le placer hors de la racine web,
par ex. `/var/lib/svpro-downloads` (propriétaire `www-data`, droits `750`), puis renseigner `storage_path`
dans `config.php`.

### Nginx

Les `.htaccess` ne sont pas lus par Nginx : bloquer explicitement les dossiers sensibles.

```nginx
location ~ ^/(storage|inc|install)/ { deny all; }
location = /config.php            { deny all; }

# Optionnel : envoi direct des fichiers par Nginx ('send_mode' => 'accel')
location /protected-files/ {
    internal;
    alias /var/lib/svpro-downloads/;
}
```

Avec Apache + `mod_xsendfile`, utiliser `'send_mode' => 'xsendfile'` et `XSendFilePath /var/lib/svpro-downloads`.

## Personnalisation

- Couleurs : mêmes variables CSS que Taskman en tête de `assets/style.css` (`--accent`, `--accent2`, `--btn`…),
  mode sombre automatique.
- Logo : `assets/logo.png` et `assets/favicon.png`.
- Extensions autorisées et taille max : **Administration › Réglages** (la liste de `config.php` ne sert que de valeur initiale).
- Rétention du journal, anonymisation des IP : `config.php`.

## Mise à jour (1.x → 1.6)

Remplacer les fichiers (sauf `config.php` et `storage/`). Les nouvelles tables (réglages, versions,
intégrité) et colonnes sont créées automatiquement au premier accès ; les fichiers de sommes déjà
présents sont analysés à cette occasion.

## Notifications : configuration

**Administration › Réglages › Notifications**

- *Serveur local* : `mail()` de PHP, donc le Postfix de la machine (cas de YunoHost).
- *SMTP* : port 587 + STARTTLS (ou 465 + SSL/TLS) avec un compte de messagerie.
  Le mot de passe SMTP est enregistré en base (table `settings`) : utilisez un compte dédié.
- Renseignez l'**URL publique du site** pour que les liens des e-mails soient corrects derrière un proxy.
- Le bouton *Envoyer un e-mail de test* affiche l'erreur exacte en cas d'échec.

## Gros fichiers : configuration

1. **Réglages › Fichiers › Taille max. par fichier** : par ex. `8192` (8 Go). C'est la seule limite
   qui compte pour l'envoi par le navigateur.
2. La taille d'un morceau (32 Mo par défaut) est automatiquement plafonnée sous `upload_max_filesize`
   et `post_max_size`. Elle doit aussi passer le `client_max_body_size` de Nginx (YunoHost : vérifier
   `/etc/nginx/conf.d/<domaine>.d/<app>.conf`, ex. `client_max_body_size 64M;`).
3. Prévoir sur le disque du stockage au moins la taille du fichier (les morceaux sont assemblés
   directement à leur place définitive).
4. Les envois abandonnés sont purgés après 48 h (`storage/.chunks`).

### Chiffrement : à savoir

- Activation : *Réglages › Chiffrement* › **Créer la clé**, puis cocher **Chiffrer les nouveaux fichiers**,
  et éventuellement **Chiffrer les fichiers existants**. Requiert l'extension `sodium` (incluse dans PHP
  sous Debian/YunoHost).
- La clé maîtresse est créée par défaut **au-dessus du dossier web** (`…/my_webapp__3/svpro-downloads.key`,
  droits 0400) ; autre emplacement : `encryption_key_file` dans `config.php` — un fichier, ou un dossier (la clé y est créée sous le nom `svpro-downloads.key`). Jamais dans `www/` ni `storage/`.
- **Sauvegardez la clé hors du serveur** (bouton *Télécharger la clé*, mot de passe requis) : sans elle,
  les fichiers chiffrés sont **irrécupérables**. Pensez-y en restaurant une sauvegarde ou en migrant :
  il faut `storage/` **et** la clé.
- Ce que ça protège : vol du disque, sauvegardes et snapshots, copie du dossier `storage`, autres
  utilisateurs du serveur. Ce que ça ne protège pas : quelqu'un qui contrôle entièrement le serveur.
- Les fichiers chiffrés sont toujours servis par PHP (`send_mode` ignoré pour eux) ; surcoût : 16 octets
  par Mio et un peu de CPU (de l'ordre de plusieurs centaines de Mo/s sur un serveur récent).
- Le dossier d'import (SFTP) contient forcément les fichiers en clair jusqu'à leur import ; ils sont
  supprimés une fois chiffrés.

### PHP 32 bits (Raspberry Pi OS armhf, i386…)

Sur un PHP 32 bits (`php -r 'echo PHP_INT_SIZE;'` affiche `4`), les entiers plafonnent à 2 Go :
`filesize()` renvoie une taille négative ou fausse et `fseek()` se trompe au-delà de 2 Go. Depuis la
1.4.3, l'application gère ces fichiers elle-même (taille réelle via `stat`, lecture séquentielle, ajout
en fin de fichier) : import, envoi par morceaux, téléchargement et reprise sont exacts jusqu'à
plusieurs To. La mise à jour corrige automatiquement les tailles mal enregistrées, et
*Réglages › Fichiers › Stockage* récupère les fichiers restés orphelins après un import échoué.
À noter : un PHP 32 bits refuse les réglages php.ini ≥ 2G (`upload_max_filesize = 64M` suffit avec
l'envoi par morceaux).

### Erreur 504 (Gateway Timeout)

Un 504 n'est **pas** un manque de mémoire : Nginx a attendu la réponse de PHP plus longtemps que
`fastcgi_read_timeout` (60 s par défaut). L'application ne charge jamais un fichier en mémoire
(lecture/écriture en flux) : `memory_limit = 128M` suffit.

Depuis la 1.4.1, tout ce qui relit un fichier de plus de 256 Mo (vérification MD5/SHA-1/SHA-512,
calcul d'empreintes, revérification, import) s'exécute **après la réponse**, en arrière-plan
(`fastcgi_finish_request`). Pour que ces tâches ne soient pas interrompues, réglez le pool PHP-FPM
(YunoHost : `/etc/php/8.X/fpm/pool.d/my_webapp__4.conf`) :

```ini
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 3600
php_admin_value[max_input_time] = 600
request_terminate_timeout = 3600
```

et la configuration Nginx de l'application (`/etc/nginx/conf.d/<domaine>.d/my_webapp__4.conf`) :

```nginx
client_max_body_size 64M;
fastcgi_read_timeout 300s;
```

puis `systemctl reload php8.X-fpm nginx`. Sur YunoHost, une mise à jour de l'application peut
régénérer ces fichiers : vérifiez d'abord si `yunohost app config get my_webapp__4` propose ces
réglages. Pour savoir quelle page a expiré :
`grep "upstream timed out" /var/log/nginx/<domaine>-error.log`.

**Import depuis le serveur** (au-delà, ou pour des transferts très longs) : renseigner `import_path`
dans `config.php`, par ex. `/var/lib/svpro-downloads/import`, lisible et modifiable par l'utilisateur
PHP (YunoHost : l'utilisateur de l'application, ex. `chown my_webapp: … && chmod 2770 …`, en ajoutant
votre compte SFTP au groupe). Sur le même disque que le stockage, l'import est un simple déplacement.

**Téléchargement de gros fichiers** : le mode par défaut `'send_mode' => 'php'` fonctionne partout
(reprise comprise) et convient très bien, même pour des ISO de plusieurs Go.
Le mode `'accel'` (Nginx sert le fichier lui-même) est une optimisation **avancée** qui exige :
1. le bloc `location /protected-files/ { internal; alias /chemin/vers/storage/; }` dans la configuration
   Nginx de l'application ;
2. que Nginx (`www-data`) puisse lire les fichiers : `chgrp -R www-data storage && chmod 2750 storage
   && chmod 640 storage/*` (le *setgid* fait hériter le groupe aux nouveaux fichiers).
Sinon, tous les téléchargements et aperçus échouent (« introuvable » / 403). *Réglages › Fichiers ›
Stockage* signale ce cas.

## Génération des sommes : bon à savoir

- Les empreintes choisies dans *Réglages › Fichiers* (MD5, SHA-1, SHA-512 par défaut) sont calculées
  juste après chaque envoi, sans faire attendre ; les visiteurs peuvent générer les fichiers correspondants.
- Les visiteurs n'obtiennent que des empreintes déjà calculées (pas de calcul lourd à la demande) ;
  les éditeurs peuvent calculer une empreinte manquante d'un clic.
- Noms produits : `fichier.iso.sha256sum` (GNU), `fichier.iso.sha256` (BSD / empreinte seule),
  `fichier.iso.checksums.txt` (BSD multi-algorithmes), `fichier.iso.sfv` ; en groupé `SHA256SUMS`,
  `MD5SUMS`, `CHECKSUMS.txt`, `checksums.sfv`. Les fichiers de sommes sélectionnés sont ignorés.
- Contrôle côté client : `sha256sum -c fichier.iso.sha256sum` (Linux), `shasum -a 256 -c` (macOS),
  `Get-FileHash fichier.iso -Algorithm SHA256` (PowerShell).

## Vérification des sommes : bon à savoir

- Le rapprochement se fait par **nom de fichier**, de préférence dans la même catégorie.
- SHA-256 est déjà calculé à l'envoi : la vérification est instantanée. MD5 / SHA-1 / SHA-512 / CRC32 /
  BLAKE2b sont calculés une fois puis mis en cache (compter quelques secondes par Go).
- BLAKE3 (`.b3sum`) n'est pas disponible en PHP : ces lignes sont signalées « non pris en charge ».
- Les signatures (`.asc`, `.sig`, `.minisig`) sont acceptées à l'envoi mais ne sont pas vérifiées.

## Arborescence

```
index.php        Liste publique
file.php         Fiche : aperçu, intégrité, historique des versions
download.php     Téléchargement (id, version archivée ou lien de partage)
preview.php      Affichage en ligne pour l'aperçu (non compté)
about.php        Page « À propos » : fonctionnement (adaptée au profil et aux réglages)
checksum.php     Génération d'un fichier de sommes (téléchargement / publication)
admin/chunk.php  Réception des envois par morceaux (reprise possible)
admin/import.php Import des fichiers déposés dans le dossier d'import
login.php / logout.php
admin/           Tableau de bord, fichiers, envoi, versions, catégories, liens, journal, utilisateurs, réglages
inc/             bootstrap.php (config, BDD, sécurité) · layout.php (gabarit) · files.php (envois, versions)
                 crypto.php (chiffrement : format, lecture/écriture, conversion)
                 integrity.php (sommes de contrôle) · mailer.php (e-mails) · send.php · migrate.php
assets/          style.css · app.js · logo
install/         schema.sql
storage/         fichiers envoyés (à déplacer hors racine web de préférence)
```

## Licence

Distribué sous licence **GNU Affero General Public License v3.0** — voir le fichier [`LICENSE`](LICENSE).
Vous pouvez utiliser, modifier et redistribuer ce logiciel ; si vous en proposez une version modifiée
en ligne, vous devez en mettre le code source à disposition de ses utilisateurs (article 13).
Le pied de page et la page *À propos* affichent un lien **Code source** : si vous modifiez
l'application, renseignez `source_url` dans `config.php` avec l'adresse de votre version.

© SV Pro — Samuel Vermeulen, Consultant Informatique & Internet
