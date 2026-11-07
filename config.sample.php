<?php
/**
 * SV Pro Downloads — configuration
 * Copier en config.php (install.php le fait automatiquement).
 */
return [
    'app_name'   => 'SV Pro Downloads',
    'base_url'   => '',            // sous-dossier éventuel, ex. '/downloads' (sans slash final)

    'db' => [
        'host'    => 'localhost',
        'port'    => 3306,
        'name'    => 'svpro_downloads',
        'user'    => 'svpro',
        'pass'    => '',
        'prefix'  => 'dl_',
    ],

    // Dossier de stockage des fichiers. Idéalement HORS de la racine web,
    // ex. '/var/lib/svpro-downloads'. Par défaut : ./storage (protégé par .htaccess).
    'storage_path' => __DIR__ . '/storage',

    // Dossier des sessions PHP propre à l'application (recommandé sur YunoHost / PHP-FPM
    // multi-pools). Vide = réglage par défaut du serveur. Doit être hors racine web ou protégé.
    'session_path' => __DIR__ . '/storage/sessions',

    // Dossier d'import (fichiers déposés par SFTP / scp, sans limite de taille), ex.
    // '/var/lib/svpro-downloads/import'. Vide = fonction désactivée. Hors racine web.
    'import_path' => '',

    // Clé maîtresse du chiffrement des fichiers (créée depuis Réglages › Chiffrement).
    // Fichier (ex. '/var/www/my_webapp__3/.key/svpro-downloads.key') ou dossier (la clé y est créée
    // sous le nom svpro-downloads.key). Vide = dirname(<dossier de l'appli>)/svpro-downloads.key
    // Jamais dans le dossier web ni dans storage/. À SAUVEGARDER à part : sans elle, fichiers perdus.
    'encryption_key_file' => '',

    'max_upload_mb' => 512,        // vérifier aussi upload_max_filesize / post_max_size dans php.ini

    // Extensions autorisées à l'envoi (valeurs initiales : modifiables ensuite dans
    // Administration › Réglages, qui prime alors sur cette liste)
    'allowed_ext' => [
        'pdf','doc','docx','odt','xls','xlsx','ods','ppt','pptx','odp','txt','csv','md','rtf',
        'zip','7z','tar','gz','tgz','bz2','xz','rar',
        'jpg','jpeg','png','gif','webp','svg',
        'mp3','ogg','flac','wav','m4a','mp4','webm','mkv',
        'iso','img','apk','exe','msi','deb','rpm','sh','ps1',
        'json','xml','yml','yaml','conf','log',
        // sommes de contrôle et signatures
        'md5','md5sum','sha1','sha1sum','sha256','sha256sum','sha512','sha512sum',
        'b2','b2sum','b3sum','crc','sfv','asc','sig','gpg','minisig','pem','pub',
    ],

    // Journal : tronquer les IP (RGPD) — 192.168.1.x / 2001:db8:x::
    'anonymize_ip'   => true,
    // Purge automatique du journal au-delà de N jours (0 = jamais)
    'log_retention_days' => 365,

    // Serveur : 'php' (lecture PHP, gère les reprises Range), 'xsendfile' (Apache mod_xsendfile)
    // ou 'accel' (Nginx X-Accel-Redirect, voir README)
    'send_mode'      => 'php',
    'accel_prefix'   => '/protected-files/',

    // Code source affiché en pied de page (licence AGPL-3.0, art. 13) : si vous modifiez
    // l'application, indiquez ici l'adresse de VOTRE version modifiée.
    'source_url'     => 'https://github.com/samuelvermeulenpro/DatasLockers',

    'per_page'       => 25,
    'login_max_attempts' => 5,     // par IP sur 15 minutes
];
