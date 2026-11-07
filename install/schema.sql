-- SV Pro Downloads — schéma MySQL / MariaDB (utf8mb4)
-- Le préfixe des tables est remplacé par install.php ({p} -> préfixe configuré)
-- Les tables des versions et de l'intégrité (v1.2) sont créées automatiquement
-- au premier accès par inc/migrate.php, comme lors d'une mise à jour.

CREATE TABLE IF NOT EXISTS {p}users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(60)  NOT NULL UNIQUE,
  email         VARCHAR(190) NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('admin','editor','member') NOT NULL DEFAULT 'member',
  active        TINYINT(1)   NOT NULL DEFAULT 1,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME     NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Catégories sur deux niveaux : structure (parent_id NULL) › service
CREATE TABLE IF NOT EXISTS {p}categories (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  parent_id  INT UNSIGNED NULL,
  name       VARCHAR(120) NOT NULL,
  position   INT NOT NULL DEFAULT 0,
  CONSTRAINT fk_{p}cat_parent FOREIGN KEY (parent_id) REFERENCES {p}categories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS {p}files (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(200) NOT NULL,
  description   TEXT NULL,
  version       VARCHAR(40)  NULL,
  original_name VARCHAR(255) NOT NULL,
  stored_name   CHAR(32)     NOT NULL UNIQUE,
  mime          VARCHAR(120) NOT NULL,
  size          BIGINT UNSIGNED NOT NULL,
  sha256        CHAR(64)     NOT NULL,
  category_id   INT UNSIGNED NULL,
  visibility    ENUM('public','private','hidden') NOT NULL DEFAULT 'public',
  downloads     INT UNSIGNED NOT NULL DEFAULT 0,
  uploaded_by   INT UNSIGNED NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_{p}files_cat (category_id),
  KEY idx_{p}files_vis (visibility),
  CONSTRAINT fk_{p}files_cat  FOREIGN KEY (category_id) REFERENCES {p}categories(id) ON DELETE SET NULL,
  CONSTRAINT fk_{p}files_user FOREIGN KEY (uploaded_by) REFERENCES {p}users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Liens de partage (fonctionnent même pour un fichier privé ou masqué)
CREATE TABLE IF NOT EXISTS {p}share_links (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_id       INT UNSIGNED NOT NULL,
  token         CHAR(40) NOT NULL UNIQUE,
  label         VARCHAR(120) NULL,
  expires_at    DATETIME NULL,
  max_downloads INT UNSIGNED NULL,
  uses          INT UNSIGNED NOT NULL DEFAULT 0,
  created_by    INT UNSIGNED NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_{p}links_file FOREIGN KEY (file_id) REFERENCES {p}files(id) ON DELETE CASCADE,
  CONSTRAINT fk_{p}links_user FOREIGN KEY (created_by) REFERENCES {p}users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS {p}download_log (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_id    INT UNSIGNED NOT NULL,
  user_id    INT UNSIGNED NULL,
  link_id    INT UNSIGNED NULL,
  ip         VARCHAR(45) NOT NULL,
  user_agent VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_{p}log_file (file_id),
  KEY idx_{p}log_date (created_at),
  CONSTRAINT fk_{p}log_file FOREIGN KEY (file_id) REFERENCES {p}files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS {p}login_attempts (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip         VARCHAR(45) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_{p}la_ip (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Réglages modifiables depuis l'administration (valeurs JSON)
CREATE TABLE IF NOT EXISTS {p}settings (
  name  VARCHAR(64) NOT NULL PRIMARY KEY,
  value MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
