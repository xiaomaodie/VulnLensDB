CREATE TABLE IF NOT EXISTS lib_package (
 id INT PRIMARY KEY, ecosystem VARCHAR(12) NOT NULL, name VARCHAR(730) COLLATE utf8mb4_bin NOT NULL,
 UNIQUE KEY package_key(ecosystem,name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_advisory (
 id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, title TEXT NOT NULL, published DATETIME NOT NULL,
 modified DATETIME NOT NULL, score DECIMAL(3,1), severity VARCHAR(16) NOT NULL,
 FULLTEXT KEY title_search(title), KEY date_severity(published,severity), KEY score_order(score,id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_alias (
 alias VARCHAR(200) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, advisory_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 osv_record BOOLEAN NOT NULL, FOREIGN KEY(advisory_id) REFERENCES lib_advisory(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_affected (
 package_id INT NOT NULL, advisory_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, listed_versions JSON NOT NULL,
 PRIMARY KEY(package_id,advisory_id), FOREIGN KEY(package_id) REFERENCES lib_package(id),
 FOREIGN KEY(advisory_id) REFERENCES lib_advisory(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_span (
 id BIGINT AUTO_INCREMENT PRIMARY KEY, package_id INT NOT NULL, advisory_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 introduced TEXT NOT NULL, end_type VARCHAR(16) NOT NULL, endpoint TEXT NOT NULL,
 FOREIGN KEY(package_id,advisory_id) REFERENCES lib_affected(package_id,advisory_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_nvd (
 cve VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, description TEXT NOT NULL, score DECIMAL(3,1),
 author VARCHAR(160), published DATETIME NOT NULL, FULLTEXT KEY description_search(description)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_cpe (
 id INT AUTO_INCREMENT PRIMARY KEY,cve VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, rule_json JSON NOT NULL,
 FOREIGN KEY(cve) REFERENCES lib_nvd(cve)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_project (
 project_key VARCHAR(380) PRIMARY KEY, url TEXT NOT NULL, score DECIMAL(3,1), assessed DATETIME
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_check (
 project_key VARCHAR(380) NOT NULL, metric VARCHAR(100) NOT NULL, score INT NOT NULL,
 PRIMARY KEY(project_key,metric), FOREIGN KEY(project_key) REFERENCES lib_project(project_key)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_profile (
 package_id INT PRIMARY KEY, version VARCHAR(200) NOT NULL, evidence_url TEXT NOT NULL, project_key VARCHAR(380),
 FOREIGN KEY(package_id) REFERENCES lib_package(id), FOREIGN KEY(project_key) REFERENCES lib_project(project_key)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_release (
 package_id INT NOT NULL, version VARCHAR(240) COLLATE utf8mb4_bin NOT NULL, published DATETIME,
 PRIMARY KEY(package_id,version), FOREIGN KEY(package_id) REFERENCES lib_package(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_edge (
 root_id INT NOT NULL, parent_id INT NOT NULL, child_id INT NOT NULL, parent_version VARCHAR(240) COLLATE utf8mb4_bin NOT NULL,
 child_version VARCHAR(240) COLLATE utf8mb4_bin NOT NULL, requirement TEXT NOT NULL,
 PRIMARY KEY(root_id,parent_id,child_id,parent_version,child_version),KEY downstream(child_id,parent_id),
 FOREIGN KEY(root_id) REFERENCES lib_profile(package_id), FOREIGN KEY(parent_id) REFERENCES lib_package(id),
 FOREIGN KEY(child_id) REFERENCES lib_package(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_stats (
 package_id INT PRIMARY KEY, advisories INT NOT NULL, max_score DECIMAL(3,1), dependents INT NOT NULL,
 releases INT NOT NULL, FOREIGN KEY(package_id) REFERENCES lib_package(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS lib_batch (
 id INT PRIMARY KEY, fingerprint CHAR(64) NOT NULL, collected DATETIME NOT NULL, manifest JSON NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS course_account (
 id BIGINT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(48) UNIQUE NOT NULL,
 password_hash VARCHAR(255) NOT NULL,role ENUM('member','admin') NOT NULL DEFAULT 'member'
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS course_scan (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,account_id BIGINT NOT NULL,created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 components INT NOT NULL,findings INT NOT NULL,uncertain INT NOT NULL,
 FOREIGN KEY(account_id) REFERENCES course_account(id)
) ENGINE=InnoDB;
