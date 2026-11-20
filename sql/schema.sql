CREATE TABLE IF NOT EXISTS package (
 name VARCHAR(120) PRIMARY KEY,
 ecosystem VARCHAR(20) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS advisory (
 id VARCHAR(64) PRIMARY KEY,
 title VARCHAR(512) NOT NULL,
 osv_level VARCHAR(20) NOT NULL,
 published DATETIME NOT NULL,
 modified DATETIME NOT NULL,
 FULLTEXT KEY ft_title (title)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS advisory_alias (
 alias_id VARCHAR(100) PRIMARY KEY,
 advisory_id VARCHAR(64) NOT NULL,
 FOREIGN KEY (advisory_id) REFERENCES advisory(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS nvd_rating (
 cve VARCHAR(64) PRIMARY KEY,
 score DECIMAL(3,1) NOT NULL,
 author VARCHAR(200) NOT NULL,
 modified DATETIME NOT NULL,
 CHECK(score BETWEEN 0 AND 10)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS package_release (
 package_name VARCHAR(120) NOT NULL,
 version VARCHAR(80) NOT NULL,
 published DATETIME NOT NULL,
 PRIMARY KEY(package_name, version),
 FOREIGN KEY(package_name) REFERENCES package(name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS affected_range (
 advisory_id VARCHAR(64) NOT NULL,
 package_name VARCHAR(120) NOT NULL,
 introduced VARCHAR(80) NOT NULL,
 fixed VARCHAR(80) NOT NULL,
 PRIMARY KEY(advisory_id,package_name,introduced,fixed),
 KEY by_package(package_name,advisory_id),
 FOREIGN KEY(advisory_id) REFERENCES advisory(id),
 FOREIGN KEY(package_name,fixed) REFERENCES package_release(package_name,version)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS evidence (
 advisory_id VARCHAR(64) NOT NULL,
 provider VARCHAR(20) NOT NULL,
 url VARCHAR(400) NOT NULL,
 retrieved DATETIME NOT NULL,
 PRIMARY KEY(advisory_id,provider,url),
 FOREIGN KEY(advisory_id) REFERENCES advisory(id)
) ENGINE=InnoDB;
