-- enzyme_predictor 数据库表结构（修正版）
-- 创建用户表
CREATE TABLE IF NOT EXISTS `user` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',
  `password_hash` VARCHAR(255) NOT NULL COMMENT '密码哈希值',
  `role` ENUM('admin', 'biochemist', 'ml_experimenter') NOT NULL DEFAULT 'biochemist' COMMENT '用户角色',
  `invite_code` VARCHAR(20) DEFAULT NULL COMMENT '邀请码',
  `registered_by` INT DEFAULT NULL COMMENT '邀请人ID',
  `invite_uses` INT NOT NULL DEFAULT 0 COMMENT '邀请码使用次数',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '注册时间',
  FOREIGN KEY (`registered_by`) REFERENCES `user`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建生化实验数据表
CREATE TABLE IF NOT EXISTS `wet_experiment` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `user_id` INT NOT NULL COMMENT '实验者ID',
  `experiment_time` DATETIME NOT NULL COMMENT '实验时间',
  `enzyme_class` VARCHAR(50) NOT NULL COMMENT '酶类别',
  `substrate_name` VARCHAR(100) NOT NULL COMMENT '底物名称',
  `kcat_value` FLOAT NOT NULL COMMENT '催化常数',
  `km_value` FLOAT DEFAULT NULL COMMENT '米氏常数',
  `ph_value` FLOAT DEFAULT NULL COMMENT 'pH值',
  `temperature` FLOAT DEFAULT NULL COMMENT '温度',
  `notes` TEXT DEFAULT NULL COMMENT '实验备注',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建机器学习实验表
CREATE TABLE IF NOT EXISTS `ml_experiment` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `user_id` INT NOT NULL COMMENT '实验者ID',
  `model_type` VARCHAR(50) NOT NULL COMMENT '模型类型',
  `training_time` DATETIME NOT NULL COMMENT '训练时间',
  `dataset_seed` INT NOT NULL COMMENT '数据集种子',
  `hyperparameters` JSON DEFAULT NULL COMMENT '超参数配置',
  `metrics` JSON DEFAULT NULL COMMENT '评估指标',
  `model_path` VARCHAR(255) DEFAULT NULL COMMENT '模型存储路径',
  `notes` TEXT DEFAULT NULL COMMENT '实验备注',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建机器学习验证数据表
CREATE TABLE IF NOT EXISTS `ml_validation` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `ml_experiment_id` INT NOT NULL COMMENT '关联的ML实验ID',
  `user_id` INT NOT NULL COMMENT '验证者ID',
  `prediction_time` DATETIME NOT NULL COMMENT '预测时间',
  `enzyme_id` INT NOT NULL COMMENT '关联的酶数据ID',
  `predicted_kcat` FLOAT NOT NULL COMMENT '预测kcat值',
  `actual_kcat` FLOAT DEFAULT NULL COMMENT '实际kcat值',
  `score` FLOAT DEFAULT NULL COMMENT '预测得分',
  `notes` TEXT DEFAULT NULL COMMENT '验证备注',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  FOREIGN KEY (`ml_experiment_id`) REFERENCES `ml_experiment`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`enzyme_id`) REFERENCES `wet_experiment`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建酶数据视图（包含实验者信息）
CREATE OR REPLACE VIEW `enzyme_data_view` AS
SELECT
    we.id,
    we.experiment_time,
    we.enzyme_class,
    we.substrate_name,
    we.kcat_value,
    u.username AS experimenter
FROM wet_experiment we
JOIN user u ON we.user_id = u.id;

-- 创建管理员用户
INSERT INTO `user` (username, password_hash, role, invite_code, invite_uses)
VALUES (
    'admin',
    '$2b$12$EixZaL4H3Xf7Y1Zg01d7MOYcQz6l/0kR5yFAZ4O3ZfK3i9LbXY5Eq', -- 密码：Admin123!
    'admin',
    'ADMIN_INVITE',
    0
);

-- 创建生化测试用户（修正版）
SET @admin_id = (SELECT id FROM `user` WHERE username = 'admin');
INSERT INTO `user` (username, password_hash, role, invite_code, registered_by, invite_uses)
VALUES (
    'biochemist_test',
    '$2b$12$DWbQpX6g7e5n0ZJZ6bY7AOuZ5hB7g3Zt7D7bJZ7kG7r3JZ6bY7A', -- 密码：BioTest123!
    'biochemist',
    'BIO_TEST_001',
    @admin_id,
    0
);

-- 创建机器学习测试用户（修正版）
SET @admin_id = (SELECT id FROM `user` WHERE username = 'admin');
INSERT INTO `user` (username, password_hash, role, invite_code, registered_by, invite_uses)
VALUES (
    'ml_test_user',
    '$2b$12$K6bY7AOuZ5hB7g3Zt7D7bJZ7kG7r3JZ6bY7A$DWbQpX6g7e5n0', -- 密码：MLTest123!
    'ml_experimenter',
    'ML_TEST_001',
    @admin_id,
    0
);

-- 创建双角色测试用户（修正版）
SET @admin_id = (SELECT id FROM `user` WHERE username = 'admin');
INSERT INTO `user` (username, password_hash, role, invite_code, registered_by, invite_uses)
VALUES (
    'bio_ml_test',
    '$2b$12$3ZfK3i9LbXY5EqEixZaL4H3Xf7Y1Zg01d7MOYcQz6l', -- 密码：BioMLTest123!
    'biochemist', -- 若需双角色，需修改role字段类型为VARCHAR
    'BIO_ML_001',
    @admin_id,
    0
);

-- 创建永久有效的邀请码
INSERT INTO `user` (username, password_hash, role, invite_code, invite_uses)
VALUES (
    'invite_generator',
    '$2b$12$randomhashhere',
    'admin',
    'FOREVER_VALID_123',
    0
);

-- 创建索引
CREATE INDEX idx_enzyme_class ON wet_experiment (enzyme_class);
CREATE INDEX idx_username ON user (username);
CREATE INDEX idx_experiment_time ON wet_experiment (experiment_time);
CREATE INDEX idx_training_time ON ml_experiment (training_time);