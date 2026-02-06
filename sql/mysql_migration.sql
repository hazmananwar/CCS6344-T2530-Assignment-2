-- sql/mysql_migration.sql
-- MySQL 8 migration schema (RDS MySQL compatible)
-- Includes: tables, triggers, stored procedures, "RLS-like" view using session variables.

CREATE DATABASE IF NOT EXISTS StudentProjectDB;
USE StudentProjectDB;

-- ======================
-- TABLES (App_*)
-- ======================
CREATE TABLE IF NOT EXISTS App_Roles (
  RoleID INT AUTO_INCREMENT PRIMARY KEY,
  RoleName VARCHAR(50) UNIQUE NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS App_Users (
  UserID INT AUTO_INCREMENT PRIMARY KEY,
  Username VARCHAR(50) UNIQUE NOT NULL,
  PasswordHash VARCHAR(256) NOT NULL,
  Salt VARCHAR(50) NOT NULL,
  Email VARCHAR(100) NULL,
  EncryptedPhone VARBINARY(255) NULL,
  RoleID INT NOT NULL,
  PDPA_Consent TINYINT(1) DEFAULT 0,
  CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_users_role FOREIGN KEY (RoleID) REFERENCES App_Roles(RoleID)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS App_Assignments (
  AssignmentID INT AUTO_INCREMENT PRIMARY KEY,
  ProjectTitle VARCHAR(100),
  Description VARCHAR(255),
  GitHubLink VARCHAR(200),
  SubmittedBy INT NOT NULL,
  SubmissionDate DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_assign_user FOREIGN KEY (SubmittedBy) REFERENCES App_Users(UserID)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS App_Milestones (
  MilestoneID INT AUTO_INCREMENT PRIMARY KEY,
  AssignmentID INT NOT NULL,
  TaskName VARCHAR(100),
  IsCompleted TINYINT(1) DEFAULT 0,
  CONSTRAINT fk_milestone_assign FOREIGN KEY (AssignmentID)
    REFERENCES App_Assignments(AssignmentID) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS App_Notifications (
  NotifID INT AUTO_INCREMENT PRIMARY KEY,
  UserID INT NOT NULL,
  Message VARCHAR(255),
  IsRead TINYINT(1) DEFAULT 0,
  DateCreated DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_notif_user FOREIGN KEY (UserID) REFERENCES App_Users(UserID)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS App_Feedback (
  FeedbackID INT AUTO_INCREMENT PRIMARY KEY,
  SubmittedBy INT NOT NULL,
  IssueType VARCHAR(50),
  Message TEXT,
  DateCreated DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_feedback_user FOREIGN KEY (SubmittedBy) REFERENCES App_Users(UserID)
) ENGINE=InnoDB;

-- ======================
-- TABLES (Sec_*)
-- ======================
CREATE TABLE IF NOT EXISTS Sec_AuditLog (
  AuditID INT AUTO_INCREMENT PRIMARY KEY,
  ActionType VARCHAR(50),
  TableName VARCHAR(50),
  RecordID INT,
  UserID INT,
  UserIP VARCHAR(50),
  Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  Details VARCHAR(255)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Sec_SystemConfig (
  ConfigKey VARCHAR(50) PRIMARY KEY,
  ConfigValue VARCHAR(50)
) ENGINE=InnoDB;

-- Seed roles/config
INSERT INTO App_Roles (RoleName) VALUES ('Admin'),('Lecturer'),('Student'),('External Examiner')
ON DUPLICATE KEY UPDATE RoleName=VALUES(RoleName);

INSERT INTO Sec_SystemConfig (ConfigKey, ConfigValue)
VALUES ('AllowUploads', 'TRUE')
ON DUPLICATE KEY UPDATE ConfigValue=VALUES(ConfigValue);

-- ======================
-- TRIGGERS (split insert/delete)
-- ======================
DROP TRIGGER IF EXISTS trg_AuditAssignments_Insert;
DROP TRIGGER IF EXISTS trg_AuditAssignments_Delete;

DELIMITER $$

CREATE TRIGGER trg_AuditAssignments_Insert
AFTER INSERT ON App_Assignments
FOR EACH ROW
BEGIN
  INSERT INTO Sec_AuditLog (ActionType, TableName, RecordID, Details)
  VALUES ('INSERT_PROJECT', 'Assignments', NEW.AssignmentID, NEW.ProjectTitle);

  INSERT INTO App_Notifications (UserID, Message)
  SELECT UserID, 'New project submitted!'
  FROM App_Users
  WHERE RoleID = 2;
END$$

CREATE TRIGGER trg_AuditAssignments_Delete
AFTER DELETE ON App_Assignments
FOR EACH ROW
BEGIN
  INSERT INTO Sec_AuditLog (ActionType, TableName, RecordID, Details)
  VALUES ('DELETE_PROJECT', 'Assignments', OLD.AssignmentID, OLD.ProjectTitle);
END$$

DELIMITER ;

-- ======================
-- STORED PROCEDURES
-- ======================
DROP PROCEDURE IF EXISTS Sec_sp_RegisterUser;
DROP PROCEDURE IF EXISTS Sec_sp_GetUserAuth;
DROP PROCEDURE IF EXISTS Sec_sp_GetUserProfile;

DELIMITER $$

-- Register user with AES_ENCRYPT for phone (encryption key passed in)
CREATE PROCEDURE Sec_sp_RegisterUser(
  IN pUsername VARCHAR(50),
  IN pPassHash VARCHAR(256),
  IN pSalt VARCHAR(50),
  IN pEmail VARCHAR(100),
  IN pPhone VARCHAR(20),
  IN pRoleID INT,
  IN pEncKey VARCHAR(128)
)
BEGIN
  INSERT INTO App_Users
    (Username, PasswordHash, Salt, Email, EncryptedPhone, RoleID, PDPA_Consent)
  VALUES
    (pUsername, pPassHash, pSalt, pEmail, AES_ENCRYPT(pPhone, pEncKey), pRoleID, 1);
END$$

-- Auth for login (no decrypt needed)
CREATE PROCEDURE Sec_sp_GetUserAuth(
  IN pUsername VARCHAR(50)
)
BEGIN
  SELECT UserID, PasswordHash, Salt, RoleID
  FROM App_Users
  WHERE Username = pUsername;
END$$

-- Optional profile fetch (decrypt phone if needed)
CREATE PROCEDURE Sec_sp_GetUserProfile(
  IN pUsername VARCHAR(50),
  IN pEncKey VARCHAR(128)
)
BEGIN
  SELECT
    UserID, Username, Email, RoleID,
    CAST(AES_DECRYPT(EncryptedPhone, pEncKey) AS CHAR(50)) AS Phone
  FROM App_Users
  WHERE Username = pUsername;
END$$

DELIMITER ;

-- ======================
-- "RLS-like" VIEW using session variables
-- ======================
-- Your app must run:
--   SET @app_user_id = <session user id>;
--   SET @app_role_id = <session role id>;
-- before selecting from this view.
DROP VIEW IF EXISTS App_Assignments_RLS;

CREATE VIEW App_Assignments_RLS AS
SELECT *
FROM App_Assignments
WHERE
  (@app_role_id IN (1,2,4))
  OR
  (@app_role_id = 3 AND SubmittedBy = @app_user_id);
