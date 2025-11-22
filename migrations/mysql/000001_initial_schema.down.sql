-- Rollback initial schema for MySQL

-- Drop tables (in reverse order due to foreign keys)
DROP TABLE IF EXISTS secondary_storage;
DROP TABLE IF EXISTS verifications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
