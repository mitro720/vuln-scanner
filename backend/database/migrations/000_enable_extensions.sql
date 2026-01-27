-- Migration: 000_enable_extensions.sql
-- Description: Enables required PostgreSQL extensions
-- Run this FIRST before any other migrations

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
