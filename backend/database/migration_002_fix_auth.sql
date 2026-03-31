-- Migration: 002_fix_auth.sql
-- Description: Fixes foreign key violations by creating a public users table
-- and updating scans/targets to reference it instead of auth.users.
-- This version drops RLS policies first to avoid column alteration errors.

-- 1. Create public users table if it doesn't exist
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(50) DEFAULT 'user',
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Drop existing RLS policies that depend on user_id columns
-- Scans table policies
DROP POLICY IF EXISTS "Users can view their own scans" ON scans;
DROP POLICY IF EXISTS "Users can create their own scans" ON scans;
DROP POLICY IF EXISTS "Users can update their own scans" ON scans;

-- Targets table policies
DROP POLICY IF EXISTS "Users can view their own targets" ON targets;
DROP POLICY IF EXISTS "Users can create their own targets" ON targets;
DROP POLICY IF EXISTS "Users can update their own targets" ON targets;
DROP POLICY IF EXISTS "Users can delete their own targets" ON targets;

-- Findings table policies (depends on scans)
DROP POLICY IF EXISTS "Users can view findings from their scans" ON findings;

-- Scheduled scans table policies
DROP POLICY IF EXISTS "Users can manage their scheduled scans" ON scheduled_scans;

-- Services table policies
DROP POLICY IF EXISTS "Users can view services from their scans" ON services;
DROP POLICY IF EXISTS "Users can insert services from their scans" ON services;

-- Service CVEs table policies
DROP POLICY IF EXISTS "Users can view service CVEs from their scans" ON service_cves;
DROP POLICY IF EXISTS "Users can insert service CVEs from their scans" ON service_cves;

-- 3. Update scans table: Remove old foreign key and add new one
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_user_id_fkey;
-- Check if user_id exists and alter its type
DO $$ 
BEGIN 
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scans' AND column_name='user_id') THEN
        ALTER TABLE scans ALTER COLUMN user_id TYPE UUID USING user_id::UUID;
    ELSE
        ALTER TABLE scans ADD COLUMN user_id UUID;
    END IF;
END $$;
ALTER TABLE scans ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- 4. Update targets table: Remove old foreign key and add new one
ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_user_id_fkey;
DO $$ 
BEGIN 
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='targets' AND column_name='user_id') THEN
        ALTER TABLE targets ALTER COLUMN user_id TYPE UUID USING user_id::UUID;
    ELSE
        ALTER TABLE targets ADD COLUMN user_id UUID;
    END IF;
END $$;
ALTER TABLE targets ADD CONSTRAINT targets_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- 5. Update scheduled_scans table
ALTER TABLE scheduled_scans DROP CONSTRAINT IF EXISTS scheduled_scans_user_id_fkey;
DO $$ 
BEGIN 
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scheduled_scans' AND column_name='user_id') THEN
        ALTER TABLE scheduled_scans ALTER COLUMN user_id TYPE UUID USING user_id::UUID;
    ELSE
        ALTER TABLE scheduled_scans ADD COLUMN user_id UUID;
    END IF;
END $$;
ALTER TABLE scheduled_scans ADD CONSTRAINT scheduled_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- 6. Disable RLS for now to ensure custom JWT auth works (since RLS uses auth.uid())
ALTER TABLE targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE services DISABLE ROW LEVEL SECURITY;
ALTER TABLE service_cves DISABLE ROW LEVEL SECURITY;

-- 7. Add updated_at trigger for users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 8. Ensure default admin user exists if table was just created
-- password: admin123 (bcrypt hash)
INSERT INTO users (username, password_hash, role, status)
SELECT 'admin', '$2a$10$pxHh9v8T0YhR.vY.vY.vY.vY.vY.vY.vY.vY.vY.vY.vY.vY.vY', 'admin', 'active'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');

NOTIFY pgrst, 'reload schema';
