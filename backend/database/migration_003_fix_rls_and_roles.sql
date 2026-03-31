-- ========================================================
-- Migration 003: Fix RLS, roles, and broken trigger
-- Run this in your Supabase SQL Editor
-- ========================================================

-- 0. Fix the broken trigger: either add the column or drop the trigger
-- Option A: Add updated_at column so the trigger works
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- 1. Disable RLS on all app tables so backend (service_role key) works cleanly
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings DISABLE ROW LEVEL SECURITY;

-- Disable RLS on crawl_graphs only if the table exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'crawl_graphs') THEN
        EXECUTE 'ALTER TABLE public.crawl_graphs DISABLE ROW LEVEL SECURITY';
    END IF;
END $$;

-- 2. Normalize roles: 'user' -> 'member'
UPDATE public.users SET role = 'member' WHERE role = 'user';

-- 3. Ensure status defaults and fix nulls
ALTER TABLE public.users ALTER COLUMN status SET DEFAULT 'active';
UPDATE public.users SET status = 'active' WHERE status IS NULL;

-- 4. Ensure admin user is active
UPDATE public.users SET status = 'active', role = 'admin' WHERE username = 'admin';

-- 5. Verify
SELECT id, username, role, status, created_at FROM public.users ORDER BY created_at;
