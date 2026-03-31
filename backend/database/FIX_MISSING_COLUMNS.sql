-- 1. Add missing columns to 'scans' table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS current_phase VARCHAR(100);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_count INTEGER DEFAULT 0;

-- 2. Add missing columns to 'findings' table (if using old schema)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp_category VARCHAR(10);

-- 3. Notify PostgREST to reload the schema cache
NOTIFY pgrst, 'reload schema';


-- 3. Verification
-- If you still see the error, click "Reload Schema" or "Reload Project" in the Supabase Dashboard.
