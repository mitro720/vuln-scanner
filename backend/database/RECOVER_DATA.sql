-- SecureScan Data Recovery Script
-- Use this to reassign "orphaned" scans and targets to your new admin user.
-- This is necessary because the User IDs changed when we switched to custom authentication.

-- 1. Reassign all scans that have missing or invalid user_ids to the 'admin' user
UPDATE scans 
SET user_id = (SELECT id FROM users WHERE username = 'admin' LIMIT 1)
WHERE user_id IS NULL 
   OR user_id NOT IN (SELECT id FROM users);

-- 2. Reassign all targets to the 'admin' user
UPDATE targets 
SET user_id = (SELECT id FROM users WHERE username = 'admin' LIMIT 1)
WHERE user_id IS NULL 
   OR user_id NOT IN (SELECT id FROM users);

-- 3. Reassign all scheduled scans to the 'admin' user
UPDATE scheduled_scans 
SET user_id = (SELECT id FROM users WHERE username = 'admin' LIMIT 1)
WHERE user_id IS NULL 
   OR user_id NOT IN (SELECT id FROM users);

-- 4. Verify the changes
SELECT 'Scans reassigned' as status, COUNT(*) as count FROM scans WHERE user_id = (SELECT id FROM users WHERE username = 'admin' LIMIT 1);
