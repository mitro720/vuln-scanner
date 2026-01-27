-- First, check if the column exists, and add it if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scans' AND column_name = 'target_url'
    ) THEN
        ALTER TABLE scans ADD COLUMN target_url VARCHAR(500);
    END IF;
END $$;

-- Verify the column was added
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'scans'
ORDER BY ordinal_position;
