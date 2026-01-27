-- Migration: 006_enable_rls.sql
-- Description: Enables Row Level Security and creates policies
-- NOTE: For testing without authentication, you can skip this migration

-- Enable Row Level Security
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- Targets policies
CREATE POLICY "Users can view their own targets"
  ON targets FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own targets"
  ON targets FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own targets"
  ON targets FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own targets"
  ON targets FOR DELETE
  USING (auth.uid() = user_id);

-- Scans policies
CREATE POLICY "Users can view their own scans"
  ON scans FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own scans"
  ON scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans"
  ON scans FOR UPDATE
  USING (auth.uid() = user_id);

-- Findings policies (accessible through scans)
CREATE POLICY "Users can view findings from their scans"
  ON findings FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = findings.scan_id
      AND scans.user_id = auth.uid()
    )
  );
