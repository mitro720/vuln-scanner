-- Migration: 002_create_scans_table.sql
-- Description: Creates the scans table for storing scan records

CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  target_url VARCHAR(500), -- Direct URL for quick scans without target record
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
  scan_type VARCHAR(50) NOT NULL DEFAULT 'full', -- quick, full, custom
  progress INTEGER DEFAULT 0,
  current_phase VARCHAR(100), -- Current scan phase for live updates
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  config JSONB DEFAULT '{}'::jsonb,
  metadata JSONB DEFAULT '{}'::jsonb,
  findings_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
