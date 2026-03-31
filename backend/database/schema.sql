-- SecureScan Database Schema for Supabase (PostgreSQL)

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (Custom authentication)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(50) DEFAULT 'user',
  status VARCHAR(50) DEFAULT 'pending', -- pending, active, suspended
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  url VARCHAR(500) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  target_url VARCHAR(500), -- Direct URL for quick scans without target record
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
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

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  owasp_category VARCHAR(10), -- A01, A02, etc.
  name VARCHAR(255) NOT NULL,
  severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
  confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
  url TEXT,
  method VARCHAR(10), -- GET, POST, etc.
  parameter VARCHAR(255),
  technique VARCHAR(100), -- Attack technique used (e.g., "Boolean-based blind")
  evidence JSONB DEFAULT '{}'::jsonb,
  poc TEXT,
  remediation TEXT,
  cvss_score DECIMAL(3,1),
  status VARCHAR(50) DEFAULT 'open', -- open, false_positive, fixed, accepted
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan comparisons table
CREATE TABLE IF NOT EXISTS scan_comparisons (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  scan_id_old UUID REFERENCES scans(id) ON DELETE CASCADE,
  scan_id_new UUID REFERENCES scans(id) ON DELETE CASCADE,
  new_findings INTEGER DEFAULT 0,
  fixed_findings INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scheduled scans table
CREATE TABLE IF NOT EXISTS scheduled_scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  cron_expression VARCHAR(100) NOT NULL,
  scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
  config JSONB DEFAULT '{}'::jsonb,
  is_active BOOLEAN DEFAULT true,
  last_run TIMESTAMP WITH TIME ZONE,
  next_run TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  format VARCHAR(20) NOT NULL, -- pdf, html, json
  file_path VARCHAR(500),
  generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_targets_user_id ON targets(user_id);

-- Updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON targets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scheduled_scans_updated_at BEFORE UPDATE ON scheduled_scans
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) - Disabled for Custom Auth
ALTER TABLE targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans DISABLE ROW LEVEL SECURITY;
