-- Migration: 003_create_findings_table.sql
-- Description: Creates the findings table for storing vulnerability findings

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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
