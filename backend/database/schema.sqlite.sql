-- SQLite Schema for Local Development
-- Run this with: sqlite3 scanner.db < schema.sqlite.sql

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  url TEXT NOT NULL,
  name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
  target_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  scan_type TEXT NOT NULL DEFAULT 'full',
  progress INTEGER DEFAULT 0,
  current_phase TEXT,
  started_at DATETIME,
  completed_at DATETIME,
  config TEXT DEFAULT '{}',
  metadata TEXT DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  owasp_category TEXT,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
  url TEXT,
  method TEXT,
  parameter TEXT,
  technique TEXT,
  evidence TEXT DEFAULT '{}',
  poc TEXT,
  remediation TEXT,
  cvss_score REAL,
  status TEXT DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
