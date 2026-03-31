-- ========================================================
-- SecureScan - FULL DATABASE SCHEMA (Consolidated)
-- Run this in your Supabase SQL Editor
-- ========================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. CORE TABLES
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(50) DEFAULT 'user',
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS targets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  url VARCHAR(500) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
  target_url VARCHAR(500),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
  progress INTEGER DEFAULT 0,
  current_phase VARCHAR(100),
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  config JSONB DEFAULT '{}'::jsonb,
  metadata JSONB DEFAULT '{}'::jsonb,
  findings_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  owasp_category VARCHAR(10),
  name VARCHAR(255) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
  url TEXT,
  method VARCHAR(10),
  parameter VARCHAR(255),
  technique VARCHAR(100),
  evidence JSONB DEFAULT '{}'::jsonb,
  poc TEXT,
  remediation TEXT,
  cvss_score DECIMAL(3,1),
  status VARCHAR(50) DEFAULT 'open',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS crawl_graphs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  target_url VARCHAR(500) NOT NULL,
  nodes JSONB NOT NULL,
  edges JSONB NOT NULL,
  forms JSONB DEFAULT '[]'::jsonb,
  stats JSONB DEFAULT '{}'::jsonb,
  crawled_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. CVE & SERVICE TABLES
CREATE TABLE IF NOT EXISTS services (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  service_name VARCHAR(100) NOT NULL,
  version VARCHAR(100),
  banner TEXT,
  protocol VARCHAR(20) DEFAULT 'tcp',
  state VARCHAR(20) DEFAULT 'open',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cves (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  cvss_score DECIMAL(3,1),
  cvss_vector VARCHAR(200),
  severity VARCHAR(20),
  published_date TIMESTAMP WITH TIME ZONE,
  last_modified_date TIMESTAMP WITH TIME ZONE,
  "references" JSONB DEFAULT '[]'::jsonb,
  cwe_ids JSONB DEFAULT '[]'::jsonb,
  affected_products JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_cves (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  service_id UUID REFERENCES services(id) ON DELETE CASCADE,
  cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100) DEFAULT 100,
  match_type VARCHAR(50),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(service_id, cve_id)
);

-- 4. UTILITIES
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

-- 5. INDEXES
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);

-- 6. SECURITY BLOC - Disable RLS for Local Development
ALTER TABLE targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
ALTER TABLE crawl_graphs DISABLE ROW LEVEL SECURITY;
ALTER TABLE services DISABLE ROW LEVEL SECURITY;
ALTER TABLE cves DISABLE ROW LEVEL SECURITY;
ALTER TABLE service_cves DISABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans DISABLE ROW LEVEL SECURITY;

-- DONE!
