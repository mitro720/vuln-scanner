-- CVE Database Integration - Migration 001
-- Adds tables for storing detected services and CVE information

-- Services table - stores detected services with version information
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

-- CVEs table - caches CVE data to reduce API calls
CREATE TABLE IF NOT EXISTS cves (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  cvss_score DECIMAL(3,1),
  cvss_vector VARCHAR(200),
  severity VARCHAR(20), -- critical, high, medium, low
  published_date TIMESTAMP WITH TIME ZONE,
  last_modified_date TIMESTAMP WITH TIME ZONE,
  "references" JSONB DEFAULT '[]'::jsonb,
  cwe_ids JSONB DEFAULT '[]'::jsonb,
  affected_products JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Service CVEs junction table - many-to-many relationship
CREATE TABLE IF NOT EXISTS service_cves (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  service_id UUID REFERENCES services(id) ON DELETE CASCADE,
  cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100) DEFAULT 100,
  match_type VARCHAR(50), -- exact, version_range, banner_match
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(service_id, cve_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);
CREATE INDEX IF NOT EXISTS idx_services_service_name ON services(service_name);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_service_cves_service_id ON service_cves(service_id);
CREATE INDEX IF NOT EXISTS idx_service_cves_cve_id ON service_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_service_cves_scan_id ON service_cves(scan_id);

-- Updated_at triggers
CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON services
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cves_updated_at BEFORE UPDATE ON cves
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies
ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_cves ENABLE ROW LEVEL SECURITY;

-- Services policies (accessible through scans)
CREATE POLICY "Users can view services from their scans"
  ON services FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = services.scan_id
      AND scans.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can insert services from their scans"
  ON services FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = services.scan_id
      AND scans.user_id = auth.uid()
    )
  );

-- CVEs policies (public read for cached data)
CREATE POLICY "Anyone can view CVEs"
  ON cves FOR SELECT
  USING (true);

CREATE POLICY "System can insert CVEs"
  ON cves FOR INSERT
  WITH CHECK (true);

CREATE POLICY "System can update CVEs"
  ON cves FOR UPDATE
  USING (true);

-- Service CVEs policies (accessible through scans)
CREATE POLICY "Users can view service CVEs from their scans"
  ON service_cves FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = service_cves.scan_id
      AND scans.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can insert service CVEs from their scans"
  ON service_cves FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = service_cves.scan_id
      AND scans.user_id = auth.uid()
    )
  );
