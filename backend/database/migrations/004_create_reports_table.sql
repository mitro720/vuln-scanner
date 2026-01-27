-- Migration: 004_create_reports_table.sql
-- Description: Creates the reports table for storing generated reports

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  format VARCHAR(20) NOT NULL, -- pdf, html, json
  file_path VARCHAR(500),
  generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
