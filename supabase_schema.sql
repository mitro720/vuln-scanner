-- Users table for authentication and admin approval
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scans table to track individual scan runs
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    progress INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    config JSONB DEFAULT '{}'::jsonb,
    current_phase TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Findings table to store discovered vulnerabilities
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    cvss_score NUMERIC(3,1),
    poc TEXT,
    evidence JSONB,
    remediation TEXT,
    owasp TEXT,
    url TEXT,
    confidence INTEGER,
    service_name TEXT,
    cwe TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optional: Targets table if you want to explicitly map domains/assets monitored
CREATE TABLE IF NOT EXISTS public.targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    last_scanned TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, url)
);

-- Services table for detailed port/service tracking
CREATE TABLE IF NOT EXISTS public.services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT,
    service_name TEXT,
    version TEXT,
    product TEXT,
    extra_info TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
