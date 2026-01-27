# Database Setup Guide

## Quick Start (SQLite - No Setup Required)
The app will automatically use SQLite if Supabase isn't configured. Just run `npm start` and you're good to go!

## Production Setup (Supabase)

### 1. Create Supabase Project
1. Go to [supabase.com](https://supabase.com)
2. Create a free account
3. Click "New Project"
4. Choose a name and password

### 2. Run Database Schema
1. In Supabase Dashboard, go to **SQL Editor**
2. Copy the contents of `backend/database/schema.sql`
3. Paste and click **Run**

### 3. Get API Credentials
1. Go to **Project Settings** → **API**
2. Copy:
   - Project URL
   - `anon` public key
   - `service_role` secret key (keep this private!)

### 4. Configure Environment
1. Copy `backend/.env.example` to `backend/.env`
2. Fill in your Supabase credentials:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_KEY=your_service_role_key_here
```

### 5. Disable Row Level Security (For Testing)
Since we don't have authentication yet, disable RLS:
```sql
ALTER TABLE targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
```

### 6. Restart the App
```bash
npm start
```

## Schema Updates
Both `schema.sql` (Supabase/PostgreSQL) and `schema.sqlite.sql` (SQLite) are kept in sync.

When adding new fields:
1. Update both schema files
2. For Supabase: Run migration in SQL Editor
3. For SQLite: Delete `scanner.db` and restart (auto-recreates)

## Current Schema Version
- `target_url` field added to `scans` table (allows scanning without creating target records)
- `current_phase` field added to `scans` table (for live scan progress)
- `technique` field added to `findings` table (stores attack technique details)
