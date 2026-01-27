# Database Migrations

This folder contains modular SQL migration files for the vulnerability scanner database.

## Migration Order

Run migrations in numerical order:

1. **000_enable_extensions.sql** - Enable UUID extension
2. **001_create_targets_table.sql** - Create targets table
3. **002_create_scans_table.sql** - Create scans table
4. **003_create_findings_table.sql** - Create findings table
5. **004_create_reports_table.sql** - Create reports table
6. **005_create_triggers.sql** - Create automatic timestamp triggers
7. **006_enable_rls.sql** - Enable Row Level Security (optional for testing)

## Quick Setup for Supabase

### Option 1: Run All Migrations at Once
Copy and paste the contents of each file in order into the Supabase SQL Editor.

### Option 2: Run Individual Migrations
Run each migration file separately in the SQL Editor for better control and debugging.

### For Testing Without Authentication
Skip migration `006_enable_rls.sql` or run this to disable RLS:
```sql
ALTER TABLE targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
```

## Adding New Migrations

When adding new features:
1. Create a new migration file with the next number (e.g., `007_add_new_feature.sql`)
2. Add a description comment at the top
3. Update this README with the new migration
4. Run the migration in Supabase SQL Editor

## Schema Changes

If you need to modify existing tables:
- Create a new migration file (don't edit old ones)
- Use `ALTER TABLE` statements
- Example: `007_add_column_to_scans.sql`
