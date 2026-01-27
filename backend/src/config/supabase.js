import { createClient } from '@supabase/supabase-js'
import dotenv from 'dotenv'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import sqlite from './sqlite.js'

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

let dbClient

// Check if valid Supabase credentials exist
const isPlaceholder = (val) => !val || val.includes('placeholder') || val.includes('your_supabase')

const hasSupabase = process.env.SUPABASE_URL &&
    !isPlaceholder(process.env.SUPABASE_URL) &&
    process.env.SUPABASE_SERVICE_KEY &&
    !isPlaceholder(process.env.SUPABASE_SERVICE_KEY)

if (hasSupabase) {
    console.log('🔌 Connected to Supabase')
    try {
        dbClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
    } catch (e) {
        console.warn('⚠️  Supabase connection failed. Falling back to local database.')
        dbClient = sqlite
    }
} else {
    // Fallback to SQLite
    console.warn('⚠️  Supabase not configured (or using placeholders). Using local In-Memory database.')
    dbClient = sqlite
}

export const supabase = dbClient
export default dbClient
