import { createClient } from '@supabase/supabase-js'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

dotenv.config({ path: path.join(__dirname, '.env') })

const url = process.env.SUPABASE_URL
const key = process.env.SUPABASE_SERVICE_KEY

if (!url || !key) {
    console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY')
    process.exit(1)
}

const supabase = createClient(url, key)

async function check() {
    console.log('--- Checking Scans ---')
    const { data: scans, error: scanError } = await supabase
        .from('scans')
        .select('id, target_url, status, progress, findings_count, created_at')
        .order('created_at', { ascending: false })
        .limit(10)
    
    if (scanError) {
        console.error('❌ Error fetching scans:', scanError.message)
    } else {
        console.table(scans)
    }

    console.log('\n--- Checking Findings for Latest Scan ---')
    if (scans && scans.length > 0) {
        const latestId = scans[0].id
        const { data: findings, error: findError, count } = await supabase
            .from('findings')
            .select('*', { count: 'exact' })
            .eq('scan_id', latestId)
        
        if (findError) {
            console.error('❌ Error fetching findings:', findError.message)
        } else {
            console.log(`Found ${count} findings for scan ${latestId}`)
            if (findings.length > 0) {
                console.table(findings.slice(0, 5).map(f => ({
                    name: f.name,
                    severity: f.severity,
                    url: f.url
                })))
            }
        }
    }
}

check()
