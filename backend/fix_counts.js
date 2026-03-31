import { createClient } from '@supabase/supabase-js'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

dotenv.config({ path: path.join(__dirname, '.env') })

const url = process.env.SUPABASE_URL
const key = process.env.SUPABASE_SERVICE_KEY

const supabase = createClient(url, key)

async function fix() {
    console.log('🔄 Syncing findings counts...')
    
    // Get all scans
    const { data: scans } = await supabase.from('scans').select('id')
    
    for (const scan of scans) {
        const { count, data: findings } = await supabase
            .from('findings')
            .select('severity', { count: 'exact' })
            .eq('scan_id', scan.id)
        
        if (count > 0) {
            const sevCounts = {
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0
            }
            
            findings.forEach(f => {
                const key = `${f.severity.toLowerCase()}_count`
                if (sevCounts.hasOwnProperty(key)) {
                    sevCounts[key]++
                }
            })

            console.log(`Updating scan ${scan.id}: ${count} findings`)
            await supabase.from('scans').update({
                findings_count: count,
                ...sevCounts
            }).eq('id', scan.id)
        }
    }
    console.log('✅ Sync complete.')
}

fix()
