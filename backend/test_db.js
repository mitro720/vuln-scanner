import { createClient } from '@supabase/supabase-js'
import dotenv from 'dotenv'
dotenv.config()

const url = process.env.SUPABASE_URL
const key = process.env.SUPABASE_SERVICE_KEY

console.log('Testing Supabase connection...')
console.log('URL:', url)

const supabase = createClient(url, key)

async function test() {
    try {
        const { data, error } = await supabase.from('scans').select('count').limit(1)
        if (error) {
            console.error('❌ Supabase Query Error:', error.message)
        } else {
            console.log('✅ Supabase Connection Successful!')
        }
    } catch (err) {
        console.error('❌ Supabase Fetch Error:', err.message)
    }
}

test()
