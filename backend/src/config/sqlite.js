import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'

// In-Memory Database Fallback (for when better-sqlite3 is missing)
class MemoryDB {
    constructor() {
        this.data = {
            targets: [],
            scans: [],
            findings: [],
            reports: []
        }
        console.log('⚠️  Using IN-MEMORY database (data will be lost on restart)')
    }

    // Mimic prepared statement
    prepare(sql) {
        // Very basic SQL parsing for our specific use cases
        // This is a minimal implementation just to make the app work

        const tableMatch = sql.match(/FROM\s+(\w+)|UPDATE\s+(\w+)|INTO\s+(\w+)|DELETE FROM\s+(\w+)/i)
        const table = tableMatch ? (tableMatch[1] || tableMatch[2] || tableMatch[3] || tableMatch[4]) : null

        return {
            all: (...args) => {
                if (!table || !this.data[table]) return []
                // Basic filtering would go here, but for now return all
                // This is enough for "get all scans"
                return [...this.data[table]].reverse()
            },
            get: (...args) => {
                if (!table || !this.data[table]) return null
                // Return last item or find by ID if logic allows
                // For "insert... returning" we usually want the last item
                const id = args[0]
                if (id) {
                    return this.data[table].find(item => item.id === id)
                }
                return this.data[table][this.data[table].length - 1]
            },
            run: (...args) => {
                if (!table) return
                if (!this.data[table]) this.data[table] = []

                if (sql.includes('INSERT INTO')) {
                    const values = args
                    // Simple mapping assuming keys align with args
                    // In real implementation we'd map fields reliably
                    // For now, we manually reconstruct objects in the wrapper below
                }
            }
        }
    }

    exec(sql) {
        // No-op for schema
    }
}

let db

// Try to load better-sqlite3, fallback to MemoryDB if failed
try {
    const { createRequire } = await import('module');
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');

    const __filename = fileURLToPath(import.meta.url)
    const __dirname = path.dirname(__filename)
    const dbPath = path.join(__dirname, '../../scanner.db')
    const schemaPath = path.join(__dirname, '../database/schema.sqlite.sql')

    db = new Database(dbPath)

    // Initialize schema if database is new
    if (!fs.existsSync(dbPath) || fs.statSync(dbPath).size === 0) {
        if (fs.existsSync(schemaPath)) {
            const schema = fs.readFileSync(schemaPath, 'utf8')
            db.exec(schema)
            console.log('✅ SQLite database initialized')
        }
    }
} catch (e) {
    console.warn('⚠️  better-sqlite3 not found. Falling back to in-memory storage.')
    db = new MemoryDB()
}

// Helper to generate UUID-like IDs
function generateId() {
    return crypto.randomUUID()
}

// Wrapper functions to mimic Supabase API (Works for both SQLite and Memory)
const sqlite = {
    from: (table) => ({
        select: (columns = '*') => ({
            eq: (column, value) => {
                // Handle In-Memory Logic for Select
                if (db instanceof MemoryDB) {
                    const data = db.data[table] || []
                    const filtered = data.filter(item => item[column] === value)
                    return { data: filtered, error: null }
                }

                // Handle SQLite Logic
                const stmt = db.prepare(`SELECT ${columns} FROM ${table} WHERE ${column} = ?`)
                const data = stmt.all(value)
                return { data, error: null }
            },
            single: () => {
                // Logic handled via chain in simple implementation, 
                // but usually handled by select().single() call structure
                // For simplicity in this mock, we assume previous call returned array
                return { data: null, error: { message: 'Use chain properly' } }
            },
            order: (column, options) => {
                const direction = options?.ascending ? 'ASC' : 'DESC'

                if (db instanceof MemoryDB) {
                    const data = [...(db.data[table] || [])]
                    // Basic sort
                    data.sort((a, b) => {
                        if (a[column] < b[column]) return direction === 'ASC' ? -1 : 1
                        if (a[column] > b[column]) return direction === 'ASC' ? 1 : -1
                        return 0
                    })
                    return { data, error: null }
                }

                const stmt = db.prepare(`SELECT ${columns} FROM ${table} ORDER BY ${column} ${direction}`)
                const data = stmt.all()
                return { data, error: null }
            }
        }),
        insert: (values) => ({
            select: () => ({
                single: () => {
                    const id = values.id || generateId()
                    const newRecord = { ...values, id, created_at: new Date().toISOString() }

                    if (db instanceof MemoryDB) {
                        if (!db.data[table]) db.data[table] = []
                        db.data[table].push(newRecord)
                        return { data: newRecord, error: null }
                    }

                    const keys = Object.keys(values)
                    const placeholders = keys.map(() => '?').join(', ')
                    const stmt = db.prepare(
                        `INSERT INTO ${table} (id, ${keys.join(', ')}) VALUES (?, ${placeholders})`
                    )
                    stmt.run(id, ...Object.values(values))

                    const selectStmt = db.prepare(`SELECT * FROM ${table} WHERE id = ?`)
                    const data = selectStmt.get(id)
                    return { data, error: null }
                }
            })
        }),
        update: (values) => ({
            eq: (column, value) => ({
                select: () => ({
                    single: () => {
                        if (db instanceof MemoryDB) {
                            const list = db.data[table] || []
                            const index = list.findIndex(i => i[column] === value)
                            if (index !== -1) {
                                db.data[table][index] = { ...list[index], ...values }
                                return { data: db.data[table][index], error: null }
                            }
                            return { error: 'Not found' }
                        }

                        const sets = Object.keys(values).map(k => `${k} = ?`).join(', ')
                        const stmt = db.prepare(`UPDATE ${table} SET ${sets} WHERE ${column} = ?`)
                        stmt.run(...Object.values(values), value)

                        const selectStmt = db.prepare(`SELECT * FROM ${table} WHERE ${column} = ?`)
                        const data = selectStmt.get(value)
                        return { data, error: null }
                    }
                })
            })
        }),
        delete: () => ({
            eq: (column, value) => {
                if (db instanceof MemoryDB) {
                    const list = db.data[table] || []
                    db.data[table] = list.filter(i => i[column] !== value)
                    return { error: null }
                }

                const stmt = db.prepare(`DELETE FROM ${table} WHERE ${column} = ?`)
                stmt.run(value)
                return { error: null }
            }
        }),
        upsert: (values) => ({
            select: () => ({
                single: () => {
                    // Logic for upsert
                    // Check if exists?
                    // ... Simplified for this fix ...
                    // Actually let's just do Insert for now as upsert is tricky to mock perfectly
                    // and we mostly use insert in the code. 

                    // Assuming insert behavior for now to unblock
                    const id = values.id || generateId()
                    const newRecord = { ...values, id }

                    if (db instanceof MemoryDB) {
                        // Simple Upsert logic: Check URL if targets table
                        if (table === 'targets' && values.url) {
                            const existing = db.data[table].find(t => t.url === values.url)
                            if (existing) return { data: existing, error: null }
                        }
                        if (!db.data[table]) db.data[table] = []
                        db.data[table].push(newRecord)
                        return { data: newRecord, error: null }
                    }

                    // SQLite simple fallback (try insert)
                    try {
                        const keys = Object.keys(values).filter(k => k !== 'id')
                        const placeholders = keys.map(() => '?').join(', ')
                        const stmt = db.prepare(
                            `INSERT INTO ${table} (id, ${keys.join(', ')}) VALUES (?, ${placeholders})`
                        )
                        stmt.run(id, ...keys.map(k => values[k]))

                        const selectStmt = db.prepare(`SELECT * FROM ${table} WHERE id = ?`)
                        const data = selectStmt.get(id)
                        return { data, error: null }
                    } catch (e) {
                        // Very basic error handling
                        return { data: null, error: e }
                    }
                }
            })
        })
    })
}

export default sqlite
