import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import supabase from '../config/supabase.js'

const JWT_SECRET = process.env.JWT_SECRET || 'securescan-secret-key-123'

export const login = async (req, res) => {
    const { username, password } = req.body

    try {
        const { data: users, error } = await supabase.from('users').select('*').eq('username', username)
        
        if (error || !users || users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        const user = users[0]
        // Block only if explicitly 'pending' or 'suspended'
        if (user.status === 'pending' || user.status === 'suspended') {
            return res.status(403).json({ error: 'Account pending admin approval' })
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password_hash)
        
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        )

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        })
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message })
    }
}

export const register = async (req, res) => {
    const { username, password } = req.body

    try {
        // Check if exists
        const { data: existing } = await supabase.from('users').select('*').eq('username', username)
        if (existing && existing.length > 0) {
            return res.status(400).json({ error: 'Username already taken' })
        }

        const salt = await bcrypt.genSalt(10)
        const password_hash = await bcrypt.hash(password, salt)

        // default to 'user' role and 'pending' status
        const { data: user, error } = await supabase.from('users').insert({
            username,
            password_hash,
            role: 'user',
            status: 'pending'
        }).select().single()

        if (error) throw new Error(error)

        res.status(201).json({
            message: 'Registration successful. Account pending admin approval.'
        })
    } catch (err) {
        res.status(500).json({ error: 'Registration failed', details: err.message })
    }
}


export const getMe = async (req, res) => {
    try {
        const { data: users, error } = await supabase.from('users').select('*').eq('id', req.user.id)
        
        if (error || !users || users.length === 0) {
            return res.status(404).json({ error: 'User not found' })
        }

        const user = users[0]
        res.json({
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                status: user.status
            }
        })
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch user' })
    }
}

// Seed admin user if none exists
export const seedAdmin = async () => {
    try {
        const { data: users } = await supabase.from('users').select('*').eq('username', 'admin')
        if (users && users.length > 0) return

        const salt = await bcrypt.genSalt(10)
        const password_hash = await bcrypt.hash('admin123', salt)
        
        await supabase.from('users').insert({
            username: 'admin',
            password_hash,
            role: 'admin',
            status: 'active'
        }).select().single()
        
        console.log('✅ Default admin user created (admin/admin123)')
    } catch (err) {
        console.error('❌ Failed to seed admin:', err.message)
    }
}
