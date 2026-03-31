import bcrypt from 'bcryptjs'
import supabase from '../config/supabase.js'

export const getAllUsers = async (req, res) => {
    try {
        const { data: users, error } = await supabase.from('users').select('*').order('created_at', { ascending: false })
        
        if (error) throw error

        const safeUsers = users.map(u => ({
            id: u.id,
            username: u.username,
            role: u.role,
            status: u.status,
            created_at: u.created_at
        }))

        res.json({ success: true, data: safeUsers })
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to fetch users' })
    }
}

export const createUser = async (req, res) => {
    const { username, password, role } = req.body

    if (!username || !password) {
        return res.status(400).json({ success: false, error: 'Username and password are required' })
    }

    try {
        // Check if user exists
        const { data: existing } = await supabase.from('users').select('*').eq('username', username)
        if (existing && existing.length > 0) {
            return res.status(400).json({ success: false, error: 'Username already exists' })
        }

        const salt = await bcrypt.genSalt(10)
        const password_hash = await bcrypt.hash(password, salt)

        const { data: user, error } = await supabase.from('users').insert({
            username,
            password_hash,
            role: role || 'member',
            status: 'active' // admin created users are active instantly
        }).select().single()

        if (error) throw error

        res.status(201).json({
            success: true,
            data: {
                id: user.id,
                username: user.username,
                role: user.role,
                created_at: user.created_at
            }
        })
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to create user', details: err.message })
    }
}

export const deleteUser = async (req, res) => {
    const { id } = req.params

    // Prevent self-deletion
    if (id === req.user.id) {
        return res.status(400).json({ success: false, error: 'Cannot delete your own account' })
    }

    try {
        const { error } = await supabase.from('users').delete().eq('id', id)
        if (error) throw error

        res.json({ success: true, message: 'User deleted successfully' })
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to delete user' })
    }
}

export const updateUserRole = async (req, res) => {
    const { id } = req.params
    const { role } = req.body

    if (!['admin', 'member', 'user'].includes(role)) {
        return res.status(400).json({ success: false, error: 'Invalid role. Must be admin, member, or user.' })
    }

    try {
        const { data: user, error } = await supabase.from('users').update({ role }).eq('id', id).select().single()
        if (error) {
            console.error('❌ Supabase updateUserRole error:', error)
            throw error
        }
        res.json({ success: true, data: user })
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to update user role' })
    }
}

export const updateUserStatus = async (req, res) => {
    const { id } = req.params
    const { status } = req.body

    if (!['active', 'pending', 'approved', 'suspended'].includes(status)) {
        return res.status(400).json({ success: false, error: 'Invalid status' })
    }

    try {
        const { data: user, error } = await supabase.from('users').update({ status }).eq('id', id).select().single()
        if (error) {
            console.error('❌ Supabase updateUserStatus error:', error)
            throw error
        }
        res.json({ success: true, data: user })
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to update user status' })
    }
}
