/**
 * Policy Controller — save, load, and delete named scan configurations
 */
import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'

// GET /api/policies
export const getPolicies = async (req, res, next) => {
    try {
        const { data, error } = await supabase
            .from('scan_policies')
            .select('*')
            .order('created_at', { ascending: false })
        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, data: data || [] })
    } catch (e) { next(e) }
}

// POST /api/policies
export const createPolicy = async (req, res, next) => {
    try {
        const { name, description, scan_type, config } = req.body
        if (!name || !config) throw new AppError('name and config required', 400)

        const { data, error } = await supabase.from('scan_policies').insert({
            name,
            description: description || '',
            scan_type: scan_type || 'custom',
            config,
        }).select().single()

        if (error) throw new AppError(error.message, 400)
        res.status(201).json({ success: true, data })
    } catch (e) { next(e) }
}

// PUT /api/policies/:id
export const updatePolicy = async (req, res, next) => {
    try {
        const { id } = req.params
        const { name, description, scan_type, config } = req.body

        const { data, error } = await supabase.from('scan_policies')
            .update({ name, description, scan_type, config })
            .eq('id', id).select().single()

        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, data })
    } catch (e) { next(e) }
}

// DELETE /api/policies/:id
export const deletePolicy = async (req, res, next) => {
    try {
        const { id } = req.params
        const { error } = await supabase.from('scan_policies').delete().eq('id', id)
        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, message: 'Policy deleted' })
    } catch (e) { next(e) }
}
