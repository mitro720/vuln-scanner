import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'

// Get all findings
export const getFindings = async (req, res, next) => {
    try {
        const { severity, scan_id } = req.query

        let query = supabase.from('findings').select('*')

        if (severity) {
            query = query.eq('severity', severity)
        }

        if (scan_id) {
            query = query.eq('scan_id', scan_id)
        }

        const { data, error } = await query.order('created_at', { ascending: false })

        if (error) throw new AppError(error.message, 400)

        res.json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}

// Create new finding (called by Python scanner)
export const createFinding = async (req, res, next) => {
    try {
        const {
            scan_id,
            name,
            severity,
            owasp_category,
            url,
            confidence,
            technique,
            evidence,
            poc,
            remediation,
            cwe,
            cvss_score,
            cvss_vector
        } = req.body

        if (!scan_id || !name || !severity) {
            throw new AppError('Missing required fields: scan_id, name, severity', 400)
        }

        const { data, error } = await supabase
            .from('findings')
            .insert({
                scan_id,
                name,
                severity: severity.toLowerCase(),
                owasp: owasp_category,
                url,
                confidence: confidence || 0,
                technique,
                evidence,
                poc,
                remediation,
                cwe,
                cvss_score,
                cvss_vector
            })
            .select()
            .single()

        if (error) throw new AppError(error.message, 400)

        res.status(201).json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}

// Get single finding
export const getFindingById = async (req, res, next) => {
    try {
        const { id } = req.params

        const { data, error } = await supabase
            .from('findings')
            .select('*')
            .eq('id', id)
            .single()

        if (error) throw new AppError(error.message, 404)

        res.json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}

// Update finding (e.g., mark as false positive)
export const updateFinding = async (req, res, next) => {
    try {
        const { id } = req.params
        const updates = req.body

        const { data, error } = await supabase
            .from('findings')
            .update(updates)
            .eq('id', id)
            .select()
            .single()

        if (error) throw new AppError(error.message, 400)

        res.json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}
