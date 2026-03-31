import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'

// Get all findings
export const getFindings = async (req, res, next) => {
    try {
        const { severity, scan_id } = req.query

        let query = supabase.from('findings').select('*')
        
        // If not admin, only show user's own findings
        if (req.user.role !== 'admin') {
            query = query.eq('user_id', req.user.id)
        }

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
            user_id, // Receives from Python bridge (passed during scan start)
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
            cvss_vector,
            epss_score,
            epss_percentile
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
                owasp_category,
                url,
                confidence: confidence || 0,
                technique,
                evidence,
                poc,
                remediation,
                cwe,
                cvss_score,
                cvss_vector,
                epss_score,
                epss_percentile
            })
            .select()
            .single()

        if (error) throw new AppError(error.message, 400)

        // Increment scan findings count and severity specific counts
        const severityField = `${severity.toLowerCase()}_count`
        const { error: updateError } = await supabase.rpc('increment_scan_stats', { 
            p_scan_id: scan_id, 
            p_severity_field: severityField 
        })

        if (updateError) {
            // Fallback if RPC doesn't exist: Manual update
            console.warn('⚠️ increment_scan_stats RPC failed, attempting manual update:', updateError.message)
            
            // Get current counts
            const { data: scan } = await supabase.from('scans').select('findings_count, ' + severityField).eq('id', scan_id).single()
            
            if (scan) {
                await supabase.from('scans').update({
                    findings_count: (scan.findings_count || 0) + 1,
                    [severityField]: (scan[severityField] || 0) + 1,
                    updated_at: new Date().toISOString()
                }).eq('id', scan_id)
            }
        }

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

// PATCH /api/findings/:id/status — update remediation status
export const updateFindingStatus = async (req, res, next) => {
    try {
        const { id } = req.params
        const { status, note } = req.body

        const VALID_STATUSES = ['open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive']
        if (status && !VALID_STATUSES.includes(status)) {
            throw new AppError(`Invalid status. Must be one of: ${VALID_STATUSES.join(', ')}`, 400)
        }

        const updates = {
            remediation_status: status,
            remediation_updated_at: new Date().toISOString(),
        }
        if (note !== undefined) updates.remediation_note = note

        const { data, error } = await supabase
            .from('findings')
            .update(updates)
            .eq('id', id)
            .select()
            .single()

        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, data })
    } catch (error) {
        next(error)
    }
}
