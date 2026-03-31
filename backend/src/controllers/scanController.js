import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'
import { spawn } from 'child_process'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const MAX_CONCURRENT_SCANS = 5;

// Get all scans
export const getScans = async (req, res, next) => {
    try {
        let query = supabase.from('scans').select('*')
        
        // If not admin, only show user's own scans
        if (req.user.role !== 'admin') {
            query = query.eq('user_id', req.user.id)
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

// Get single scan by ID
export const getScanById = async (req, res, next) => {
    try {
        const { id } = req.params

        const { data, error } = await supabase
            .from('scans')
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

// Create new scan
export const createScan = async (req, res, next) => {
    try {
        const { target_url, scan_type, config, phase } = req.body

        if (!target_url) {
            throw new AppError('Target URL is required', 400)
        }

        // Validate URL format
        try {
            new URL(target_url)
        } catch {
            throw new AppError('Invalid URL format', 400)
        }

        // Check concurrent scans
        const { count, error: countError } = await supabase
            .from('scans')
            .select('*', { count: 'exact', head: true })
            .in('status', ['running', 'pending'])

        if (countError) throw new AppError(countError.message, 400)
        
        if (count >= MAX_CONCURRENT_SCANS) {
            throw new AppError(`Maximum concurrent scan limit (${MAX_CONCURRENT_SCANS}) reached. Please stop or wait for existing scans to finish.`, 429)
        }

        // Create scan record directly with target_url (no target record needed)
        console.log('📝 Creating scan record in database...', { target_url, scan_type, config, phase })
        const { data: scanData, error: scanError } = await supabase
            .from('scans')
            .insert({
                target_url: target_url,
                user_id: req.user.id, // Associate with current user
                status: 'pending',
                scan_type: phase ? `modular:${phase}` : (scan_type || 'full'),
                config: config || {},
                progress: 0,
            })
            .select()
            .single()

        if (scanError) throw new AppError(scanError.message, 400)

        console.log('✅ Scan record created:', scanData.id)

        // Trigger Python scanner via API bridge
        const scannerUrl = process.env.SCANNER_API_URL || 'http://127.0.0.1:8000';
        console.log(`🚀 [ENVIRONMENT: ${process.env.NODE_ENV || 'local'}] Triggering Python scanner at ${scannerUrl}/scan/start...`)
        try {
            const scannerResponse = await fetch(`${scannerUrl}/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: scanData.id,
                    user_id: req.user.id, // Pass user context to engine
                    target_url: target_url,
                    config: config || {},
                    phase: phase || 'all'
                })
            })

            console.log('📡 Python scanner response status:', scannerResponse.status)

            if (!scannerResponse.ok) {
                const errorText = await scannerResponse.text()
                console.error('❌ Failed to start Python scanner:', errorText)
                // Update scan status to failed
                await supabase
                    .from('scans')
                    .update({ status: 'failed' })
                    .eq('id', scanData.id)
            } else {
                const responseData = await scannerResponse.json()
                console.log('✅ Python scanner started:', responseData)
                // Update scan status to running
                await supabase
                    .from('scans')
                    .update({ status: 'running' })
                    .eq('id', scanData.id)
            }
        } catch (error) {
            console.error('❌ Error triggering scanner:', error.message)
            await supabase
                .from('scans')
                .update({ status: 'failed' })
                .eq('id', scanData.id)
        }

        res.status(201).json({
            success: true,
            data: scanData,
        })
    } catch (error) {
        next(error)
    }
}

// Stop an active scan
export const stopScan = async (req, res, next) => {
    try {
        const { id } = req.params

        console.log(`🛑 Requesting stop for scan: ${id}`)
        
        try {
            const scannerUrl = process.env.SCANNER_API_URL || 'http://localhost:8000';
            const scannerResponse = await fetch(`${scannerUrl}/scan/stop/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })

            if (!scannerResponse.ok) {
                const errorText = await scannerResponse.text()
                console.error('❌ Failed to stop Python scanner:', errorText)
                // We still update the DB if the scanner is unreachable or returns error
            }
        } catch (error) {
            console.error('❌ Error notifying scanner bridge:', error.message)
        }

        // Update scan status in database
        const { data, error } = await supabase
            .from('scans')
            .update({ status: 'stopped' })
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

// Update scan (Deep Merge Metadata)
export const updateScan = async (req, res, next) => {
    try {
        const { id } = req.params
        const updates = req.body

        // Fetch current scan to perform metadata merging if needed
        const { data: currentScan, error: fetchError } = await supabase
            .from('scans')
            .select('metadata')
            .eq('id', id)
            .single()

        if (fetchError) throw new AppError(fetchError.message, 404)

        // Merge metadata if it's being updated
        let finalUpdates = { ...updates }
        if (updates.metadata) {
            let existingMeta = currentScan.metadata || {}
            if (typeof existingMeta === 'string') {
                try { existingMeta = JSON.parse(existingMeta) } catch (e) { existingMeta = {} }
            }
            let newMeta = updates.metadata || {}
            if (typeof newMeta === 'string') {
                try { newMeta = JSON.parse(newMeta) } catch (e) { newMeta = {} }
            }
            finalUpdates.metadata = {
                ...existingMeta,
                ...newMeta
            }
        }

        const { data, error } = await supabase
            .from('scans')
            .update(finalUpdates)
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

// Delete scan
export const deleteScan = async (req, res, next) => {
    try {
        const { id } = req.params

        const { error } = await supabase
            .from('scans')
            .delete()
            .eq('id', id)

        if (error) throw new AppError(error.message, 400)

        res.json({
            success: true,
            message: 'Scan deleted successfully',
        })
    } catch (error) {
        next(error)
    }
}

// Get scan findings
export const getScanFindings = async (req, res, next) => {
    try {
        const { id } = req.params

        const { data, error } = await supabase
            .from('findings')
            .select('*')
            .eq('scan_id', id)
            .order('severity', { ascending: false })

        if (error) throw new AppError(error.message, 400)

        res.json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}

// Get scan statistics
export const getScanStats = async (req, res, next) => {
    try {
        // Build base queries
        let scansQuery = supabase.from('scans').select('status')
        let findingsQuery = supabase.from('findings').select('severity')

        // Filter by user if not admin
        if (req.user.role !== 'admin') {
            scansQuery = scansQuery.eq('user_id', req.user.id)
            // findings doesn't have a user_id column directly; join via scans
            // For now skip per-user finding filter at stats level to prevent schema errors
        }

        const { data: scans, error: scanError } = await scansQuery
        if (scanError) throw new AppError(scanError.message, 400)

        const { data: findings, error: findingError } = await findingsQuery

        if (findingError) throw new AppError(findingError.message, 400)

        const stats = {
            totalScans: scans.length,
            activeScans: scans.filter(s => s.status === 'running' || s.status === 'pending').length,
            completedScans: scans.filter(s => s.status === 'completed').length,
            totalFindings: findings.length,
            criticalFindings: findings.filter(f => f.severity === 'critical').length,
            highFindings: findings.filter(f => f.severity === 'high').length
        }

        res.json({
            success: true,
            data: stats,
        })
    } catch (error) {
        next(error)
    }
}
// Continue scan with selected targets/modules
export const continueScan = async (req, res, next) => {
    try {
        const { id } = req.params
        const { selected_targets, selected_modules, custom_payloads } = req.body

        if (!selected_targets || !Array.isArray(selected_targets) || selected_targets.length === 0) {
            throw new AppError('At least one target must be selected', 400)
        }

        // 1. Get existing scan
        const { data: scan, error: fetchError } = await supabase
            .from('scans')
            .select('*')
            .eq('id', id)
            .single()

        if (fetchError) throw new AppError(fetchError.message, 404)

        // 2. Update config with new targets and modules
        const newConfig = {
            ...(scan.config || {}),
            targets: selected_targets,
            modules: selected_modules || [],
            custom_payloads: custom_payloads || [],
            owasp: true,
            cve_detection: true,
            port_scan: true
        }

        // 3. Update scan in DB
        console.log(`🔄 Continuing scan ${id} with ${selected_targets.length} targets...`)
        const { data, error: updateError } = await supabase
            .from('scans')
            .update({
                config: newConfig,
                status: 'running',
                progress: 40 // Mark as moved past recon
            })
            .eq('id', id)
            .select()
            .single()

        if (updateError) throw new AppError(updateError.message, 400)

        // 4. Trigger Python bridge with "vuln_only" phase
        try {
            const scannerUrl = process.env.SCANNER_API_URL || 'http://localhost:8000';
            const scannerResponse = await fetch(`${scannerUrl}/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: id,
                    target_url: scan.target_url,
                    config: newConfig,
                    phase: 'vuln_only' 
                })
            })
            console.log('📡 Python scanner continuation triggered:', scannerResponse.status)
        } catch (err) {
            console.error('❌ Failed to trigger python bridge for continuation:', err.message)
        }

        res.json({
            success: true,
            data,
        })
    } catch (error) {
        next(error)
    }
}

// Cleanup stale scans on startup (mark as interrupted)
export const cleanupStaleScans = async () => {
    try {
        console.log('🧹 Cleaning up stale scans...')
        const { error } = await supabase
            .from('scans')
            .update({ 
                status: 'stopped', 
                current_phase: 'Scan was interrupted due to server restart' 
            })
            .in('status', ['running', 'pending'])

        if (error) console.error('❌ Failed to cleanup stale scans:', error.message)
        else console.log('✅ Stale scans marked as stopped.')
    } catch (e) {
        console.error('❌ Error in cleanupStaleScans:', e.message)
    }
}
