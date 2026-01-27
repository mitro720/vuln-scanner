import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'
import { spawn } from 'child_process'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Get all scans
export const getScans = async (req, res, next) => {
    try {
        const { data, error } = await supabase
            .from('scans')
            .select('*')
            .order('created_at', { ascending: false })

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
        const { target_url, scan_type, config } = req.body

        if (!target_url) {
            throw new AppError('Target URL is required', 400)
        }

        // Validate URL format
        try {
            new URL(target_url)
        } catch {
            throw new AppError('Invalid URL format', 400)
        }

        // Create scan record directly with target_url (no target record needed)
        console.log('📝 Creating scan record in database...', { target_url, scan_type, config })
        const { data: scanData, error: scanError } = await supabase
            .from('scans')
            .insert({
                target_url: target_url,
                status: 'pending',
                scan_type: scan_type || 'full',
                config: config || {},
                progress: 0,
            })
            .select()
            .single()

        if (scanError) throw new AppError(scanError.message, 400)

        console.log('✅ Scan record created:', scanData.id)

        // Trigger Python scanner via API bridge
        console.log('🚀 Triggering Python scanner at http://localhost:8000/scan/start...')
        try {
            const scannerResponse = await fetch('http://localhost:8000/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: scanData.id,
                    target_url: target_url,
                    config: config || {}
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

// Update scan status
export const updateScan = async (req, res, next) => {
    try {
        const { id } = req.params
        const updates = req.body

        const { data, error } = await supabase
            .from('scans')
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
        // Get all scans to calculate stats
        // Note: In a real production app with millions of rows, use count() or specific RPC calls
        const { data: scans, error: scanError } = await supabase
            .from('scans')
            .select('status')

        if (scanError) throw new AppError(scanError.message, 400)

        const { data: findings, error: findingError } = await supabase
            .from('findings')
            .select('severity')

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
