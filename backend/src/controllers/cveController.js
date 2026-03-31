import { supabase } from '../config/supabase.js'

/**
 * Get CVE details by CVE ID
 */
export const getCVEById = async (req, res) => {
    try {
        const { cveId } = req.params

        const { data, error } = await supabase
            .from('cves')
            .select('*')
            .eq('cve_id', cveId)
            .single()

        if (error) {
            if (error.code === 'PGRST116') {
                return res.status(404).json({
                    success: false,
                    error: 'CVE not found'
                })
            }
            throw error
        }

        res.json({
            success: true,
            data
        })
    } catch (error) {
        console.error('Error fetching CVE:', error)
        res.status(500).json({
            success: false,
            error: 'Failed to fetch CVE details'
        })
    }
}

/**
 * Get all services detected in a scan
 */
export const getServicesByScan = async (req, res) => {
    try {
        const { scanId } = req.params

        const { data, error } = await supabase
            .from('services')
            .select('*')
            .eq('scan_id', scanId)
            .order('port', { ascending: true })

        if (error) throw error

        res.json({
            success: true,
            data,
            count: data.length
        })
    } catch (error) {
        console.error('Error fetching services:', error)
        res.status(500).json({
            success: false,
            error: 'Failed to fetch services'
        })
    }
}

/**
 * Get all CVEs found in a scan with service details
 */
export const getCVEsByScan = async (req, res) => {
    try {
        const { scanId } = req.params

        // Get CVEs from findings
        let query = supabase.from('findings').select('*').eq('scan_id', scanId)
        
        // Filter by user if not admin
        if (req.user.role !== 'admin') {
            query = query.eq('user_id', req.user.id)
        }

        const { data, error } = await query

        if (error) throw error

        let cveFindings = data.filter(f => f.owasp === 'CVE' || String(f.name).startsWith('CVE-'));

        // Group by severity for summary
        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: cveFindings.length
        }

        const formattedData = cveFindings.map(item => {
            const severity = item.severity?.toLowerCase() || 'unknown'
            if (summary.hasOwnProperty(severity)) {
                summary[severity]++
            }

            return {
                ...item,
                cve_id: item.name,
                cve: {
                    cve_id: item.name,
                    description: item.description,
                    severity: item.severity,
                    cvss_score: item.cvss_score
                },
                service: {
                    service_name: item.service_name || 'Service',
                    port: item.evidence?.port || '?'
                }
            }
        })

        res.json({
            success: true,
            data: formattedData,
            summary
        })
    } catch (error) {
        console.error('Error fetching CVEs:', error)
        res.status(500).json({
            success: false,
            error: 'Failed to fetch CVEs'
        })
    }
}

/**
 * Manual CVE lookup by service and version
 */
export const lookupCVE = async (req, res) => {
    try {
        const { service, version, product } = req.body

        if (!service || !version) {
            return res.status(400).json({
                success: false,
                error: 'Service and version are required'
            })
        }

        // This would typically call the Python CVE matcher
        // For now, return a placeholder response
        res.json({
            success: true,
            message: 'CVE lookup functionality requires Python scanner integration',
            data: {
                service,
                version,
                product,
                cves: []
            }
        })
    } catch (error) {
        console.error('Error looking up CVE:', error)
        res.status(500).json({
            success: false,
            error: 'Failed to lookup CVE'
        })
    }
}

/**
 * Get CVE statistics for a scan
 */
export const getCVEStats = async (req, res) => {
    try {
        const { scanId } = req.params

        // Get all CVEs for the scan from findings
        let query = supabase.from('findings').select('*').eq('scan_id', scanId)
        
        // Filter by user if not admin
        if (req.user.role !== 'admin') {
            query = query.eq('user_id', req.user.id)
        }

        const { data, error } = await query

        if (error) throw error

        let cveFindings = data.filter(f => f.owasp === 'CVE' || String(f.name).startsWith('CVE-'));

        // Calculate statistics
        const stats = {
            total: cveFindings.length,
            by_severity: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                unknown: 0
            },
            avg_cvss: 0,
            max_cvss: 0
        }

        let cvssSum = 0
        let cvssCount = 0

        cveFindings.forEach(item => {
            const severity = item.severity?.toLowerCase() || 'unknown'

            if (stats.by_severity.hasOwnProperty(severity)) {
                stats.by_severity[severity]++
            } else {
                stats.by_severity.unknown++
            }

            if (item.cvss_score) {
                const score = parseFloat(item.cvss_score)
                cvssSum += score
                cvssCount++
                stats.max_cvss = Math.max(stats.max_cvss, score)
            }
        })

        if (cvssCount > 0) {
            stats.avg_cvss = (cvssSum / cvssCount).toFixed(1)
        }

        res.json({
            success: true,
            data: stats
        })
    } catch (error) {
        console.error('Error fetching CVE stats:', error)
        res.status(500).json({
            success: false,
            error: 'Failed to fetch CVE statistics'
        })
    }
}
