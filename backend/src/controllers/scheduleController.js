/**
 * Schedule Controller — cron-based recurring scan scheduling
 */
import cron from 'node-cron'
import supabase from '../config/supabase.js'
import { AppError } from '../middleware/errorHandler.js'

// In-memory registry of active cron tasks: { scheduleId → task }
const activeJobs = new Map()

/* ── Helpers ──────────────────────────────────────────────────────────── */
const FREQUENCY_TO_CRON = {
    hourly: '0 * * * *',
    daily: '0 8 * * *',
    weekly: '0 8 * * 1',
    monthly: '0 8 1 * *',
}

function getNextRun(cronExpr) {
    // Simple approximation — cron-parser would be more precise
    const now = new Date()
    const next = new Date(now.getTime() + 60 * 1000) // at least 1 min from now
    return next.toISOString()
}

async function triggerScan(schedule) {
    console.log(`⏰ Scheduled scan triggered for: ${schedule.target_url}`)
    try {
        const { data, error } = await supabase.from('scans').insert({
            target_url: schedule.target_url,
            status: 'pending',
            scan_type: schedule.scan_type || 'full',
            config: schedule.config || {},
            progress: 0,
            triggered_by: 'schedule',
        }).select().single()

        if (error) { console.error('Schedule trigger DB error:', error.message); return }

        // Update schedule last_run
        await supabase.from('scan_schedules').update({
            last_run: new Date().toISOString(),
            last_scan_id: data.id,
            run_count: (schedule.run_count || 0) + 1,
        }).eq('id', schedule.id)

        // Fire scanner
        const scannerUrl = process.env.SCANNER_API_URL || 'http://localhost:8000';
        await fetch(`${scannerUrl}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: data.id, target_url: schedule.target_url, config: schedule.config || {} }),
        }).catch(() => { })

        console.log(`✅ Scheduled scan created: ${data.id}`)
    } catch (e) {
        console.error('Schedule trigger error:', e.message)
    }
}

export function registerSchedule(schedule) {
    if (!schedule?.cron_expression) return
    if (!cron.validate(schedule.cron_expression)) {
        console.warn(`Invalid cron for schedule ${schedule.id}: ${schedule.cron_expression}`)
        return
    }
    const task = cron.schedule(schedule.cron_expression, () => triggerScan(schedule), {
        scheduled: true,
        timezone: 'UTC',
    })
    activeJobs.set(schedule.id, task)
    console.log(`📅 Registered schedule ${schedule.id}: ${schedule.cron_expression} → ${schedule.target_url}`)
}

export function unregisterSchedule(id) {
    const task = activeJobs.get(id)
    if (task) { task.stop(); activeJobs.delete(id) }
}

/* ── Bootstrap: load all active schedules on server start ─────────────── */
export async function initSchedules() {
    try {
        const { data, error } = await supabase
            .from('scan_schedules')
            .select('*')
            .eq('enabled', true)
        if (error) { console.warn('Could not load schedules:', error.message); return }
        ; (data || []).forEach(registerSchedule)
        console.log(`✅ Loaded ${(data || []).length} active scan schedule(s)`)
    } catch (e) {
        console.warn('initSchedules error:', e.message)
    }
}

/* ── REST Controllers ─────────────────────────────────────────────────── */

// GET /api/schedules
export const getSchedules = async (req, res, next) => {
    try {
        const { data, error } = await supabase
            .from('scan_schedules')
            .select('*')
            .order('created_at', { ascending: false })
        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, data: data || [] })
    } catch (e) { next(e) }
}

// POST /api/schedules
export const createSchedule = async (req, res, next) => {
    try {
        const { target_url, frequency, cron_expression, scan_type, config, name } = req.body
        if (!target_url) throw new AppError('target_url required', 400)

        const cronExpr = cron_expression || FREQUENCY_TO_CRON[frequency] || FREQUENCY_TO_CRON.daily
        if (!cron.validate(cronExpr)) throw new AppError('Invalid cron expression', 400)

        const { data, error } = await supabase.from('scan_schedules').insert({
            name: name || `Schedule: ${target_url}`,
            target_url,
            frequency: frequency || 'custom',
            cron_expression: cronExpr,
            scan_type: scan_type || 'full',
            config: config || {},
            enabled: true,
            next_run: getNextRun(cronExpr),
            run_count: 0,
        }).select().single()

        if (error) throw new AppError(error.message, 400)
        registerSchedule(data)
        res.status(201).json({ success: true, data })
    } catch (e) { next(e) }
}

// PATCH /api/schedules/:id/toggle
export const toggleSchedule = async (req, res, next) => {
    try {
        const { id } = req.params
        const { data: current } = await supabase.from('scan_schedules').select('*').eq('id', id).single()
        if (!current) throw new AppError('Schedule not found', 404)

        const enabled = !current.enabled
        const { data, error } = await supabase.from('scan_schedules').update({ enabled }).eq('id', id).select().single()
        if (error) throw new AppError(error.message, 400)

        if (enabled) registerSchedule(data); else unregisterSchedule(id)
        res.json({ success: true, data })
    } catch (e) { next(e) }
}

// DELETE /api/schedules/:id
export const deleteSchedule = async (req, res, next) => {
    try {
        const { id } = req.params
        unregisterSchedule(id)
        const { error } = await supabase.from('scan_schedules').delete().eq('id', id)
        if (error) throw new AppError(error.message, 400)
        res.json({ success: true, message: 'Schedule deleted' })
    } catch (e) { next(e) }
}
