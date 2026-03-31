const StatusBadge = ({ status }) => {
    const config = {
        completed: { 
            color: 'emerald', 
            label: 'Completed', 
            dot: 'bg-emerald-500', 
            bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
        },
        running: { 
            color: 'primary', 
            label: 'Scanning', 
            dot: 'bg-primary-500 animate-pulse', 
            bg: 'bg-primary-500/10 text-primary-400 border-primary-500/20 shadow-[0_0_10px_rgba(139,92,246,0.1)]' 
        },
        failed: { 
            color: 'rose', 
            label: 'Failed', 
            dot: 'bg-rose-500', 
            bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' 
        },
        pending: { 
            color: 'slate', 
            label: 'Queued', 
            dot: 'bg-slate-500', 
            bg: 'bg-slate-500/10 text-slate-400 border-slate-500/20' 
        },
        stopped: { 
            color: 'amber', 
            label: 'Stopped', 
            dot: 'bg-amber-500', 
            bg: 'bg-amber-500/10 text-amber-400 border-amber-400/20' 
        }
    }

    const { label, dot, bg } = config[status.toLowerCase()] || config.pending

    return (
        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${bg}`}>
            <span className={`w-1.5 h-1.5 rounded-full mr-2 ${dot}`} />
            {label}
        </span>
    )
}

export default StatusBadge
