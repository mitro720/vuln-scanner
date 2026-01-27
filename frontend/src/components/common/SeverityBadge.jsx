const SeverityBadge = ({ severity, size = 'md' }) => {
    const sizeClasses = {
        sm: 'px-2 py-0.5 text-xs',
        md: 'px-3 py-1 text-sm',
        lg: 'px-4 py-2 text-base',
    }

    const severityClasses = {
        critical: 'severity-badge-critical',
        high: 'severity-badge-high',
        medium: 'severity-badge-medium',
        low: 'severity-badge-low',
        info: 'severity-badge-info',
    }

    return (
        <span className={`
      inline-flex items-center justify-center rounded-full font-semibold
      ${sizeClasses[size]}
      ${severityClasses[severity.toLowerCase()]}
    `}>
            {severity.toUpperCase()}
        </span>
    )
}

export default SeverityBadge
