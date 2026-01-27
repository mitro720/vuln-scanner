const StatusBadge = ({ status }) => {
    const styles = {
        completed: 'bg-green-100 text-green-700',
        running: 'bg-blue-100 text-blue-700',
        failed: 'bg-red-100 text-red-700',
        pending: 'bg-gray-100 text-gray-700'
    }

    const labels = {
        completed: 'Completed',
        running: 'Running',
        failed: 'Failed',
        pending: 'Pending'
    }

    const currentStyle = styles[status] || styles.pending
    const label = labels[status] || status

    return (
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${currentStyle}`}>
            {label}
        </span>
    )
}

export default StatusBadge
