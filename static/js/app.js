'use strict';
const socket = io();

socket.on('new_alert', (alert) => {
    const badge = document.getElementById('open-alerts-badge');
    if (badge) {
        const n = parseInt(badge.textContent || '0') + 1;
        badge.textContent = n;
    }
    showToast(`New ${alert.severity} alert: ${alert.title}`, alert.severity);
});

socket.on('alert_updated', () => {
    // Could refresh table without full reload
});

function showToast(msg, severity) {
    const colors = { CRITICAL: '#ff4757', HIGH: '#ffa502', MEDIUM: '#eccc68', LOW: '#70a1ff' };
    const toast = document.createElement('div');
    toast.style.cssText = `position:fixed;bottom:20px;right:20px;background:${colors[severity]||'#64ffda'};color:#080f1e;padding:12px 20px;border-radius:6px;font-size:.88em;font-weight:600;z-index:9999;max-width:350px;`;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

async function updateAlertStatus(alertId, status) {
    try {
        const res = await fetch(`/api/alert/${alertId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status }),
        });
        if (res.ok) location.reload();
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function executeResponse(actionType, target, alertId) {
    try {
        const res = await fetch('/api/response', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action_type: actionType, target, alert_id: alertId }),
        });
        const data = await res.json();
        alert(data.message || 'Action completed');
    } catch (err) {
        alert('Error: ' + err.message);
    }
}
