// Alert system functionality

class AlertSystem {
    constructor() {
        this.alerts = [];
        this.container = document.getElementById('alertContainer');
        this.init();
    }

    init() {
        // Start alert simulation after page load
        setTimeout(() => {
            this.simulateAlert();
        }, 3000);

        // Set up periodic alerts
        setInterval(() => {
            this.simulateAlert();
        }, 15000);
    }

    simulateAlert() {
        const alertTypes = ['critical', 'warning', 'info'];
        const messages = {
            critical: 'Critical outbreak detected in your area - immediate action required',
            warning: 'Water quality degradation detected - exercise caution',
            info: 'Weekly health surveillance update available'
        };

        const type = alertTypes[Math.floor(Math.random() * alertTypes.length)];
        const message = messages[type];

        this.showAlert(message, type);
    }

    showAlert(message, type = 'info') {
        const alertId = Date.now().toString();
        const alert = {
            id: alertId,
            type: type,
            message: message,
            timestamp: new Date().toLocaleTimeString()
        };

        this.alerts.unshift(alert);
        
        // Keep only last 3 alerts
        if (this.alerts.length > 3) {
            this.alerts = this.alerts.slice(0, 3);
        }

        this.renderAlert(alert);
    }

    renderAlert(alert) {
        if (!this.container) return;

        const alertElement = document.createElement('div');
        alertElement.className = `live-alert ${alert.type}`;
        alertElement.setAttribute('data-id', alert.id);
        
        alertElement.innerHTML = `
            <div class="alert-content-live">
                <div class="alert-icon-live">
                    <i class="fas ${alert.type === 'critical' ? 'fa-exclamation-triangle' : 'fa-bell'}"></i>
                </div>
                <div class="alert-text-live">
                    <p class="alert-message">${alert.message}</p>
                    <p class="alert-timestamp">${alert.timestamp}</p>
                </div>
                <button class="alert-dismiss" onclick="alertSystem.dismissAlert('${alert.id}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        this.container.appendChild(alertElement);

        // Auto-dismiss after 8 seconds
        setTimeout(() => {
            this.dismissAlert(alert.id);
        }, 8000);
    }

    dismissAlert(alertId) {
        const alertElement = document.querySelector(`[data-id="${alertId}"]`);
        if (alertElement) {
            alertElement.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => {
                if (alertElement.parentElement) {
                    alertElement.remove();
                }
            }, 300);
        }

        this.alerts = this.alerts.filter(alert => alert.id !== alertId);
    }
}

// Initialize alert system
let alertSystem;
document.addEventListener('DOMContentLoaded', function() {
    alertSystem = new AlertSystem();
});

// Add CSS for live alerts
const alertStyles = document.createElement('style');
alertStyles.textContent = `
    .alert-content-live {
        display: flex;
        align-items: flex-start;
        gap: 0.75rem;
    }

    .alert-icon-live {
        padding: 0.25rem;
        border-radius: 50%;
        flex-shrink: 0;
    }

    .live-alert.critical .alert-icon-live {
        background: #fecaca;
        color: #dc2626;
    }

    .live-alert.warning .alert-icon-live {
        background: #fef3c7;
        color: #ca8a04;
    }

    .live-alert.info .alert-icon-live {
        background: #dbeafe;
        color: #2563eb;
    }

    .alert-text-live {
        flex: 1;
    }

    .alert-message {
        font-size: 0.875rem;
        font-weight: 500;
        margin-bottom: 0.25rem;
    }

    .live-alert.critical .alert-message {
        color: #991b1b;
    }

    .live-alert.warning .alert-message {
        color: #92400e;
    }

    .live-alert.info .alert-message {
        color: #1e40af;
    }

    .alert-timestamp {
        font-size: 0.75rem;
        color: #6b7280;
        margin: 0;
    }

    .alert-dismiss {
        background: none;
        border: none;
        color: #6b7280;
        cursor: pointer;
        padding: 0.25rem;
        border-radius: 0.25rem;
        transition: all 0.2s;
        flex-shrink: 0;
    }

    .alert-dismiss:hover {
        color: #374151;
        background: rgba(0, 0, 0, 0.05);
    }

    @keyframes slideOutRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(alertStyles);