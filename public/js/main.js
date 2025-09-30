// Main JavaScript functionality

// Language change functionality
function changeLanguage(language) {
    const currentUrl = new URL(window.location);
    currentUrl.searchParams.set('lang', language);
    window.location.href = currentUrl.toString();
}

// Initialize charts on dashboard (fetch from API and render dynamically)
function initializeCharts() {
    const container = document.getElementById('trendChartContainer');
    const header = document.getElementById('trendHeaderYear');
    if (!container) return;

    fetch('/api/disease/trends', { cache: 'no-store' })
      .then(r => r.json())
      .then(data => {
        const { year, monthly = [] } = data || {};
        if (header) header.textContent = year ? `Monthly Trend (${year})` : 'Monthly Trend';

        container.innerHTML = '';
        const max = Math.max(1, ...monthly.map(m => Number(m.total || 0)));
        const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

        monthly.forEach((m, idx) => {
          const value = Number(m.total || 0);
          const bar = document.createElement('div');
          bar.className = 'chart-bar';
          bar.style.height = '0%';
          bar.setAttribute('data-value', String(value));
          bar.setAttribute('data-month', monthNames[idx] || String(m.mon));
          bar.style.transition = 'height 0.4s ease';

          // Tooltip
          bar.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'chart-tooltip';
            tooltip.textContent = `${value} cases`;
            tooltip.style.cssText = `
                position: absolute; top: -2rem; left: 50%; transform: translateX(-50%);
                background: #1f2937; color: white; padding: 0.25rem 0.5rem; border-radius: 0.25rem;
                font-size: 0.75rem; white-space: nowrap; z-index: 10;`;
            this.appendChild(tooltip);
          });
          bar.addEventListener('mouseleave', function() {
            const tooltip = this.querySelector('.chart-tooltip');
            if (tooltip) tooltip.remove();
          });

          container.appendChild(bar);

          // Animate height
          setTimeout(() => {
            const height = (value / max) * 100;
            bar.style.height = `${height}%`;
          }, idx * 80);
        });
      })
      .catch(err => {
        console.error('Failed to load trends', err);
      });
}

// Initialize outbreak map
function initializeMap() {
    const hotspots = document.querySelectorAll('.hotspot');
    
    hotspots.forEach(hotspot => {
        hotspot.addEventListener('mouseenter', function() {
            const info = this.getAttribute('data-info');
            const tooltip = document.createElement('div');
            tooltip.className = 'map-tooltip';
            tooltip.textContent = info;
            tooltip.style.cssText = `
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%);
                background: #1f2937;
                color: white;
                padding: 0.5rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                white-space: nowrap;
                margin-bottom: 0.5rem;
                z-index: 10;
            `;
            this.appendChild(tooltip);
        });
        
        hotspot.addEventListener('mouseleave', function() {
            const tooltip = this.querySelector('.map-tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
}

// Start real-time updates (only timestamp; no random stat mutation)
function startRealTimeUpdates() {
    // Update last updated time every minute
    setInterval(() => {
        const lastUpdatedElement = document.getElementById('lastUpdated');
        if (lastUpdatedElement) {
            lastUpdatedElement.textContent = new Date().toLocaleString();
        }
    }, 60000);
}

// Initialize report form
function initializeReportForm() {
    const form = document.getElementById('reportForm');
    if (!form) return;
    
    form.addEventListener('submit', function(e) {
        const submitBtn = form.querySelector('.submit-btn');
        const originalText = submitBtn.innerHTML;
        
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Submitting...';
        submitBtn.disabled = true;
        
        // Re-enable after form submission
        setTimeout(() => {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }, 2000);
    });
    
    // Add form validation feedback
    const inputs = form.querySelectorAll('input[required], select[required]');
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value.trim() === '') {
                this.style.borderColor = '#dc2626';
            } else {
                this.style.borderColor = '#16a34a';
            }
        });
        
        input.addEventListener('input', function() {
            if (this.value.trim() !== '') {
                this.style.borderColor = '#16a34a';
            }
        });
    });
}

// Initialize water quality page
function initializeWaterQuality() {
    // Simulate real-time sensor updates
    setInterval(() => {
        updateSensorReadings();
    }, 10000);
}

// Update sensor readings
function updateSensorReadings() {
    const sensorCards = document.querySelectorAll('.sensor-card.online');
    
    sensorCards.forEach(card => {
        const readings = card.querySelectorAll('.reading-value');
        readings.forEach(reading => {
            // Add pulse animation to show update
            reading.style.animation = 'pulse 0.5s ease-in-out';
            setTimeout(() => {
                reading.style.animation = '';
            }, 500);
        });
    });
}

// Initialize education page
function initializeEducation() {
    // Add smooth scrolling for module navigation
    const moduleItems = document.querySelectorAll('.module-item');
    moduleItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const href = this.getAttribute('href');
            
            // Add loading state
            this.style.opacity = '0.7';
            setTimeout(() => {
                window.location.href = href;
            }, 200);
        });
    });
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `live-alert ${type}`;
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas ${type === 'critical' ? 'fa-exclamation-triangle' : 'fa-bell'}"></i>
            <span>${message}</span>
        </div>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer; margin-left: auto;">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    const container = document.getElementById('alertContainer');
    if (container) {
        container.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
}

// Add CSS animation keyframes
const style = document.createElement('style');
style.textContent = `
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
`;
document.head.appendChild(style);