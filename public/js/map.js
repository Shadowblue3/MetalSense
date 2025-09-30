// Leaflet map that pulls hotspots from server APIs and adds a month dropdown
(function() {
  function getRiskColor(cases) {
    if (cases > 500) return '#DC2626'; // high
    if (cases > 200) return '#EA580C'; // medium-high
    if (cases > 50) return '#D97706';  // medium
    if (cases > 10) return '#F59E0B';  // low-medium
    return '#059669';                  // low
  }

  function isValidNumber(n) {
    return typeof n === 'number' && !Number.isNaN(n);
  }

  function monthName(m) {
    const names = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    if (!m || m < 1 || m > 12) return String(m || '');
    return names[m - 1];
  }

  document.addEventListener('DOMContentLoaded', function() {
    if (typeof L === 'undefined') return;

    const mapEl = document.getElementById('map');
    if (!mapEl) return;

    const map = L.map('map').setView([20.5937, 78.9629], 5);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    const markersLayer = L.layerGroup().addTo(map);

    // Inject month dropdown UI
    const outbreakCard = mapEl.closest('.dashboard-card');
    let controlsBar = outbreakCard ? outbreakCard.querySelector('.map-controls') : null;
    if (!controlsBar && outbreakCard) {
      controlsBar = document.createElement('div');
      controlsBar.className = 'map-controls';
      controlsBar.style.cssText = 'display:flex;justify-content:flex-end;gap:0.5rem;margin-bottom:0.5rem;align-items:center;';
      const label = document.createElement('label');
      label.textContent = 'Month:';
      label.style.marginRight = '0.5rem';
      const select = document.createElement('select');
      select.id = 'outbreakMonthSelect';
      select.style.cssText = 'padding:0.35rem 0.5rem;border:1px solid #d1d5db;border-radius:0.375rem;background:#fff;';
      controlsBar.appendChild(label);
      controlsBar.appendChild(select);
      // Insert controls before the map element
      const container = outbreakCard.querySelector('.outbreak-map');
      if (container) container.insertBefore(controlsBar, container.firstChild);
    }

    const monthSelect = document.getElementById('outbreakMonthSelect');

    function renderHotspots(hotspots) {
      markersLayer.clearLayers();
      (hotspots || []).forEach(h => {
        const lat = Number(h.lat), lon = Number(h.lon);
        if (!isValidNumber(lat) || !isValidNumber(lon)) return;
        const cases = Number(h.Cases || 0);
        const radius = Math.max(4, Math.min(20, Math.sqrt(cases)));
        const color = getRiskColor(cases);

        const marker = L.circleMarker([lat, lon], {
          radius,
          fillColor: color,
          color: '#ffffff',
          weight: 1,
          opacity: 0.9,
          fillOpacity: 0.75
        });

        const popup = `
          <div class="popup-content">
            <h4 class="popup-title">${(h.district || 'District')}, ${(h.state_ut || '')}</h4>
            <div class="popup-stats">
              <div class="popup-stat"><span class="popup-stat-label">Disease:</span> <span class="popup-stat-value">${h.Disease || '-'}</span></div>
              <div class="popup-stat"><span class="popup-stat-label">Cases:</span> <span class="popup-stat-value">${cases}</span></div>
            </div>
          </div>`;
        marker.bindPopup(popup).addTo(markersLayer);
      });
      setTimeout(() => map.invalidateSize(), 50);
    }

    function loadHotspots(mon) {
      const url = mon ? `/api/disease/hotspots?mon=${encodeURIComponent(mon)}` : '/api/disease/hotspots';
      fetch(url, { cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
          renderHotspots(data.hotspots || []);
        })
        .catch(err => console.error('Failed to load hotspots', err));
    }

    function populateMonths() {
      fetch('/api/disease/months', { cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
          if (!monthSelect) return;
          const { months = [], latestMonth = null } = data || {};
          monthSelect.innerHTML = '';
          months.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = `${monthName(m)} (${m})`;
            if (latestMonth === m) opt.selected = true;
            monthSelect.appendChild(opt);
          });

          monthSelect.addEventListener('change', () => {
            const m = Number(monthSelect.value || latestMonth || 0);
            loadHotspots(m);
          });

          const initial = Number(monthSelect.value || latestMonth || 0);
          loadHotspots(initial);
        })
        .catch(err => {
          console.error('Failed to load months', err);
          // Fallback without dropdown
          loadHotspots(null);
        });
    }

    populateMonths();

    window.addEventListener('resize', () => map.invalidateSize());
  });
})();
