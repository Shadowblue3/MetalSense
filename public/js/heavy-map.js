(function(){
  function isNum(x){ return typeof x === 'number' && !Number.isNaN(x); }
  function toNum(x){ const n = Number(x); return Number.isNaN(n)? undefined : n; }

  function getSeverity(sample){
    const metals = sample.metals || {}; const bg = sample.background || {};
    const keys = ['As','Cd','Cr','Cu','Pb','Zn','Ni'];
    let exceed = 0; let sumCf = 0;
    keys.forEach(k => {
      const v = toNum(metals[k]); const b = toNum(bg[k]);
      if (isNum(v) && isNum(b) && b > 0) {
        const cf = v / b;
        sumCf += cf;
        if (cf > 1) exceed++;
      }
    });
    return { exceed, sumCf };
  }

  function colorForExceed(n){
    if (n >= 4) return '#DC2626'; // high
    if (n >= 2) return '#F59E0B'; // medium
    if (n >= 1) return '#10B981'; // low
    return '#3B82F6'; // background/safe
  }

  function monthName(m){
    const names = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    if (!m || m < 1 || m > 12) return String(m||'');
    return names[m-1];
  }

  function buildPopup(p){
    const meta = getSeverity(p);
    const metals = p.metals || {}; const bg = p.background || {};
    function row(k,label){
      const v = isNum(metals[k])? metals[k].toFixed(3) : '-';
      const b = isNum(bg[k])? bg[k].toFixed(3) : '-';
      let klass = '';
      if (isNum(metals[k]) && isNum(bg[k]) && bg[k] > 0) {
        const cf = metals[k]/bg[k];
        if (cf > 1.5) klass = ' hm-high'; else if (cf > 1.0) klass = ' hm-med'; else klass = ' hm-low';
      }
      return `<tr class="${klass}"><td>${label}</td><td>${v}</td><td>${b}</td></tr>`;
    }

    return `
      <div class="popup-content">
        <h4 class="popup-title">${(p.location||'Sample')} ${p.sample_id?('#'+p.sample_id):''}</h4>
        <div class="popup-sub">${isNum(p.lat)&&isNum(p.lon)? (p.lat.toFixed(4)+', '+p.lon.toFixed(4)) : ''} • ${p.month?monthName(p.month):''} ${p.year||''}</div>
        <div class="popup-stats"><span>Exceedances: <strong>${meta.exceed}</strong></span> <span style="margin-left:0.5rem;">pH: <strong>${isNum(p.pH)? p.pH.toFixed(2) : '-'}</strong></span> <span style="margin-left:0.5rem;">EC: <strong>${isNum(p.EC)? p.EC.toFixed(1) : '-'}</strong></span></div>
        <table class="popup-table">
          <thead><tr><th>Metal</th><th>Value</th><th>Background</th></tr></thead>
          <tbody>
            ${row('As','As')} ${row('Cd','Cd')} ${row('Cr','Cr')} ${row('Cu','Cu')} ${row('Pb','Pb')} ${row('Zn','Zn')} ${row('Ni','Ni')}
          </tbody>
        </table>
      </div>`;
  }

  document.addEventListener('DOMContentLoaded', function(){
    if (typeof L === 'undefined') return;
    const el = document.getElementById('heavyMap');
    if (!el) return;

    const map = L.map('heavyMap').setView([22.9734, 78.6569], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);

    const layer = L.layerGroup().addTo(map);

    const yearSel = document.getElementById('sampleYearSelect');
    const monthSel = document.getElementById('sampleMonthSelect');

    function render(points){
      layer.clearLayers();
      const bounds = [];
      (points||[]).forEach(p => {
        const lat = toNum(p.lat), lon = toNum(p.lon);
        if (!isNum(lat) || !isNum(lon)) return;
        const sev = getSeverity(p);
        const color = colorForExceed(sev.exceed);
        const radius = Math.min(8, 6 + (sev.exceed*3));
        const m = L.circleMarker([lat, lon], { radius, fillColor: color, color: '#fff', weight: 1, fillOpacity: 0.85, opacity: 0.9 });
        m.bindPopup(buildPopup(p));
        m.addTo(layer);
        bounds.push([lat, lon]);
      });
      if (bounds.length) map.fitBounds(bounds, { padding: [30,30] });
      setTimeout(() => map.invalidateSize(), 60);
    }

    async function fetchPoints(){
      const params = [];
      const y = Number(yearSel && yearSel.value);
      const m = Number(monthSel && monthSel.value);
      if (yearSel && yearSel.value) params.push('year='+encodeURIComponent(y));
      if (monthSel && monthSel.value) params.push('month='+encodeURIComponent(m));
      const url = '/api/heavy-samples' + (params.length? ('?'+params.join('&')) : '');
      try {
        const res = await fetch(url, { cache: 'no-store' });
        const json = await res.json();
        render(json.points||[]);
      } catch(e){ console.error('heavy-map fetch', e); }
    }

    function populateSelectors(allPoints){
      const years = Array.from(new Set((allPoints||[]).map(p => p.year).filter(isNum))).sort((a,b)=>a-b);
      if (yearSel) {
        yearSel.innerHTML = '<option value="">All</option>' + years.map(y=>`<option value="${y}">${y}</option>`).join('');
      }
      const months = Array.from(new Set((allPoints||[]).map(p => p.month).filter(isNum))).sort((a,b)=>a-b);
      if (monthSel) {
        monthSel.innerHTML = '<option value="">All</option>' + months.map(m=>`<option value="${m}">${monthName(m)} (${m})</option>`).join('');
      }
    }

    async function init(){
      try {
        const res = await fetch('/api/heavy-samples', { cache: 'no-store' });
        const json = await res.json();
        const pts = json.points || [];
        populateSelectors(pts);
        render(pts);
      } catch(e){ console.error('heavy-map init', e); }
    }

    if (yearSel) yearSel.addEventListener('change', fetchPoints);
    if (monthSel) monthSel.addEventListener('change', fetchPoints);

    init();

    window.addEventListener('resize', () => map.invalidateSize());
  });
})();
