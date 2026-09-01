import Foundation

enum LocalConsoleAssets {
    static let html = #"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="color-scheme" content="light">
      <title>Scopeproof Local Console</title>
      <link rel="stylesheet" href="/assets/app.css">
      <script src="/assets/app.js" defer></script>
    </head>
    <body>
      <a class="skip-link" href="#main">Skip to evidence</a>
      <div class="app-shell">
        <aside class="sidebar">
          <div class="brand"><span class="brand-mark">S</span><div><strong>Scopeproof</strong><small>Local evidence console</small></div></div>
          <nav aria-label="Console sections">
            <button class="nav-item active" data-view="overview"><span>⌂</span>Overview</button>
            <button class="nav-item" data-view="evidence"><span>▱</span>Evidence library</button>
            <button class="nav-item" data-view="help"><span>?</span>Help & workflow</button>
          </nav>
          <div class="local-card"><span class="status-dot"></span><div><strong id="storage-mode">Local mode</strong><small id="storage-detail">Private to this Mac</small></div></div>
          <div class="identity"><span class="avatar" id="avatar">SP</span><div><strong id="local-user">Mac user</strong><small>Local administrator</small></div></div>
        </aside>

        <main id="main">
          <header class="topbar">
            <div><span class="eyebrow">Scopeproof Capture</span><h1 id="page-title">Local overview</h1></div>
            <div class="top-actions">
              <button class="button secondary" id="open-folder">Open evidence folder</button>
              <button class="button primary" id="capture">＋ Capture evidence</button>
            </div>
          </header>

          <div id="notice" class="notice hidden" role="status"></div>

          <section id="overview-view" class="view active" aria-labelledby="overview-heading">
            <div class="hero">
              <div><span class="pill success">Loopback protected</span><h2 id="overview-heading">One library for local and S3 evidence.</h2><p>Browse locally captured screenshots and the configured S3 evidence prefix from one organized view. Local files stay on this Mac; S3 access uses the verified app configuration.</p></div>
              <div class="hero-shield" aria-hidden="true">✓</div>
            </div>
            <div class="metrics" id="metrics" aria-label="Evidence summary"></div>
            <div class="grid-two">
              <section class="panel"><div class="panel-head"><div><span class="eyebrow">Recent activity</span><h2>Latest evidence</h2></div><button class="text-button" data-view-link="evidence">View all →</button></div><div id="recent-evidence" class="recent-list"></div></section>
              <section class="panel"><div class="panel-head"><div><span class="eyebrow">Configuration</span><h2>Local workspace</h2></div></div><dl class="status-list" id="workspace-status"></dl></section>
            </div>
          </section>

          <section id="evidence-view" class="view" aria-labelledby="evidence-heading">
            <div class="section-intro"><div><span class="eyebrow">Auditor-ready organization</span><h2 id="evidence-heading">Evidence library</h2><p>Browse screenshots by framework, control, assessment period, lifecycle state, and storage location.</p></div><div class="library-actions"><span id="result-count" class="result-count">0 items</span><button class="button secondary hidden" id="open-s3-browser" type="button">Browse / download S3</button><button class="button secondary" id="refresh-library" type="button">Refresh</button></div></div>
            <div id="storage-banner" class="storage-banner" role="status"></div>
            <form class="filter-bar" id="filters" role="search">
              <label class="search-field"><span class="sr-only">Search evidence</span><input id="search" type="search" placeholder="Search title, system, owner, tags, Jira, or evidence ID"></label>
              <label><span>Framework</span><select id="framework"><option value="">All frameworks</option></select></label>
              <label><span>Control</span><select id="control"><option value="">All controls</option></select></label>
              <label><span>Assessment period</span><select id="assessment-period"><option value="">All periods</option></select></label>
              <label><span>Storage</span><select id="storage-location"><option value="">All locations</option><option>Local</option><option>S3</option><option>Local + S3</option></select></label>
              <label><span>Status</span><select id="review-status"><option value="">All statuses</option><option>Draft</option><option>In Review</option><option>Approved</option><option>Rejected</option><option>Superseded</option><option>S3 only</option></select></label>
              <label><span>Group by</span><select id="group-by"><option value="control">Control</option><option value="assessmentPeriod">Assessment period</option><option value="framework">Framework</option><option value="none">No grouping</option></select></label>
              <button class="button secondary" type="button" id="clear-filters">Clear</button>
            </form>
            <div id="evidence-grid" class="library-groups"></div>
            <div id="empty-state" class="empty hidden"><div>▱</div><h3>No matching screenshots</h3><p>Adjust the filters, refresh the configured S3 prefix, or capture new evidence.</p><button class="button primary" type="button" id="empty-capture">Capture evidence</button></div>
          </section>

          <section id="help-view" class="view" aria-labelledby="help-heading">
            <div class="section-intro"><div><span class="eyebrow">Local-first workflow</span><h2 id="help-heading">How Scopeproof works</h2><p>The local console is an index and review surface. Immutable manifests and lifecycle files remain the source of truth.</p></div></div>
            <div class="help-grid">
              <article class="help-card"><span>1</span><h3>Classify before capture</h3><p>Choose the compliance framework, control, system, owner, assessment period, evidence title, and optional Jira issue in the menu-bar app.</p></article>
              <article class="help-card"><span>2</span><h3>Capture and redact</h3><p>Capture one window or combine two or more operator-scrolled viewports. Scopeproof scans locally, masks sensitive values, adds the visible evidence banner, and asks you to review the exact pixels.</p></article>
              <article class="help-card"><span>3</span><h3>Browse every location</h3><p>The library combines local screenshots with the app's verified S3 prefix, labels where each artifact exists, and groups evidence by control or assessment period.</p></article>
              <article class="help-card"><span>4</span><h3>Package for auditors</h3><p>Export approved evidence from the menu-bar app. Scopeproof verifies hashes and lifecycle history before creating the signed assessor ZIP.</p></article>
            </div>
            <section class="panel help-panel"><h2>Security boundaries</h2><ul><li>The console listens only on 127.0.0.1 and uses a new high-entropy browser session whenever Scopeproof launches.</li><li>State-changing requests require the session cookie and a same-origin browser request.</li><li>Filesystem paths, S3 object keys, and AWS credentials are never accepted from or exposed to the browser.</li><li>Local previews are served only after path containment, PNG signature, and SHA-256 manifest checks. S3-only screenshots are opened through the native validated download workflow.</li><li>The SQLite database is a disposable search index. Original PNG, manifest, lifecycle, and receipt files remain authoritative.</li></ul></section>
          </section>
        </main>
      </div>

      <dialog id="review-dialog">
        <form method="dialog" id="review-form">
          <div class="dialog-head"><div><span class="eyebrow">Lifecycle decision</span><h2 id="review-title">Review evidence</h2></div><button class="icon-button" id="review-close" type="button" aria-label="Close review dialog">×</button></div>
          <input type="hidden" id="review-evidence-id">
          <div class="form-grid">
            <label><span>Status</span><select id="review-state" required><option>Draft</option><option>In Review</option><option>Approved</option><option>Rejected</option><option>Superseded</option></select></label>
            <label><span>Owner</span><input id="review-owner" maxlength="160"></label>
            <label><span>Reviewer</span><input id="reviewer" maxlength="160" required></label>
            <label><span>Tags</span><input id="review-tags" maxlength="500" placeholder="identity, quarterly, production"></label>
          </div>
          <label><span>Review rationale</span><textarea id="review-notes" maxlength="4000" rows="5" placeholder="Explain what was reviewed, what the artifact proves, and any limitations."></textarea><small>Approval, rejection, and supersession require at least 20 characters.</small></label>
          <div class="dialog-actions"><button class="button secondary" id="review-cancel" type="button">Cancel</button><button class="button primary" id="save-review" type="submit" value="default">Save lifecycle event</button></div>
        </form>
      </dialog>
    </body>
    </html>
    """#

    static let css = #"""
    .evidence-card p{overflow-wrap:anywhere}.library-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.storage-banner{display:flex;align-items:center;gap:8px;margin-bottom:12px;padding:11px 13px;border:1px solid #dfe5f3;border-radius:11px;background:#f8faff;color:#536079;font-size:13px}.storage-banner.warning{border-color:#f0d5a7;background:#fff9ee;color:#82530b}.storage-banner strong{color:var(--ink)}.filter-bar{grid-template-columns:minmax(260px,2fr) repeat(3,minmax(135px,1fr))!important}.library-groups{display:grid;gap:24px;margin-top:18px}.evidence-group{display:grid;gap:11px}.group-heading{display:flex;align-items:end;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding:0 2px 9px}.group-heading h3{margin:0;font-size:18px}.group-heading small{color:var(--muted)}.evidence-group .evidence-grid{margin-top:0}.s3-placeholder{width:100%;aspect-ratio:16/8.7;background:linear-gradient(135deg,#eef2fb,#e3e9f5);display:grid;place-items:center;text-align:center;color:#53627d;padding:20px}.s3-placeholder span{display:block;font-size:28px;margin-bottom:8px}.s3-placeholder strong,.s3-placeholder small{display:block}.s3-placeholder small{margin-top:5px;color:#748199}.storage-pill{background:#e8efff;color:#2f4fac}.storage-pill.s3{background:#eee9ff;color:#6042a5}.storage-pill.both{background:#e2f5ed;color:#116a4b}.card-badges{display:flex;gap:6px;flex-wrap:wrap}.storage-meta{font-weight:650;color:#536079!important}.button:disabled{cursor:not-allowed;opacity:.48}.recent-thumb{width:52px;height:42px;border-radius:7px;display:grid;place-items:center;background:#e8edf7;color:#56657f;font-weight:800}.empty-inline{color:var(--muted);padding:12px 0}
    :root{--ink:#172033;--muted:#697287;--line:#e4e8ef;--surface:#fff;--canvas:#f4f6fa;--navy:#0b1731;--blue:#3d63e6;--blue-dark:#294cc5;--green:#11845b;--amber:#a96309;--red:#bc3344;--shadow:0 18px 50px rgba(17,27,53,.08);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:var(--canvas)}*{box-sizing:border-box}body{margin:0;min-width:320px;background:var(--canvas)}button,input,select,textarea{font:inherit}.skip-link{position:fixed;left:12px;top:-60px;z-index:10;background:#fff;padding:10px 14px;border-radius:8px}.skip-link:focus{top:12px}.app-shell{min-height:100vh;display:grid;grid-template-columns:248px minmax(0,1fr)}.sidebar{position:sticky;top:0;height:100vh;background:var(--navy);color:#fff;padding:26px 18px 20px;display:flex;flex-direction:column}.brand{display:flex;gap:12px;align-items:center;padding:0 8px 28px}.brand-mark{width:38px;height:38px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(145deg,#6886ff,#3555d8);font-weight:800}.brand strong,.brand small{display:block}.brand small{color:#9fabc5;margin-top:2px}.sidebar nav{display:grid;gap:6px}.nav-item{border:0;background:transparent;color:#b7c1d8;text-align:left;padding:11px 12px;border-radius:9px;display:flex;gap:11px;align-items:center;cursor:pointer}.nav-item:hover,.nav-item:focus-visible{background:#172746;color:#fff}.nav-item.active{background:#203457;color:#fff;font-weight:650}.local-card{margin-top:auto;border:1px solid #2a4169;background:#122445;border-radius:12px;padding:13px;display:flex;gap:10px;align-items:center}.local-card strong,.local-card small,.identity strong,.identity small{display:block}.local-card small,.identity small{color:#9fabc5;margin-top:3px}.status-dot{width:9px;height:9px;border-radius:50%;background:#4ed3a0;box-shadow:0 0 0 4px rgba(78,211,160,.12)}.identity{display:flex;gap:10px;align-items:center;padding:20px 8px 0}.avatar{width:34px;height:34px;display:grid;place-items:center;background:#dce4ff;color:#263f9d;border-radius:50%;font-size:12px;font-weight:800}main{min-width:0;padding:0 34px 52px}.topbar{height:96px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);gap:20px}.topbar h1{font-size:25px;margin:4px 0 0}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:800;color:#7a8499}.top-actions{display:flex;gap:10px}.button{border:1px solid transparent;border-radius:9px;padding:10px 14px;font-weight:700;cursor:pointer}.button:focus-visible,.nav-item:focus-visible,.text-button:focus-visible,.icon-button:focus-visible,input:focus,select:focus,textarea:focus{outline:3px solid rgba(61,99,230,.25);outline-offset:2px}.button.primary{background:var(--blue);color:#fff}.button.primary:hover{background:var(--blue-dark)}.button.secondary{background:#fff;border-color:#d8deea;color:#2d3850}.button.secondary:hover{background:#f8f9fc}.view{display:none;padding-top:28px}.view.active{display:block}.notice{margin-top:20px;padding:12px 14px;border-radius:10px;background:#e9f7f1;color:#146544;border:1px solid #bee6d6}.notice.error{background:#fff0f2;color:#9d2938;border-color:#f3c3ca}.hidden{display:none!important}.hero{background:linear-gradient(125deg,#fff 0%,#f3f6ff 100%);border:1px solid #dfe5f3;border-radius:18px;padding:30px 32px;display:flex;justify-content:space-between;align-items:center;box-shadow:var(--shadow)}.hero h2{font-size:30px;line-height:1.15;margin:12px 0 9px}.hero p{max-width:720px;color:var(--muted);line-height:1.6;margin:0}.hero-shield{width:78px;height:78px;border-radius:24px;display:grid;place-items:center;background:#e3f6ee;color:var(--green);font-size:34px;font-weight:800}.pill{display:inline-flex;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:800}.pill.success{background:#e2f5ed;color:#116a4b}.pill.warning{background:#fff2da;color:#8b5506}.pill.danger{background:#ffe7ea;color:#a12839}.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:18px 0}.metric{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px}.metric small{display:block;color:var(--muted);margin-bottom:8px}.metric strong{font-size:26px}.grid-two{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(300px,.8fr);gap:18px}.panel{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px}.panel-head,.section-intro{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.panel h2,.section-intro h2{margin:5px 0 0}.text-button{border:0;background:transparent;color:var(--blue);font-weight:750;cursor:pointer}.recent-list{display:grid;margin-top:14px}.recent-row{display:grid;grid-template-columns:52px minmax(0,1fr) auto;gap:12px;align-items:center;padding:12px 0;border-top:1px solid var(--line)}.recent-row img{width:52px;height:42px;border-radius:7px;object-fit:cover;background:#eef1f7}.recent-row strong,.recent-row small{display:block}.recent-row small{color:var(--muted);margin-top:4px}.status-list{margin:10px 0 0}.status-list div{display:flex;justify-content:space-between;gap:18px;padding:12px 0;border-top:1px solid var(--line)}.status-list dt{color:var(--muted)}.status-list dd{margin:0;text-align:right;font-weight:650;overflow-wrap:anywhere}.section-intro{margin-bottom:18px}.section-intro h2{font-size:28px}.section-intro p{color:var(--muted);margin:8px 0 0}.result-count{background:#e9edfb;color:#324ba6;padding:7px 10px;border-radius:999px;font-size:13px;font-weight:750}.filter-bar{background:#fff;border:1px solid var(--line);border-radius:13px;padding:14px;display:grid;grid-template-columns:minmax(240px,1.8fr) repeat(3,minmax(140px,1fr)) auto;gap:10px;align-items:end}.filter-bar label,.form-grid label,#review-form>label{display:grid;gap:6px;color:#5b6579;font-size:12px;font-weight:700}.filter-bar input,.filter-bar select,.form-grid input,.form-grid select,textarea{width:100%;border:1px solid #ccd3df;border-radius:8px;padding:9px 10px;background:#fff;color:var(--ink)}.evidence-grid{display:grid;grid-template-columns:repeat(3,minmax(260px,1fr));gap:16px;margin-top:16px}.evidence-card{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}.evidence-card img{width:100%;aspect-ratio:16/8.7;object-fit:cover;background:#e9edf4}.card-body{padding:16px;display:grid;gap:11px}.card-kicker{display:flex;justify-content:space-between;gap:10px;align-items:center}.card-kicker small{color:var(--muted)}.evidence-card h3{font-size:17px;margin:0}.evidence-card p{font-size:13px;color:var(--muted);margin:0}.tag-row{display:flex;gap:5px;flex-wrap:wrap}.tag{background:#f0f2f7;color:#4e596f;border-radius:999px;padding:4px 7px;font-size:11px}.card-actions{display:flex;gap:8px;margin-top:auto}.card-actions .button{flex:1;padding:8px}.integrity{color:var(--red)!important;font-weight:750}.empty{text-align:center;padding:70px 20px}.empty>div{font-size:40px;color:#8390a7}.empty h3{margin:12px 0 5px}.empty p{color:var(--muted)}.help-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.help-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px}.help-card>span{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:#e6ebff;color:#334fb4;font-weight:800}.help-card h3{margin:14px 0 8px}.help-card p,.help-panel li{color:var(--muted);line-height:1.55}.help-panel{margin-top:18px}.help-panel li+li{margin-top:8px}dialog{width:min(680px,calc(100vw - 32px));border:0;border-radius:17px;padding:0;box-shadow:0 30px 90px rgba(8,16,35,.28)}dialog::backdrop{background:rgba(10,19,40,.52)}#review-form{padding:24px}.dialog-head{display:flex;justify-content:space-between;align-items:flex-start}.dialog-head h2{margin:4px 0 0}.icon-button{border:0;background:#eef1f6;width:32px;height:32px;border-radius:50%;font-size:22px;cursor:pointer}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:20px 0 13px}textarea{resize:vertical;line-height:1.5}#review-form small{color:var(--muted);font-weight:500}.dialog-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}@media(max-width:1080px){.metrics{grid-template-columns:repeat(3,1fr)}.evidence-grid{grid-template-columns:repeat(2,minmax(240px,1fr))}.filter-bar{grid-template-columns:1fr 1fr!important}.help-grid{grid-template-columns:1fr 1fr}}@media(max-width:760px){.app-shell{display:block}.sidebar{position:static;height:auto;padding:16px}.brand{padding-bottom:14px}.sidebar nav{display:flex;overflow-x:auto}.nav-item{white-space:nowrap}.local-card,.identity{display:none}main{padding:0 16px 34px}.topbar{height:auto;padding:18px 0;align-items:flex-start}.top-actions{display:grid}.hero{padding:24px}.hero-shield{display:none}.metrics{grid-template-columns:1fr 1fr}.grid-two{grid-template-columns:1fr}.evidence-grid,.help-grid{grid-template-columns:1fr}.filter-bar{grid-template-columns:1fr!important}.form-grid{grid-template-columns:1fr}.section-intro{display:grid}.library-actions{justify-content:flex-start}}
    .preview-button{margin-top:12px;border:1px solid #b8c4db;border-radius:8px;background:#fff;color:#334a78;padding:8px 10px;font-weight:750;cursor:pointer}.preview-button:focus-visible{outline:3px solid rgba(61,99,230,.25);outline-offset:2px}
    """#

    static let javascript = #"""
    (() => {
      const state = { status: null, allEvidence: [], evidence: [], library: null, current: null };
      const $ = (id) => document.getElementById(id);
      const request = async (url, options = {}) => {
        const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
        return payload;
      };
      const showNotice = (message, isError = false) => {
        const notice = $('notice'); notice.textContent = message; notice.classList.remove('hidden', 'error');
        if (isError) notice.classList.add('error');
        window.clearTimeout(showNotice.timer); showNotice.timer = window.setTimeout(() => notice.classList.add('hidden'), 6000);
      };
      const node = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };
      const pillClass = (status) => status === 'Approved' ? 'success' : ['Rejected','Superseded'].includes(status) ? 'danger' : 'warning';
      const initials = (name) => name.split(/\s+/).filter(Boolean).slice(0,2).map((part) => part[0]).join('').toUpperCase() || 'SP';
      const formatBytes = (bytes) => bytes === null || bytes === undefined ? '' : bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes/1024).toFixed(1)} KB` : `${(bytes/1048576).toFixed(1)} MB`;
      const formatTimestamp = (value) => { const parsed=new Date(value); return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString([], {dateStyle:'medium',timeStyle:'short'}); };

      function switchView(view) {
        document.querySelectorAll('.view').forEach((item) => item.classList.toggle('active', item.id === `${view}-view`));
        document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
        $('page-title').textContent = view === 'overview' ? 'Local overview' : view === 'evidence' ? 'Evidence library' : 'Help & workflow';
      }

      function renderMetrics(summary, evidence = state.allEvidence) {
        const local=evidence.filter((item)=>item.localAvailable).length, s3=evidence.filter((item)=>item.s3Available).length, both=evidence.filter((item)=>item.localAvailable&&item.s3Available).length, s3IntegrityAlerts=evidence.filter((item)=>item.s3Available&&!item.s3IntegrityVerified).length;
        const metrics = [
          ['Unique screenshots', evidence.length || summary.total], ['Available locally', local || summary.total], ['Stored in S3', s3],
          ['In both locations', both], ['Integrity alerts', summary.integrityFailures+s3IntegrityAlerts]
        ];
        $('metrics').replaceChildren(...metrics.map(([label, value]) => { const item = node('article','metric'); item.append(node('small','',label), node('strong','',String(value))); return item; }));
      }

      function renderStatus(status) {
        state.status = status;
        $('local-user').textContent = status.localUser;
        $('avatar').textContent = initials(status.localUser);
        renderMetrics(status.summary);
        $('storage-mode').textContent=status.s3InventoryState==='Connected'||status.s3InventoryState==='Ready'?'Local + S3':'Local mode';
        $('storage-detail').textContent=status.s3Configured?`S3 · ${status.s3InventoryState}`:'Private to this Mac';
        const values = [
          ['Evidence folder', status.evidenceRoot], ['SQLite index', status.indexState],
          ['S3 evidence', status.s3Configured ? `${status.s3InventoryState} · ${status.s3Bucket}/${status.s3Prefix}` : 'Optional · not configured'],
          ['Hosted sync', status.hostedConnected ? `Optional · ${status.hostedServer}` : 'Optional · not connected'],
          ['Automatic upload', status.autoUpload ? 'Enabled' : 'Off'], ['Local retention', `${status.retentionDays} days`],
          ['Local audit events', String(status.summary.auditEvents)]
        ];
        $('workspace-status').replaceChildren(...values.map(([term, value]) => { const row=node('div'); row.append(node('dt','',term),node('dd','',value)); return row; }));
      }

      function evidenceCard(item) {
        const card = node('article','evidence-card');
        let image;
        if(item.localAvailable){ image=node('img'); image.loading='lazy'; image.alt=`Screenshot preview for ${item.title}`; image.src=`/api/evidence/${encodeURIComponent(item.evidenceID)}/image`; }
        else {
          image=node('div','s3-placeholder'); const icon=node('span','', '☁');
          image.append(icon,node('strong','', 'Stored in S3'),node('small','',item.s3PreviewAvailable?'Load this screenshot only when needed':'Validated S3 previews are disabled in the app configuration'));
          if(item.s3PreviewAvailable){ const load=node('button','preview-button','Load secure preview'); load.type='button'; load.addEventListener('click',()=>{ load.disabled=true;load.textContent='Loading…';const preview=node('img');preview.alt=`S3 screenshot preview for ${item.title}`;preview.addEventListener('load',()=>image.replaceWith(preview),{once:true});preview.addEventListener('error',()=>{load.disabled=false;load.textContent='Try preview again';showNotice('The S3 preview could not be loaded. Verify the AWS session and download permissions.',true);},{once:true});preview.src=`/api/evidence/${encodeURIComponent(item.evidenceID)}/s3-image`; }); image.append(load); }
        }
        const body=node('div','card-body'); const kicker=node('div','card-kicker');
        const badges=node('div','card-badges'); badges.append(node('span',`pill ${pillClass(item.reviewStatus)}`,item.reviewStatus),node('span',`pill storage-pill ${item.storageLocation==='S3'?'s3':item.storageLocation==='Local + S3'?'both':''}`,item.storageLocation));
        kicker.append(badges,node('small','',formatTimestamp(item.localTimestamp)));
        const title=node('h3','',item.title); const metaParts=[item.complianceArea,item.controlID,item.system].filter(Boolean); const meta=node('p','',metaParts.join(' · '));
        const periodParts=[item.environment,item.assessmentPeriod,item.jiraIssueKey].filter(Boolean); const period=node('p','',periodParts.join(' · '));
        const source=item.sourceURL ? node('p','',`URL · ${item.sourceURL}`) : null;
        const tags=node('div','tag-row'); item.tags.slice(0,6).forEach((tag) => tags.append(node('span','tag',tag)));
        if (item.safetyStatus === 'Legacy unsigned · browsing only') tags.append(node('span','integrity','Legacy unsigned · browsing only'));
        if (!item.lifecycleValid) tags.append(node('span','integrity','Lifecycle integrity requires attention'));
        if (item.s3IntegrityStatus) tags.append(node('span',item.s3IntegrityVerified?'tag':'integrity',item.s3IntegrityStatus));
        if(item.s3Available){ const versions=item.s3VersionCount>1?` · ${item.s3VersionCount} versions`:''; body.append(node('p','storage-meta',`S3 · ${formatBytes(item.s3SizeBytes)}${versions}`)); }
        const actions=node('div','card-actions');
        if(item.localAvailable){ const reveal=node('button','button secondary','Reveal'); reveal.type='button'; reveal.addEventListener('click',()=>performAction('/api/actions/reveal',{evidenceID:item.evidenceID},'Evidence revealed in Finder.')); actions.append(reveal); }
        if(item.reviewAvailable){ const review=node('button','button primary','Review'); review.type='button'; review.disabled=!item.lifecycleValid; review.addEventListener('click',()=>openReview(item)); actions.append(review); }
        if(item.s3Available){ const browse=node('button','button secondary',item.s3PreviewAvailable?'S3 files…':'Downloads off'); browse.type='button'; browse.disabled=!item.s3PreviewAvailable; if(item.s3PreviewAvailable)browse.addEventListener('click',openS3Browser); actions.append(browse); }
        const content=[kicker,title]; if(metaParts.length) content.push(meta); if(periodParts.length) content.push(period); body.prepend(...content); if(source) body.append(source); body.append(tags,actions); card.append(image,body); return card;
      }

      function renderEvidence(items) {
        state.evidence=items; $('result-count').textContent=`${items.length} ${items.length===1?'item':'items'}`;
        const grouping=$('group-by').value, groups=new Map();
        items.forEach((item)=>{ const key=grouping==='control'?`${item.controlID}${item.controlTitle?` — ${item.controlTitle}`:''}`:grouping==='assessmentPeriod'?(item.assessmentPeriod||'No assessment period'):grouping==='framework'?item.complianceArea:'All screenshots'; if(!groups.has(key))groups.set(key,[]); groups.get(key).push(item); });
        const sections=[...groups.entries()].map(([label,records])=>{ const section=node('section','evidence-group'); const heading=node('div','group-heading'); heading.append(node('h3','',label),node('small','',`${records.length} ${records.length===1?'screenshot':'screenshots'}`)); const grid=node('div','evidence-grid'); grid.append(...records.map(evidenceCard)); section.append(heading,grid); return section; });
        $('evidence-grid').replaceChildren(...sections); $('empty-state').classList.toggle('hidden',items.length>0);
        const recent=state.allEvidence.slice(0,5).map((item)=>{ const row=node('div','recent-row'); let image;if(item.localAvailable){image=node('img');image.alt='';image.src=`/api/evidence/${encodeURIComponent(item.evidenceID)}/image`;}else{image=node('div','recent-thumb','S3');} const copy=node('div'); copy.append(node('strong','',item.title),node('small','',`${item.controlID} · ${item.storageLocation} · ${formatTimestamp(item.localTimestamp)}`)); row.append(image,copy,node('span',`pill ${pillClass(item.reviewStatus)}`,item.reviewStatus)); return row; });
        $('recent-evidence').replaceChildren(...recent);
        if (!recent.length) { const empty=node('p','empty-inline', 'No screenshots are available locally or in the configured S3 prefix.'); $('recent-evidence').replaceChildren(empty); }
      }

      function filterEvidence() {
        const search=$('search').value.trim().toLowerCase(), framework=$('framework').value, control=$('control').value, period=$('assessment-period').value, storage=$('storage-location').value, status=$('review-status').value;
        const items=state.allEvidence.filter((item)=>{ const haystack=[item.title,item.evidenceID,item.complianceArea,item.controlID,item.controlTitle,item.system,item.environment,item.owner,item.reviewer,item.assessmentPeriod,item.jiraIssueKey,item.sourceURL,...item.tags].filter(Boolean).join(' ').toLowerCase(); return (!search||haystack.includes(search))&&(!framework||item.complianceArea===framework)&&(!control||item.controlID===control)&&(!period||item.assessmentPeriod===period)&&(!storage||item.storageLocation===storage)&&(!status||item.reviewStatus===status); });
        renderEvidence(items);
      }

      function renderStorage(storage) {
        state.library=storage; const connected=storage.s3State==='Connected';
        $('storage-mode').textContent=connected?'Local + S3':'Local mode'; $('storage-detail').textContent=storage.bucket?`S3 · ${storage.s3State}`:'Private to this Mac';
        $('open-s3-browser').classList.toggle('hidden',!storage.bucket||!storage.downloadsAllowed);
        const banner=$('storage-banner'); banner.classList.toggle('warning',Boolean(storage.warning));
        banner.replaceChildren(node('strong','',storage.mode),node('span','',storage.bucket?`S3 ${storage.s3State.toLowerCase()} · ${storage.bucket}/${storage.prefix}`:'S3 is optional and is not configured. Showing local screenshots.'));
        if(storage.warning) banner.append(node('span','',storage.warning));
      }

      async function loadEvidence(refreshS3=false) {
        $('refresh-library').disabled=true; $('refresh-library').textContent='Refreshing…';
        try { const payload=await request(`/api/library${refreshS3?'?refreshS3=1':''}`); state.allEvidence=payload.evidence; populateOptions('framework',payload.facets.frameworks,'All frameworks'); populateOptions('control',payload.facets.controls,'All controls'); populateOptions('assessment-period',payload.facets.assessmentPeriods,'All periods'); renderStorage(payload.storage); renderMetrics(state.status.summary,state.allEvidence); filterEvidence(); if(payload.storage.warning) showNotice(payload.storage.warning,true); }
        finally { $('refresh-library').disabled=false; $('refresh-library').textContent='Refresh'; }
      }

      function populateOptions(id, values, label) { const select=$(id), current=select.value; select.replaceChildren(new Option(label,''),...values.map((value)=>new Option(value,value))); select.value=current; }
      async function performAction(url, body, success) { try { await request(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); showNotice(success); } catch(error){ showNotice(error.message,true); } }
      function openS3Browser(){ performAction('/api/actions/open-s3-browser',{},'S3 browser opened in Scopeproof.'); }
      function openReview(item) { state.current=item; $('review-evidence-id').value=item.evidenceID; $('review-title').textContent=`Review ${item.evidenceID}`; $('review-state').value=item.reviewStatus; $('review-owner').value=item.owner; $('reviewer').value=item.reviewer || state.status.localUser; $('review-tags').value=item.tags.join(', '); $('review-notes').value=item.reviewNotes; $('review-dialog').showModal(); }
      async function saveReview(event) {
        event.preventDefault(); const status=$('review-state').value, notes=$('review-notes').value.trim();
        if (['Approved','Rejected','Superseded'].includes(status) && notes.length<20) { showNotice('Enter at least 20 characters explaining this decision.',true); return; }
        try { await request(`/api/evidence/${encodeURIComponent($('review-evidence-id').value)}/review`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status,owner:$('review-owner').value,reviewer:$('reviewer').value,notes,tags:$('review-tags').value.split(',').map((value)=>value.trim()).filter(Boolean)})}); $('review-dialog').close(); await refresh(); showNotice('Lifecycle event saved and indexed.'); } catch(error){ showNotice(error.message,true); }
      }
      async function refresh(){ const status=await request('/api/status'); renderStatus(status); await loadEvidence(); }
      function capture(){ performAction('/api/actions/capture',{},'Capture dialog opened in Scopeproof.'); }

      document.querySelectorAll('[data-view]').forEach((button)=>button.addEventListener('click',()=>switchView(button.dataset.view)));
      document.querySelectorAll('[data-view-link]').forEach((button)=>button.addEventListener('click',()=>switchView(button.dataset.viewLink)));
      $('filters').addEventListener('input',()=>{ window.clearTimeout(filterEvidence.timer); filterEvidence.timer=window.setTimeout(filterEvidence,100); });
      $('clear-filters').addEventListener('click',()=>{ $('filters').reset(); filterEvidence(); });
      $('refresh-library').addEventListener('click',()=>loadEvidence(true).then(()=>showNotice('Evidence library refreshed.')).catch((error)=>showNotice(error.message,true)));
      $('open-s3-browser').addEventListener('click',openS3Browser);
      $('open-folder').addEventListener('click',()=>performAction('/api/actions/open-folder',{},'Evidence folder opened.'));
      $('capture').addEventListener('click',capture); $('empty-capture').addEventListener('click',capture); $('review-form').addEventListener('submit',saveReview);
      $('review-close').addEventListener('click',()=>$('review-dialog').close()); $('review-cancel').addEventListener('click',()=>$('review-dialog').close());
      refresh().catch((error)=>showNotice(error.message,true));
    })();
    """#
}
