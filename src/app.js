(function () {
  "use strict";

  const STORE_KEY = "angel-gates-state-v1";

  const navItems = [
    { id: "overview", label: "Manager Dashboard", countKey: null },
    { id: "controllers", label: "Controllers", countKey: "gates" },
    { id: "residents", label: "Resident App", countKey: "residents" },
    { id: "passes", label: "Visitor Passes", countKey: "passes" },
    { id: "edge", label: "Live Edge", countKey: null },
    { id: "integrations", label: "Integrations", countKey: "integrations" },
    { id: "maintenance", label: "Maintenance", countKey: "alerts" },
    { id: "audit", label: "Audit Logs", countKey: "audits" },
    { id: "sync", label: "Cloud Sync", countKey: null }
  ];

  const credentialTypes = ["License plate", "QR code", "PIN"];
  const providers = ["DoorKing", "Linear", "LiftMaster", "Custom relay controller", "Cloud API"];
  const triggerModes = ["Dry-contact relay intent", "Wiegand credential handoff", "API authorization callback"];
  const operatorClasses = ["Barrier gate operator", "Slide or swing gate operator", "Pedestrian controlled door"];
  const alertSeverities = ["Critical", "Attention", "Scheduled"];

  const defaultState = () => ({
    version: 1,
    settings: {
      siteName: "",
      cloudEndpoint: "",
      edgeApiUrl: "",
      edgeApiToken: "",
      syncMode: "Manual export",
      lastExportAt: "",
      lastImportAt: ""
    },
    gates: [],
    residents: [],
    passes: [],
    integrations: [],
    alerts: [],
    audits: []
  });

  let state = loadState();
  let activeView = getInitialView();
  let latestDecision = null;
  let edgeEvents = [];
  let edgeStatus = null;
  let edgePollTimer = null;

  const root = document.getElementById("view-root");
  const nav = document.getElementById("primary-nav");

  document.addEventListener("DOMContentLoaded", () => {
    render();
    document.getElementById("export-workspace-button").addEventListener("click", exportWorkspace);
    document.getElementById("reset-workspace-button").addEventListener("click", clearWorkspace);
    window.addEventListener("hashchange", () => {
      activeView = getInitialView();
      render();
    });
  });

  function loadState() {
    const empty = defaultState();
    try {
      const stored = JSON.parse(localStorage.getItem(STORE_KEY));
      if (!stored || typeof stored !== "object") {
        return empty;
      }

      return {
        ...empty,
        ...stored,
        settings: { ...empty.settings, ...(stored.settings || {}) },
        gates: Array.isArray(stored.gates) ? stored.gates : [],
        residents: Array.isArray(stored.residents) ? stored.residents : [],
        passes: Array.isArray(stored.passes) ? stored.passes : [],
        integrations: Array.isArray(stored.integrations) ? stored.integrations : [],
        alerts: Array.isArray(stored.alerts) ? stored.alerts : [],
        audits: Array.isArray(stored.audits) ? stored.audits : []
      };
    } catch (error) {
      console.warn("Unable to load local workspace", error);
      return empty;
    }
  }

  function saveState() {
    localStorage.setItem(STORE_KEY, JSON.stringify(state));
    render();
  }

  function getInitialView() {
    const hash = window.location.hash.replace("#", "");
    return navItems.some((item) => item.id === hash) ? hash : "overview";
  }

  function render() {
    stopEdgePolling();
    renderNav();
    renderMetrics();
    renderTopbar();
    root.innerHTML = viewMarkup(activeView);
    bindView(activeView);
  }

  function renderNav() {
    nav.innerHTML = navItems
      .map((item) => {
        const count = item.countKey ? state[item.countKey].length : "";
        return `
          <a class="nav-link ${activeView === item.id ? "active" : ""}" href="#${item.id}">
            <span>${item.label}</span>
            ${item.countKey ? `<span class="nav-count">${count}</span>` : ""}
          </a>
        `;
      })
      .join("");
  }

  function renderMetrics() {
    document.getElementById("metric-gates").textContent = state.gates.length;
    document.getElementById("metric-residents").textContent = state.residents.length;
    document.getElementById("metric-passes").textContent = state.passes.length;
    document.getElementById("metric-audits").textContent = state.audits.length;

    const syncStatus = state.settings.cloudEndpoint ? "Cloud endpoint configured" : "Local workspace";
    document.getElementById("rail-sync-status").textContent = syncStatus;
  }

  function renderTopbar() {
    const titles = {
      overview: ["Manager Dashboard", "Access authorization layer"],
      controllers: ["Retrofit Controller", "Authorize before any relay intent"],
      residents: ["Resident App", "Resident credentials and app status"],
      passes: ["Visitor Passes", "Time-bound access credentials"],
      edge: ["Live Edge", "Direct-to-edge pilot console"],
      integrations: ["System Integrations", "Existing gate systems stay in the loop"],
      maintenance: ["Maintenance Alerts", "Operational issues tied to controllers"],
      audit: ["Audit Logs", "Every decision and configuration action"],
      sync: ["Cloud Sync", "Workspace export, import, and endpoint settings"]
    };
    const [kicker, title] = titles[activeView] || titles.overview;
    document.getElementById("section-kicker").textContent = kicker;
    document.getElementById("section-title").textContent = title;
  }

  function viewMarkup(view) {
    const views = {
      overview: overviewView,
      controllers: controllersView,
      residents: residentsView,
      passes: passesView,
      edge: edgeView,
      integrations: integrationsView,
      maintenance: maintenanceView,
      audit: auditView,
      sync: syncView
    };
    return (views[view] || overviewView)();
  }

  function bindView(view) {
    const bindings = {
      overview: bindOverview,
      controllers: bindControllers,
      residents: bindResidents,
      passes: bindPasses,
      edge: bindEdge,
      integrations: bindIntegrations,
      maintenance: bindMaintenance,
      audit: bindAudit,
      sync: bindSync
    };
    (bindings[view] || function () {})();
  }

  function overviewView() {
    return `
      <div class="view-grid">
        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Bucket One</p>
              <h2>V1 Scope</h2>
              <p>Build the modern access-control layer that coordinates residents, visitors, credentials, audit trails, maintenance, cloud handoff, and existing gate systems.</p>
            </div>
          </div>
          <div class="surface-body">
            <ul class="stack-list">
              <li><strong>Resident app and visitor passes</strong><span>Residents can manage approved, time-bound access without replacing the property manager workflow.</span></li>
              <li><strong>Credential decision engine</strong><span>License plate, QR, and PIN checks resolve to an authorization decision before relay intent is issued.</span></li>
              <li><strong>Manager dashboard and audit logs</strong><span>Operators get accountable records for access decisions, configuration changes, and maintenance issues.</span></li>
              <li><strong>Retrofit controller strategy</strong><span>Existing DoorKing, Linear, LiftMaster, or relay-based systems remain the physical control path.</span></li>
            </ul>
          </div>
        </section>

        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Bucket Two</p>
              <h2>Safety and Compliance Boundary</h2>
              <p>The product must not imply it replaces certified gate operators, required entrapment protection, installer commissioning, or property safety procedures.</p>
            </div>
          </div>
          <div class="surface-body">
            <ul class="stack-list boundary-list">
              <li><strong>UL 294 design path</strong><span>Access-control equipment and activity reporting should be designed with physical access-control certification in mind.</span></li>
              <li><strong>UL 325 gate operator boundary</strong><span>Barrier and gate operator safety remains with listed operators, installed protections, and qualified installers.</span></li>
              <li><strong>Relay intent only after authorization</strong><span>The app records an authorized relay intent; certified field hardware and site rules govern physical motion.</span></li>
              <li><strong>No bypass of entrapment protection</strong><span>Safety devices, loops, photo eyes, reversing edges, and operator logic stay mandatory.</span></li>
            </ul>
          </div>
        </section>

        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Edge Authorization</p>
              <h2>Ask the edge for a decision</h2>
              <p>The dashboard never computes allow or deny. It sends the tuple to the local edge API and renders the edge response.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="access-form" class="form-grid compact">
              <div class="field">
                <label for="access-credential-type">Credential type</label>
                <select id="access-credential-type" name="credentialType" required>
                  ${options(credentialTypes)}
                </select>
              </div>
              <div class="field">
                <label for="access-credential-value">Credential value</label>
                <input id="access-credential-value" name="credentialValue" autocomplete="off" required>
              </div>
              <div class="field">
                <label for="access-gate-id">Gate ID</label>
                <input id="access-gate-id" name="gateId" autocomplete="off" required>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Evaluate Access</button>
              </div>
            </form>
            <div class="decision-output ${latestDecision ? latestDecision.decision : ""}" id="decision-output">
              ${decisionMarkup()}
            </div>
          </div>
        </section>

        <section class="surface third">
          <div class="surface-body">
            <p class="eyebrow">Today</p>
            <h3>Configured controllers</h3>
            ${state.gates.length ? `<p>${state.gates.length} controller record${plural(state.gates.length)} in the workspace.</p>` : emptyStateMarkup("No controllers configured", "Add real controller records before evaluating site access.")}
          </div>
        </section>
        <section class="surface third">
          <div class="surface-body">
            <p class="eyebrow">Access</p>
            <h3>Active credentials</h3>
            <p>${activeCredentialCount()} credential${plural(activeCredentialCount())} available across residents and visitor passes.</p>
          </div>
        </section>
        <section class="surface third">
          <div class="surface-body">
            <p class="eyebrow">Operations</p>
            <h3>Open maintenance</h3>
            <p>${openAlertCount()} open alert${plural(openAlertCount())} tied to configured controllers.</p>
          </div>
        </section>
      </div>
    `;
  }

  function controllersView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Add Controller</p>
              <h2>Retrofit gate controller record</h2>
              <p>Records should describe the authorization interface. Certified gate operators and required protection devices remain outside this app boundary.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="controller-form" class="form-grid">
              <div class="field">
                <label for="controller-name">Controller name</label>
                <input id="controller-name" name="name" required>
              </div>
              <div class="field">
                <label for="controller-area">Site area</label>
                <input id="controller-area" name="area" required>
              </div>
              <div class="field">
                <label for="controller-class">Operator category</label>
                <select id="controller-class" name="operatorClass" required>${options(operatorClasses)}</select>
              </div>
              <div class="field">
                <label for="controller-provider">Existing system</label>
                <select id="controller-provider" name="provider" required>${options(providers)}</select>
              </div>
              <div class="field">
                <label for="controller-trigger">Authorization interface</label>
                <select id="controller-trigger" name="triggerMode" required>${options(triggerModes)}</select>
              </div>
              <div class="field">
                <label for="controller-hardware-id">Hardware identifier</label>
                <input id="controller-hardware-id" name="hardwareId" required>
              </div>
              <div class="field full checkbox-field">
                <input id="controller-safety" name="safetyAcknowledged" type="checkbox" required>
                <label for="controller-safety">Certified operator, required entrapment protection, and installer commissioning remain in place for this controller.</label>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Add Controller</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Controller Registry</p>
              <h2>Configured controllers</h2>
            </div>
          </div>
          <div class="surface-body">
            ${controllersTable()}
          </div>
        </section>
      </div>
    `;
  }

  function residentsView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Resident App</p>
              <h2>Resident credential profile</h2>
              <p>Resident records start empty. Add only real authorized residents and credentials.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="resident-form" class="form-grid">
              <div class="field">
                <label for="resident-name">Resident name</label>
                <input id="resident-name" name="name" autocomplete="name" required>
              </div>
              <div class="field">
                <label for="resident-unit">Unit or address</label>
                <input id="resident-unit" name="unit" required>
              </div>
              <div class="field">
                <label for="resident-credential-type">Credential type</label>
                <select id="resident-credential-type" name="credentialType" required>${options(credentialTypes)}</select>
              </div>
              <div class="field">
                <label for="resident-credential-value">Credential value</label>
                <input id="resident-credential-value" name="credentialValue" autocomplete="off" required>
              </div>
              <div class="field">
                <label for="resident-gate-id">Allowed controller</label>
                <select id="resident-gate-id" name="gateId" required>${gateOptions(true)}</select>
              </div>
              <div class="field">
                <label for="resident-status">App status</label>
                <select id="resident-status" name="status" required>${options(["Active", "Suspended"])}</select>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Add Resident</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Resident Records</p>
              <h2>Authorized residents</h2>
            </div>
          </div>
          <div class="surface-body">${residentsTable()}</div>
        </section>
      </div>
    `;
  }

  function passesView() {
    const now = toDatetimeLocal(new Date());
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Visitor Passes</p>
              <h2>Issue time-bound access</h2>
              <p>Passes are evaluated by credential, controller, status, start time, and expiration.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="pass-form" class="form-grid">
              <div class="field">
                <label for="pass-visitor-name">Visitor name</label>
                <input id="pass-visitor-name" name="visitorName" required>
              </div>
              <div class="field">
                <label for="pass-sponsor-name">Resident or manager sponsor</label>
                <input id="pass-sponsor-name" name="sponsorName" required>
              </div>
              <div class="field">
                <label for="pass-credential-type">Credential type</label>
                <select id="pass-credential-type" name="credentialType" required>${options(credentialTypes)}</select>
              </div>
              <div class="field">
                <label for="pass-credential-value">Credential value</label>
                <input id="pass-credential-value" name="credentialValue" autocomplete="off" required>
              </div>
              <div class="field">
                <label for="pass-gate-id">Allowed controller</label>
                <select id="pass-gate-id" name="gateId" required>${gateOptions(true)}</select>
              </div>
              <div class="field">
                <label for="pass-starts-at">Starts at</label>
                <input id="pass-starts-at" name="startsAt" type="datetime-local" value="${now}" required>
              </div>
              <div class="field">
                <label for="pass-expires-at">Expires at</label>
                <input id="pass-expires-at" name="expiresAt" type="datetime-local" required>
              </div>
              <div class="field">
                <label for="pass-status">Pass status</label>
                <select id="pass-status" name="status" required>${options(["Active", "Suspended"])}</select>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Create Visitor Pass</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Pass Registry</p>
              <h2>Visitor passes</h2>
            </div>
          </div>
          <div class="surface-body">${passesTable()}</div>
        </section>
      </div>
    `;
  }

  function edgeView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Direct Edge Link</p>
              <h2>Connect to the local controller API</h2>
              <p>Pilot dashboards talk directly to the on-site edge box over LAN or localhost. Every request uses the bearer token configured on the edge.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="edge-settings-form" class="form-grid">
              <div class="field">
                <label for="edge-api-url">Edge API URL</label>
                <input id="edge-api-url" name="edgeApiUrl" type="url" value="${escapeHtml(state.settings.edgeApiUrl)}" required>
              </div>
              <div class="field">
                <label for="edge-api-token">Bearer token</label>
                <input id="edge-api-token" name="edgeApiToken" type="password" value="${escapeHtml(state.settings.edgeApiToken)}" required>
              </div>
              <div class="field full">
                <div class="button-row">
                  <button class="primary-button" type="submit">Save Edge Link</button>
                  <button class="secondary-button" id="edge-test-button" type="button">Check Edge</button>
                </div>
              </div>
            </form>
          </div>
        </section>

        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Health</p>
              <h2>Edge status</h2>
            </div>
          </div>
          <div class="surface-body" id="edge-status-panel">
            ${edgeStatusMarkup()}
          </div>
        </section>

        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Live Feed</p>
              <h2>Entry events</h2>
            </div>
          </div>
          <div class="surface-body">
            <div class="live-feed" id="edge-event-feed">
              ${edgeEventsMarkup()}
            </div>
          </div>
        </section>
      </div>
    `;
  }

  function integrationsView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Integrations</p>
              <h2>Connect existing access systems</h2>
              <p>Configuration records capture provider, account label, transport, and endpoint. The app does not claim connectivity until a real endpoint is entered and implemented server-side.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="integration-form" class="form-grid">
              <div class="field">
                <label for="integration-provider">Provider</label>
                <select id="integration-provider" name="provider" required>${options(providers)}</select>
              </div>
              <div class="field">
                <label for="integration-name">Account or site label</label>
                <input id="integration-name" name="name" required>
              </div>
              <div class="field">
                <label for="integration-mode">Transport</label>
                <select id="integration-mode" name="mode" required>${options(["Local bridge", "Cloud API", "Event export"])}</select>
              </div>
              <div class="field">
                <label for="integration-endpoint">Endpoint URL</label>
                <input id="integration-endpoint" name="endpoint" type="url">
                <span class="helper">Leave blank only when the transport is not URL based.</span>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Save Integration</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Configured Systems</p>
              <h2>Integration records</h2>
            </div>
          </div>
          <div class="surface-body">${integrationsTable()}</div>
        </section>
      </div>
    `;
  }

  function maintenanceView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Maintenance</p>
              <h2>Create maintenance alert</h2>
              <p>Alerts are operational records for configured controllers. They do not replace site safety inspection requirements.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="alert-form" class="form-grid">
              <div class="field">
                <label for="alert-gate-id">Controller</label>
                <select id="alert-gate-id" name="gateId" required>${gateOptions(false)}</select>
              </div>
              <div class="field">
                <label for="alert-severity">Severity</label>
                <select id="alert-severity" name="severity" required>${options(alertSeverities)}</select>
              </div>
              <div class="field">
                <label for="alert-title">Alert title</label>
                <input id="alert-title" name="title" required>
              </div>
              <div class="field">
                <label for="alert-due-at">Due date</label>
                <input id="alert-due-at" name="dueAt" type="date" required>
              </div>
              <div class="field full">
                <label for="alert-notes">Notes</label>
                <textarea id="alert-notes" name="notes"></textarea>
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Create Alert</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Alert Queue</p>
              <h2>Maintenance alerts</h2>
            </div>
          </div>
          <div class="surface-body">${alertsTable()}</div>
        </section>
      </div>
    `;
  }

  function auditView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Audit Logs</p>
              <h2>Workspace event trail</h2>
              <p>Events are generated only by actions taken in this local workspace.</p>
            </div>
            <button class="secondary-button" id="export-audit-button" type="button">Export Audit JSON</button>
          </div>
          <div class="surface-body">${auditTable()}</div>
        </section>
      </div>
    `;
  }

  function syncView() {
    return `
      <div class="view-grid">
        <section class="surface full">
          <div class="section-head">
            <div>
              <p class="eyebrow">Cloud Sync</p>
              <h2>Workspace sync settings</h2>
              <p>Static builds cannot perform authenticated cloud sync by themselves. These settings define the endpoint contract for the backend layer.</p>
            </div>
          </div>
          <div class="surface-body">
            <form id="sync-form" class="form-grid">
              <div class="field">
                <label for="sync-site-name">Site name</label>
                <input id="sync-site-name" name="siteName" value="${escapeHtml(state.settings.siteName)}">
              </div>
              <div class="field">
                <label for="sync-mode">Sync mode</label>
                <select id="sync-mode" name="syncMode" required>${options(["Manual export", "Backend endpoint"], state.settings.syncMode)}</select>
              </div>
              <div class="field full">
                <label for="sync-endpoint">Cloud endpoint URL</label>
                <input id="sync-endpoint" name="cloudEndpoint" type="url" value="${escapeHtml(state.settings.cloudEndpoint)}">
              </div>
              <div class="field full">
                <button class="primary-button" type="submit">Save Sync Settings</button>
              </div>
            </form>
          </div>
        </section>
        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Export</p>
              <h2>Workspace JSON</h2>
            </div>
          </div>
          <div class="surface-body">
            <p class="notice"><strong>Manual export</strong>Export includes controllers, residents, visitor passes, integrations, alerts, settings, and audit logs from this browser workspace.</p>
            <div class="button-row">
              <button class="primary-button" id="sync-export-button" type="button">Export Workspace</button>
            </div>
            <p class="timestamp">Last export: ${state.settings.lastExportAt ? formatDate(state.settings.lastExportAt) : "None"}</p>
          </div>
        </section>
        <section class="surface">
          <div class="section-head">
            <div>
              <p class="eyebrow">Import</p>
              <h2>Restore workspace JSON</h2>
            </div>
          </div>
          <div class="surface-body">
            <input class="file-input" id="sync-import-input" type="file" accept="application/json">
            <p class="timestamp">Last import: ${state.settings.lastImportAt ? formatDate(state.settings.lastImportAt) : "None"}</p>
          </div>
        </section>
      </div>
    `;
  }

  function bindOverview() {
    const form = document.getElementById("access-form");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(form));
      latestDecision = {
        decision: "",
        reason: "Waiting for edge response..."
      };
      render();
      try {
        const result = await requestEdgeAuthorization(data);
        latestDecision = {
          decision: result.decision === "allow" ? "authorized" : "denied",
          reason: `${result.reason}. Event ${result.event_id}.`
        };
      } catch (error) {
        latestDecision = {
          decision: "denied",
          reason: error.message
        };
      }
      render();
    });
  }

  function bindControllers() {
    document.getElementById("controller-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      const gate = {
        id: createId("gate"),
        name: data.name.trim(),
        area: data.area.trim(),
        operatorClass: data.operatorClass,
        provider: data.provider,
        triggerMode: data.triggerMode,
        hardwareId: data.hardwareId.trim(),
        createdAt: new Date().toISOString()
      };
      state.gates.unshift(gate);
      addAudit({
        type: "configuration",
        title: "Controller added",
        detail: gate.name,
        gateId: gate.id
      });
      saveState();
    });
  }

  function bindResidents() {
    document.getElementById("resident-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      const resident = {
        id: createId("resident"),
        name: data.name.trim(),
        unit: data.unit.trim(),
        credentialType: data.credentialType,
        credentialValue: normalizeCredential(data.credentialType, data.credentialValue),
        gateId: data.gateId,
        status: data.status,
        createdAt: new Date().toISOString()
      };
      state.residents.unshift(resident);
      addAudit({
        type: "configuration",
        title: "Resident added",
        detail: resident.name,
        gateId: resident.gateId
      });
      saveState();
    });
  }

  function bindPasses() {
    document.getElementById("pass-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      const startsAt = new Date(data.startsAt);
      const expiresAt = new Date(data.expiresAt);

      if (Number.isNaN(startsAt.getTime()) || Number.isNaN(expiresAt.getTime()) || expiresAt <= startsAt) {
        window.alert("Expiration must be later than the start time.");
        return;
      }

      const pass = {
        id: createId("pass"),
        visitorName: data.visitorName.trim(),
        sponsorName: data.sponsorName.trim(),
        credentialType: data.credentialType,
        credentialValue: normalizeCredential(data.credentialType, data.credentialValue),
        gateId: data.gateId,
        startsAt: startsAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        status: data.status,
        createdAt: new Date().toISOString()
      };
      state.passes.unshift(pass);
      addAudit({
        type: "configuration",
        title: "Visitor pass created",
        detail: `${pass.visitorName} sponsored by ${pass.sponsorName}`,
        gateId: pass.gateId
      });
      saveState();
    });
  }

  function bindEdge() {
    const form = document.getElementById("edge-settings-form");
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(form));
      state.settings.edgeApiUrl = data.edgeApiUrl.trim().replace(/\/+$/, "");
      state.settings.edgeApiToken = data.edgeApiToken.trim();
      saveState();
    });

    document.getElementById("edge-test-button").addEventListener("click", async () => {
      await refreshEdgeStatus();
      await refreshEdgeEvents();
      renderEdgePanels();
    });

    startEdgePolling();
  }

  function bindIntegrations() {
    document.getElementById("integration-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      const integration = {
        id: createId("integration"),
        provider: data.provider,
        name: data.name.trim(),
        mode: data.mode,
        endpoint: data.endpoint.trim(),
        createdAt: new Date().toISOString()
      };
      state.integrations.unshift(integration);
      addAudit({
        type: "configuration",
        title: "Integration saved",
        detail: `${integration.provider} ${integration.mode}`
      });
      saveState();
    });
  }

  function bindMaintenance() {
    document.getElementById("alert-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      const alert = {
        id: createId("alert"),
        gateId: data.gateId,
        severity: data.severity,
        title: data.title.trim(),
        dueAt: data.dueAt,
        notes: data.notes.trim(),
        status: "Open",
        createdAt: new Date().toISOString()
      };
      state.alerts.unshift(alert);
      addAudit({
        type: "maintenance",
        title: "Maintenance alert created",
        detail: alert.title,
        gateId: alert.gateId
      });
      saveState();
    });

    document.querySelectorAll("[data-resolve-alert]").forEach((button) => {
      button.addEventListener("click", () => {
        const alert = state.alerts.find((item) => item.id === button.dataset.resolveAlert);
        if (!alert) return;
        alert.status = "Resolved";
        alert.resolvedAt = new Date().toISOString();
        addAudit({
          type: "maintenance",
          title: "Maintenance alert resolved",
          detail: alert.title,
          gateId: alert.gateId
        });
        saveState();
      });
    });
  }

  function bindAudit() {
    const button = document.getElementById("export-audit-button");
    if (button) {
      button.addEventListener("click", () => downloadJson("angel-gates-audit.json", state.audits));
    }
  }

  function bindSync() {
    document.getElementById("sync-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      state.settings.siteName = data.siteName.trim();
      state.settings.syncMode = data.syncMode;
      state.settings.cloudEndpoint = data.cloudEndpoint.trim();
      addAudit({
        type: "configuration",
        title: "Sync settings saved",
        detail: state.settings.syncMode
      });
      saveState();
    });

    document.getElementById("sync-export-button").addEventListener("click", exportWorkspace);
    document.getElementById("sync-import-input").addEventListener("change", importWorkspace);
  }

  async function requestEdgeAuthorization(data) {
    return edgeRequest("/authorize", {
      method: "POST",
      body: JSON.stringify({
        credential_type: edgeCredentialType(data.credentialType),
        credential_value: data.credentialValue,
        gate_id: data.gateId,
        request_source: "dashboard"
      })
    });
  }

  function edgeCredentialType(label) {
    if (label === "License plate") return "plate";
    if (label === "QR code") return "qr";
    if (label === "PIN") return "pin";
    return String(label || "").toLowerCase();
  }

  async function edgeRequest(path, options = {}) {
    if (!state.settings.edgeApiUrl || !state.settings.edgeApiToken) {
      throw new Error("Edge API URL and bearer token are required.");
    }
    const response = await fetch(`${state.settings.edgeApiUrl}${path}`, {
      ...options,
      headers: {
        "Authorization": `Bearer ${state.settings.edgeApiToken}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || `Edge API returned ${response.status}.`);
    }
    return body;
  }

  async function refreshEdgeStatus() {
    edgeStatus = await edgeRequest("/health");
    return edgeStatus;
  }

  async function refreshEdgeEvents() {
    const latestSequence = edgeEvents.reduce((max, event) => Math.max(max, Number(event.sequence || 0)), 0);
    const path = latestSequence ? `/events?after_sequence=${latestSequence}&limit=50` : "/events?limit=25";
    const result = await edgeRequest(path);
    const incoming = Array.isArray(result.events) ? result.events : [];
    if (latestSequence) {
      edgeEvents = [...incoming.reverse(), ...edgeEvents].slice(0, 50);
    } else {
      edgeEvents = incoming;
    }
    return edgeEvents;
  }

  function startEdgePolling() {
    if (!state.settings.edgeApiUrl || !state.settings.edgeApiToken) {
      return;
    }
    refreshEdgeStatus()
      .then(refreshEdgeEvents)
      .then(renderEdgePanels)
      .catch((error) => {
        edgeStatus = { error: error.message };
        renderEdgePanels();
      });
    edgePollTimer = window.setInterval(() => {
      refreshEdgeEvents().then(renderEdgePanels).catch(() => {});
    }, 2500);
  }

  function stopEdgePolling() {
    if (edgePollTimer) {
      window.clearInterval(edgePollTimer);
      edgePollTimer = null;
    }
  }

  function renderEdgePanels() {
    const statusPanel = document.getElementById("edge-status-panel");
    const feed = document.getElementById("edge-event-feed");
    if (statusPanel) {
      statusPanel.innerHTML = edgeStatusMarkup();
    }
    if (feed) {
      feed.innerHTML = edgeEventsMarkup();
    }
  }

  function edgeStatusMarkup() {
    if (!state.settings.edgeApiUrl || !state.settings.edgeApiToken) {
      return emptyStateMarkup("No edge link configured", "Enter the local edge API URL and bearer token for this pilot console.");
    }
    if (!edgeStatus) {
      return emptyStateMarkup("Not checked yet", "Use Check Edge or wait for the live poller.");
    }
    if (edgeStatus.error) {
      return emptyStateMarkup("Edge unreachable", edgeStatus.error);
    }
    return `
      <ul class="stack-list">
        <li><strong>Edge ID</strong><span>${escapeHtml(edgeStatus.edge_id || "Not assigned")}</span></li>
        <li><strong>Configured gates</strong><span>${Number(edgeStatus.configured_gates || 0)}</span></li>
        <li><strong>Cached active credentials</strong><span>${Number(edgeStatus.cached_active_credentials || 0)}</span></li>
        <li><strong>Unsynced events</strong><span>${Number(edgeStatus.unsynced_events || 0)}</span></li>
        <li><strong>Head hash</strong><span class="timestamp">${escapeHtml(edgeStatus.head_hash || "")}</span></li>
      </ul>
    `;
  }

  function edgeEventsMarkup() {
    if (!state.settings.edgeApiUrl || !state.settings.edgeApiToken) {
      return emptyStateMarkup("Live feed disconnected", "Configure the edge link before loading entry events.");
    }
    if (!edgeEvents.length) {
      return emptyStateMarkup("No edge events loaded", "The feed will populate from the edge event log.");
    }
    return edgeEvents
      .map((event) => `
        <article class="event-line ${event.decision === "allow" ? "allowed" : event.decision === "deny" ? "denied" : ""}">
          <div>
            <strong>${escapeHtml(event.credential_type || event.event_type || "event")} ${event.decision ? escapeHtml(event.decision).toUpperCase() : ""}</strong>
            <span>${escapeHtml(event.principal_label || event.reason || "No principal")}</span>
          </div>
          <div>
            <span>${escapeHtml(event.gate_id || "workspace")}</span>
            <small>${formatDate(event.occurred_at)} · #${Number(event.sequence || 0)}</small>
          </div>
        </article>
      `)
      .join("");
  }

  function addAudit(entry) {
    state.audits.unshift({
      id: createId("audit"),
      at: new Date().toISOString(),
      ...entry
    });
  }

  function controllersTable() {
    if (!state.gates.length) {
      return emptyStateMarkup("No controllers configured", "Add real field controller records before issuing access decisions.");
    }
    return `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Area</th>
              <th>Existing System</th>
              <th>Interface</th>
              <th>Hardware ID</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            ${state.gates.map((gate) => `
              <tr>
                <td><strong>${escapeHtml(gate.name)}</strong><br><span class="badge warn">${escapeHtml(gate.operatorClass)}</span></td>
                <td>${escapeHtml(gate.area)}</td>
                <td>${escapeHtml(gate.provider)}</td>
                <td>${escapeHtml(gate.triggerMode)}</td>
                <td><span class="timestamp">${escapeHtml(gate.hardwareId)}</span></td>
                <td>${formatDate(gate.createdAt)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function residentsTable() {
    if (!state.residents.length) {
      return emptyStateMarkup("No resident records", "Resident records are created only from submitted workspace data.");
    }
    return tableMarkup(
      ["Resident", "Unit", "Credential", "Controller", "Status", "Created"],
      state.residents.map((resident) => [
        `<strong>${escapeHtml(resident.name)}</strong>`,
        escapeHtml(resident.unit),
        `${escapeHtml(resident.credentialType)}<br><span class="timestamp">${escapeHtml(maskCredential(resident.credentialType, resident.credentialValue))}</span>`,
        escapeHtml(gateName(resident.gateId)),
        statusBadge(resident.status),
        formatDate(resident.createdAt)
      ])
    );
  }

  function passesTable() {
    if (!state.passes.length) {
      return emptyStateMarkup("No visitor passes", "Visitor passes are created from resident or manager requests.");
    }
    return tableMarkup(
      ["Visitor", "Sponsor", "Credential", "Controller", "Window", "Status"],
      state.passes.map((pass) => [
        `<strong>${escapeHtml(pass.visitorName)}</strong>`,
        escapeHtml(pass.sponsorName),
        `${escapeHtml(pass.credentialType)}<br><span class="timestamp">${escapeHtml(maskCredential(pass.credentialType, pass.credentialValue))}</span>`,
        escapeHtml(gateName(pass.gateId)),
        `${formatDate(pass.startsAt)}<br><span class="timestamp">Until ${formatDate(pass.expiresAt)}</span>`,
        statusBadge(passStatus(pass))
      ])
    );
  }

  function integrationsTable() {
    if (!state.integrations.length) {
      return emptyStateMarkup("No integrations configured", "Add real provider configuration when a site is ready for system connection.");
    }
    return tableMarkup(
      ["Provider", "Label", "Transport", "Endpoint", "Created"],
      state.integrations.map((integration) => [
        `<strong>${escapeHtml(integration.provider)}</strong>`,
        escapeHtml(integration.name),
        escapeHtml(integration.mode),
        integration.endpoint ? `<span class="timestamp">${escapeHtml(integration.endpoint)}</span>` : `<span class="badge warn">No URL stored</span>`,
        formatDate(integration.createdAt)
      ])
    );
  }

  function alertsTable() {
    if (!state.alerts.length) {
      return emptyStateMarkup("No maintenance alerts", "Create alerts for real controller issues, inspections, or service actions.");
    }
    return `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Alert</th>
              <th>Controller</th>
              <th>Severity</th>
              <th>Due</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.alerts.map((alert) => `
              <tr>
                <td><strong>${escapeHtml(alert.title)}</strong>${alert.notes ? `<br><span class="timestamp">${escapeHtml(alert.notes)}</span>` : ""}</td>
                <td>${escapeHtml(gateName(alert.gateId))}</td>
                <td>${severityBadge(alert.severity)}</td>
                <td>${escapeHtml(alert.dueAt)}</td>
                <td>${statusBadge(alert.status)}</td>
                <td>${alert.status === "Open" ? `<button class="text-button" type="button" data-resolve-alert="${alert.id}">Resolve</button>` : ""}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function auditTable() {
    if (!state.audits.length) {
      return emptyStateMarkup("No audit events", "Configuration changes and access decisions will appear here after real actions are taken.");
    }
    return tableMarkup(
      ["Time", "Type", "Event", "Controller", "Decision"],
      state.audits.map((audit) => [
        formatDate(audit.at),
        `<span class="timestamp">${escapeHtml(audit.type)}</span>`,
        `<strong>${escapeHtml(audit.title)}</strong><br><span class="timestamp">${escapeHtml(audit.detail || "")}</span>`,
        escapeHtml(audit.gateId ? gateName(audit.gateId) : "Workspace"),
        audit.decision ? decisionBadge(audit.decision) : ""
      ])
    );
  }

  function tableMarkup(headers, rows) {
    return `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>${headers.map((header) => `<th>${header}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function decisionMarkup() {
    if (!latestDecision) {
      return `
        <strong>No decision evaluated</strong>
        <span>Submit a credential request after controllers and credentials are configured.</span>
      `;
    }
    return `
      <strong>${latestDecision.decision === "authorized" ? "Authorized" : "Denied"}</strong>
      <span>${escapeHtml(latestDecision.reason)}</span>
    `;
  }

  function emptyStateMarkup(title, body) {
    return `
      <div class="empty-state">
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(body)}</span>
      </div>
    `;
  }

  function gateOptions(includeAll) {
    const allOption = includeAll ? `<option value="all">All configured controllers</option>` : "";
    if (!state.gates.length) {
      return `${allOption}<option value="" disabled selected>No configured controllers</option>`;
    }
    return `${allOption}${state.gates.map((gate) => `<option value="${gate.id}">${escapeHtml(gate.name)}</option>`).join("")}`;
  }

  function options(values, selectedValue) {
    return values
      .map((value) => `<option value="${escapeHtml(value)}" ${value === selectedValue ? "selected" : ""}>${escapeHtml(value)}</option>`)
      .join("");
  }

  function statusBadge(status) {
    const key = String(status).toLowerCase();
    const badgeClass = key === "active" || key === "open" ? "good" : key === "resolved" ? "" : "stop";
    return `<span class="badge ${badgeClass}">${escapeHtml(status)}</span>`;
  }

  function severityBadge(severity) {
    const badgeClass = severity === "Critical" ? "stop" : severity === "Attention" ? "warn" : "good";
    return `<span class="badge ${badgeClass}">${escapeHtml(severity)}</span>`;
  }

  function decisionBadge(decision) {
    return `<span class="badge ${decision === "authorized" ? "good" : "stop"}">${escapeHtml(decision)}</span>`;
  }

  function passStatus(pass) {
    if (pass.status !== "Active") return pass.status;
    const now = new Date();
    if (new Date(pass.startsAt) > now) return "Scheduled";
    if (new Date(pass.expiresAt) < now) return "Expired";
    return "Active";
  }

  function gateName(gateId) {
    if (gateId === "all") return "All configured controllers";
    const gate = state.gates.find((item) => item.id === gateId);
    return gate ? gate.name : "Unknown controller";
  }

  function activeCredentialCount() {
    const activeResidents = state.residents.filter((resident) => resident.status === "Active").length;
    const now = new Date();
    const activePasses = state.passes.filter((pass) => {
      return pass.status === "Active" && new Date(pass.startsAt) <= now && new Date(pass.expiresAt) >= now;
    }).length;
    return activeResidents + activePasses;
  }

  function openAlertCount() {
    return state.alerts.filter((alert) => alert.status === "Open").length;
  }

  function exportWorkspace() {
    state.settings.lastExportAt = new Date().toISOString();
    localStorage.setItem(STORE_KEY, JSON.stringify(state));
    downloadJson("angel-gates-workspace.json", state);
    render();
  }

  function importWorkspace(event) {
    const file = event.currentTarget.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const imported = JSON.parse(reader.result);
        const empty = defaultState();
        state = {
          ...empty,
          ...imported,
          settings: {
            ...empty.settings,
            ...(imported.settings || {}),
            lastImportAt: new Date().toISOString()
          },
          gates: Array.isArray(imported.gates) ? imported.gates : [],
          residents: Array.isArray(imported.residents) ? imported.residents : [],
          passes: Array.isArray(imported.passes) ? imported.passes : [],
          integrations: Array.isArray(imported.integrations) ? imported.integrations : [],
          alerts: Array.isArray(imported.alerts) ? imported.alerts : [],
          audits: Array.isArray(imported.audits) ? imported.audits : []
        };
        addAudit({
          type: "sync",
          title: "Workspace imported",
          detail: file.name
        });
        saveState();
      } catch (error) {
        window.alert("The selected file is not valid workspace JSON.");
      }
    };
    reader.readAsText(file);
  }

  function clearWorkspace() {
    const confirmed = window.confirm("Clear every local Angel Gates record stored in this browser?");
    if (!confirmed) return;
    state = defaultState();
    latestDecision = null;
    localStorage.setItem(STORE_KEY, JSON.stringify(state));
    render();
  }

  function downloadJson(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function createId(prefix) {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return `${prefix}_${window.crypto.randomUUID()}`;
    }
    return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  }

  function normalizeCredential(type, value) {
    const trimmed = String(value || "").trim();
    if (type === "License plate") {
      return trimmed.toUpperCase().replace(/\s+/g, "");
    }
    if (type === "PIN") {
      return trimmed.replace(/\s+/g, "");
    }
    return trimmed;
  }

  function maskCredential(type, value) {
    const raw = String(value || "");
    if (type === "PIN") {
      return raw.length ? "*".repeat(Math.min(raw.length, 8)) : "";
    }
    if (raw.length <= 4) return raw;
    return `${raw.slice(0, 2)}...${raw.slice(-2)}`;
  }

  function formatDate(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    }).format(date);
  }

  function toDatetimeLocal(date) {
    const offset = date.getTimezoneOffset() * 60000;
    return new Date(date.getTime() - offset).toISOString().slice(0, 16);
  }

  function plural(count) {
    return count === 1 ? "" : "s";
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();
