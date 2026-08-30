/**
 * ULPF Operations Dashboard — Client Application
 * Vanilla JS, Zero External Libraries, Virtualized Table
 * Independent Color Themes (Light / Dark) & View Modes (Default / Professional)
 * Resizable Columns, Custom Width Presets, Side-by-Side Traceability Inspector
 */

(function () {
  "use strict";

  const DEFAULT_WIDTHS = {
    standard: { ts: 210, vendor: 175, category: 145, action: 115, sev: 95, flow: 260, parser: 140, id: 110, details: 100 },
    compact: { ts: 170, vendor: 140, category: 120, action: 95, sev: 80, flow: 200, parser: 120, id: 95, details: 85 },
    comfortable: { ts: 250, vendor: 240, category: 180, action: 140, sev: 110, flow: 340, parser: 170, id: 130, details: 120 },
  };

  let savedWidths = null;
  try {
    savedWidths = JSON.parse(localStorage.getItem("ulpf_col_widths"));
  } catch (e) {}

  // Application State
  const state = {
    colorTheme: localStorage.getItem("ulpf_color_theme") || "light",
    viewMode: localStorage.getItem("ulpf_view_mode") || "default",
    densityPreset: localStorage.getItem("ulpf_density") || "standard",
    colWidths: Object.assign({}, DEFAULT_WIDTHS.standard, savedWidths || {}),
    activeTab: "events",
    events: [],
    totalEvents: 0,
    currentPage: 1,
    pageSize: 50,
    totalPages: 1,
    selectedEventId: null,
    selectedRowIndex: -1,
    sortColumn: "ingest_timestamp",
    sortOrder: "desc",
    filters: {
      search: "",
      vendor: "",
      category: "",
      action: "",
      outcome: "",
      severityMin: null,
      severityMax: null,
      timeRange: "",
      parserName: "",
    },
    stats: {},
    parsers: [],
    deadLetters: [],
    deadLetterTotal: 0,
    sseConnected: false,
  };

  // DOM Elements cache
  const el = {
    // Mode & Theme Controls
    viewDefaultBtn: document.getElementById("viewDefaultBtn"),
    viewProBtn: document.getElementById("viewProBtn"),
    colorThemeBtn: document.getElementById("colorThemeBtn"),
    colorThemeText: document.getElementById("colorThemeText"),
    themeIconSun: document.getElementById("themeIconSun"),
    themeIconMoon: document.getElementById("themeIconMoon"),

    // Pro View Elements
    proTabsBar: document.getElementById("proTabsBar"),
    proFiltersPanel: document.getElementById("proFiltersPanel"),
    metricsGrid: document.getElementById("metricsGrid"),

    // Search & Inputs
    searchInput: document.getElementById("searchInput"),
    vendorFilter: document.getElementById("vendorFilter"),
    categoryFilter: document.getElementById("categoryFilter"),
    actionFilter: document.getElementById("actionFilter"),
    outcomeFilter: document.getElementById("outcomeFilter"),
    timeFilter: document.getElementById("timeFilter"),
    parserFilter: document.getElementById("parserFilter"),
    quickChips: document.getElementById("quickChips"),

    // Virtual Table
    tableContainer: document.getElementById("eventsPanel"),
    tableHeaderRow: document.getElementById("tableHeaderRow"),
    virtualViewport: document.getElementById("virtualViewport"),
    virtualSpacer: document.getElementById("virtualSpacer"),
    virtualContent: document.getElementById("virtualContent"),

    // Pagination & Status
    pageInfo: document.getElementById("pageInfo"),
    prevPageBtn: document.getElementById("prevPageBtn"),
    nextPageBtn: document.getElementById("nextPageBtn"),

    // Panels
    eventsPanel: document.getElementById("eventsPanel"),
    deadLetterPanel: document.getElementById("deadLetterPanel"),
    parsersPanel: document.getElementById("parsersPanel"),
    liveHostPanel: document.getElementById("liveHostPanel"),
    filterSection: document.querySelector(".filter-section"),

    // Modals
    inspectorModal: document.getElementById("inspectorModal"),
    closeInspectorBtn: document.getElementById("closeInspectorBtn"),
    shortcutsModal: document.getElementById("shortcutsModal"),
    closeShortcutsBtn: document.getElementById("closeShortcutsBtn"),
    shortcutsHelpBtn: document.getElementById("shortcutsHelpBtn"),

    // Inspector Details
    inspectEventId: document.getElementById("inspectEventId"),
    inspectParser: document.getElementById("inspectParser"),
    inspectRawFormat: document.getElementById("inspectRawFormat"),
    inspectRawHash: document.getElementById("inspectRawHash"),
    inspectRawPayload: document.getElementById("inspectRawPayload"),
    inspectUesJson: document.getElementById("inspectUesJson"),
    copyRawBtn: document.getElementById("copyRawBtn"),
    copyJsonBtn: document.getElementById("copyJsonBtn"),
    exportCsvBtn: document.getElementById("exportCsvBtn"),
    exportJsonBtn: document.getElementById("exportJsonBtn"),
  };

  // --------------------------------------------------------------------------
  // Color Theme Management (Light vs Dark)
  // --------------------------------------------------------------------------
  function setColorTheme(theme) {
    state.colorTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("ulpf_color_theme", theme);

    const isDark = theme === "dark";
    if (el.colorThemeText) el.colorThemeText.textContent = isDark ? "Light" : "Dark";
    if (el.themeIconSun) el.themeIconSun.style.display = isDark ? "inline-block" : "none";
    if (el.themeIconMoon) el.themeIconMoon.style.display = isDark ? "none" : "inline-block";
  }

  function toggleColorTheme() {
    setColorTheme(state.colorTheme === "dark" ? "light" : "dark");
  }

  // --------------------------------------------------------------------------
  // View Mode Management (Default vs Professional)
  // --------------------------------------------------------------------------
  function setViewMode(mode) {
    state.viewMode = mode;
    document.documentElement.setAttribute("data-view", mode);
    localStorage.setItem("ulpf_view_mode", mode);

    const isPro = mode === "professional";
    if (el.viewDefaultBtn) el.viewDefaultBtn.classList.toggle("active", !isPro);
    if (el.viewProBtn) el.viewProBtn.classList.toggle("active", isPro);

    if (el.proTabsBar) el.proTabsBar.style.display = "flex";
    if (el.proFiltersPanel) el.proFiltersPanel.style.display = isPro ? "grid" : "none";

    renderTableHeader();
    if (virtualScroller) {
      virtualScroller.updateRowHeight();
      virtualScroller.render();
    }
  }

  function toggleViewMode() {
    setViewMode(state.viewMode === "professional" ? "default" : "professional");
  }

  function applyColumnWidths() {
    const w = state.colWidths;
    const isPro = state.viewMode === "professional";
    const c = el.tableContainer || document.getElementById("eventsPanel");
    if (!c) return;

    c.style.setProperty("--col-ts", `${w.ts}px`);
    c.style.setProperty("--col-vendor", `${w.vendor}px`);
    c.style.setProperty("--col-category", `${w.category}px`);
    c.style.setProperty("--col-action", `${w.action}px`);
    c.style.setProperty("--col-sev", `${w.sev}px`);
    c.style.setProperty("--col-flow", `${w.flow}px`);
    c.style.setProperty("--col-parser", `${w.parser}px`);
    c.style.setProperty("--col-id", `${w.id}px`);
    c.style.setProperty("--col-details", `${w.details}px`);

    let totalWidth = 0;
    if (isPro) {
      totalWidth = w.ts + w.vendor + w.category + w.action + w.sev + w.flow + w.parser + w.id + 40;
    } else {
      totalWidth = w.ts + w.vendor + w.action + w.sev + w.flow + w.details + 40;
    }
    c.style.setProperty("--table-min-width", `${totalWidth}px`);
  }

  // --------------------------------------------------------------------------
  // Virtual Table Scroller
  // --------------------------------------------------------------------------
  class VirtualScroller {
    constructor(viewport, spacer, content) {
      this.viewport = viewport;
      this.spacer = spacer;
      this.content = content;
      this.rowHeight = state.viewMode === "professional" ? 38 : 46;
      this.buffer = 8;
      this.ticking = false;

      this.viewport.addEventListener("scroll", () => {
        if (!this.ticking) {
          window.requestAnimationFrame(() => {
            this.render();
            this.ticking = false;
          });
          this.ticking = true;
        }
      });

      // Auto-recompute on size or visibility transitions
      if (typeof ResizeObserver !== "undefined" && this.viewport) {
        this.resizeObserver = new ResizeObserver(() => {
          if (this.viewport.clientHeight > 0) {
            this.render();
          }
        });
        this.resizeObserver.observe(this.viewport);
      }
    }

    updateRowHeight() {
      this.rowHeight = state.viewMode === "professional" ? 38 : 46;
    }

    scrollToTop() {
      if (this.viewport) {
        this.viewport.scrollTop = 0;
      }
    }

    render() {
      const totalRows = state.events.length;
      const totalHeight = Math.max(0, totalRows * this.rowHeight);
      this.spacer.style.height = `${totalHeight}px`;

      if (totalRows === 0) {
        this.content.style.transform = "none";
        this.content.innerHTML = `
          <div style="padding: 60px 20px; text-align: center; color: var(--text-muted);">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin: 0 auto 12px auto; opacity: 0.45; display: block;">
              <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <div style="font-weight: 600; font-size: 1rem; color: var(--text-primary); margin-bottom: 4px;">No matching normalized events</div>
            <p style="font-size: 0.85rem;">Try adjusting your search terms or clearing the filter chips.</p>
          </div>
        `;
        return;
      }

      let scrollTop = this.viewport.scrollTop || 0;
      const viewportHeight = this.viewport.clientHeight || 500;

      // Clamping guard against out-of-bounds scroll offset (e.g. after filter change or pagination)
      const maxScroll = Math.max(0, totalHeight - viewportHeight);
      if (scrollTop > maxScroll && maxScroll >= 0) {
        scrollTop = maxScroll;
        this.viewport.scrollTop = scrollTop;
      }

      const startIndex = Math.max(0, Math.min(totalRows - 1, Math.floor(scrollTop / this.rowHeight) - this.buffer));
      const endIndex = Math.min(totalRows - 1, Math.ceil((scrollTop + viewportHeight) / this.rowHeight) + this.buffer);

      const offsetY = startIndex * this.rowHeight;
      this.content.style.transform = `translateY(${offsetY}px)`;

      let html = "";
      for (let i = startIndex; i <= endIndex; i++) {
        const item = state.events[i];
        if (item) {
          html += renderEventRow(item, i);
        }
      }
      this.content.innerHTML = html;

      // Attach row click handlers
      const rows = this.content.querySelectorAll(".event-row");
      rows.forEach((row) => {
        row.addEventListener("click", () => {
          const idx = parseInt(row.getAttribute("data-index"), 10);
          selectRow(idx);
          openEventInspector(state.events[idx].event_id);
        });
      });
    }
  }

  let virtualScroller;

  // --------------------------------------------------------------------------
  // Table Header & Resizable Columns
  // --------------------------------------------------------------------------
  function renderTableHeader() {
    const isPro = state.viewMode === "professional";

    if (!isPro) {
      // Default view simplified columns
      el.tableHeaderRow.innerHTML = `
        <div class="table-header-col col-ts" data-sort="ingest_timestamp">
          <span class="col-header-label">Time ${getSortIndicator("ingest_timestamp")}</span>
          <div class="col-resizer" data-col="ts"></div>
        </div>
        <div class="table-header-col col-vendor" data-sort="vendor">
          <span class="col-header-label">Source / Vendor ${getSortIndicator("vendor")}</span>
          <div class="col-resizer" data-col="vendor"></div>
        </div>
        <div class="table-header-col col-action" data-sort="action">
          <span class="col-header-label">Action ${getSortIndicator("action")}</span>
          <div class="col-resizer" data-col="action"></div>
        </div>
        <div class="table-header-col col-sev" data-sort="severity">
          <span class="col-header-label">Severity ${getSortIndicator("severity")}</span>
          <div class="col-resizer" data-col="sev"></div>
        </div>
        <div class="table-header-col col-flow">
          <span class="col-header-label">Connection Path</span>
          <div class="col-resizer" data-col="flow"></div>
        </div>
        <div class="table-header-col col-details" style="justify-content: flex-end;">
          <span class="col-header-label">Details</span>
        </div>
      `;
    } else {
      // Professional view full columns
      el.tableHeaderRow.innerHTML = `
        <div class="table-header-col col-ts" data-sort="ingest_timestamp">
          <span class="col-header-label">TIMESTAMP (UTC) ${getSortIndicator("ingest_timestamp")}</span>
          <div class="col-resizer" data-col="ts"></div>
        </div>
        <div class="table-header-col col-vendor" data-sort="vendor">
          <span class="col-header-label">VENDOR / PROD ${getSortIndicator("vendor")}</span>
          <div class="col-resizer" data-col="vendor"></div>
        </div>
        <div class="table-header-col col-category" data-sort="category">
          <span class="col-header-label">CATEGORY ${getSortIndicator("category")}</span>
          <div class="col-resizer" data-col="category"></div>
        </div>
        <div class="table-header-col col-action" data-sort="action">
          <span class="col-header-label">ACTION / OUT ${getSortIndicator("action")}</span>
          <div class="col-resizer" data-col="action"></div>
        </div>
        <div class="table-header-col col-sev" data-sort="severity">
          <span class="col-header-label">SEV ${getSortIndicator("severity")}</span>
          <div class="col-resizer" data-col="sev"></div>
        </div>
        <div class="table-header-col col-flow" data-sort="src_ip">
          <span class="col-header-label">SRC → DST [PROTO]</span>
          <div class="col-resizer" data-col="flow"></div>
        </div>
        <div class="table-header-col col-parser" data-sort="parser_name">
          <span class="col-header-label">PARSER ${getSortIndicator("parser_name")}</span>
          <div class="col-resizer" data-col="parser"></div>
        </div>
        <div class="table-header-col col-id">
          <span class="col-header-label">EVENT ID</span>
          <div class="col-resizer" data-col="id"></div>
        </div>
      `;
    }

    attachSortListeners();
    attachResizerListeners();
    applyColumnWidths();
  }

  function attachSortListeners() {
    el.tableHeaderRow.querySelectorAll("[data-sort]").forEach((col) => {
      col.addEventListener("click", (e) => {
        if (e.target.classList.contains("col-resizer")) return;
        const field = col.getAttribute("data-sort");
        if (state.sortColumn === field) {
          state.sortOrder = state.sortOrder === "desc" ? "asc" : "desc";
        } else {
          state.sortColumn = field;
          state.sortOrder = "desc";
        }
        renderTableHeader();
        fetchEvents(1);
      });
    });
  }

  let activeResizer = null;
  let startX = 0;
  let startWidth = 0;
  let activeColKey = "";

  function attachResizerListeners() {
    el.tableHeaderRow.querySelectorAll(".col-resizer").forEach((resizer) => {
      resizer.addEventListener("mousedown", (e) => {
        e.stopPropagation();
        e.preventDefault();

        activeResizer = resizer;
        activeColKey = resizer.getAttribute("data-col");
        startX = e.clientX;
        startWidth = state.colWidths[activeColKey] || 150;

        resizer.classList.add("resizing");
        document.body.classList.add("resizing");

        const onMouseMove = (moveEvent) => {
          if (!activeResizer) return;
          const diff = moveEvent.clientX - startX;
          const newWidth = Math.max(50, startWidth + diff);
          state.colWidths[activeColKey] = newWidth;
          applyColumnWidths();
        };

        const onMouseUp = () => {
          if (activeResizer) {
            activeResizer.classList.remove("resizing");
            activeResizer = null;
          }
          document.body.classList.remove("resizing");
          localStorage.setItem("ulpf_col_widths", JSON.stringify(state.colWidths));
          window.removeEventListener("mousemove", onMouseMove);
          window.removeEventListener("mouseup", onMouseUp);
        };

        window.addEventListener("mousemove", onMouseMove);
        window.addEventListener("mouseup", onMouseUp);
      });
    });
  }

  function setupDensityToolbar() {
    const compactBtn = document.getElementById("densityCompactBtn");
    const standardBtn = document.getElementById("densityStandardBtn");
    const comfortableBtn = document.getElementById("densityComfortableBtn");
    const resetBtn = document.getElementById("resetWidthsBtn");

    function setPreset(name) {
      state.densityPreset = name;
      state.colWidths = Object.assign({}, DEFAULT_WIDTHS[name]);
      localStorage.setItem("ulpf_density", name);
      localStorage.setItem("ulpf_col_widths", JSON.stringify(state.colWidths));

      [compactBtn, standardBtn, comfortableBtn].forEach((b) => b && b.classList.remove("active"));
      if (name === "compact" && compactBtn) compactBtn.classList.add("active");
      if (name === "standard" && standardBtn) standardBtn.classList.add("active");
      if (name === "comfortable" && comfortableBtn) comfortableBtn.classList.add("active");

      applyColumnWidths();
      virtualScroller.render();
    }

    if (compactBtn) compactBtn.addEventListener("click", () => setPreset("compact"));
    if (standardBtn) standardBtn.addEventListener("click", () => setPreset("standard"));
    if (comfortableBtn) comfortableBtn.addEventListener("click", () => setPreset("comfortable"));
    if (resetBtn) resetBtn.addEventListener("click", () => setPreset("standard"));

    if (state.densityPreset === "compact" && compactBtn) {
      [compactBtn, standardBtn, comfortableBtn].forEach((b) => b && b.classList.remove("active"));
      compactBtn.classList.add("active");
    } else if (state.densityPreset === "comfortable" && comfortableBtn) {
      [compactBtn, standardBtn, comfortableBtn].forEach((b) => b && b.classList.remove("active"));
      comfortableBtn.classList.add("active");
    }
  }

  function getSortIndicator(field) {
    if (state.sortColumn !== field) return "";
    return state.sortOrder === "desc" ? "▼" : "▲";
  }

  // --------------------------------------------------------------------------
  // SVG Icon Templates (100% Offline / Zero CDN)
  // --------------------------------------------------------------------------
  const ICONS = {
    allow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>',
    deny: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>',
    unknownAction: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle></svg>',
    auth: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
    network: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>',
    vpn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>',
    system: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>',
    threat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
    policy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
    server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4 10z"></path></svg>',
    code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>'
  };

  function getCategoryBadgeHtml(catRaw, eventType) {
    const cat = (catRaw || "").toLowerCase();
    const evt = (eventType || "").toLowerCase();

    let icon = ICONS.network;
    let badgeClass = "badge-cat-network";
    let label = cat || "network";

    if (cat.includes("auth") || evt.includes("login") || evt.includes("sshd") || evt.includes("user")) {
      icon = ICONS.auth;
      badgeClass = "badge-cat-authentication";
      label = "AUTHENTICATION";
    } else if (cat.includes("vpn") || evt.includes("vpn")) {
      icon = ICONS.vpn;
      badgeClass = "badge-cat-vpn";
      label = "VPN";
    } else if (cat.includes("system") || evt.includes("sys") || evt.includes("id47")) {
      icon = ICONS.system;
      badgeClass = "badge-cat-system";
      label = evt.includes("id47") ? "SYSTEM (ID47)" : "SYSTEM";
    } else if (cat.includes("threat") || cat.includes("attack") || cat.includes("alert")) {
      icon = ICONS.threat;
      badgeClass = "badge-cat-threat";
      label = "THREAT";
    } else if (cat.includes("policy") || evt.includes("rule")) {
      icon = ICONS.policy;
      badgeClass = "badge-cat-policy";
      label = "POLICY";
    } else {
      label = label.toUpperCase();
    }

    return `<span class="badge ${badgeClass}"><span class="badge-icon">${icon}</span>${escapeHtml(label)}</span>`;
  }

  function getActionBadgeHtml(actionStr, isPro) {
    const act = (actionStr || "unknown").toLowerCase();
    let badgeClass = "badge-unknown";
    let icon = ICONS.unknownAction;
    let display = isPro ? act.toUpperCase() : "Unknown";

    if (["allow", "permit", "success", "accepted", "traffic"].some((k) => act.includes(k))) {
      badgeClass = "badge-allow";
      icon = ICONS.allow;
      display = isPro ? act.toUpperCase() : "Allowed";
    } else if (["deny", "drop", "block", "failure", "alert", "error", "critical"].some((k) => act.includes(k))) {
      badgeClass = "badge-deny";
      icon = ICONS.deny;
      display = isPro ? act.toUpperCase() : "Blocked";
    }

    return `<span class="badge ${badgeClass}"><span class="badge-icon">${icon}</span>${escapeHtml(display)}</span>`;
  }

  function getVendorIconHtml(vendor, format) {
    const v = (vendor || "").toLowerCase();
    const f = (format || "").toLowerCase();
    if (v.includes("cisco") || v.includes("palo")) return ICONS.shield;
    if (v.includes("squid") || f.includes("rfc3164")) return ICONS.globe;
    if (f.includes("json")) return ICONS.code;
    return ICONS.server;
  }

  function renderEventRow(item, index) {
    const isPro = state.viewMode === "professional";
    const isSelected = index === state.selectedRowIndex;
    const selectedClass = isSelected ? " selected" : "";

    const ts = formatTimestamp(item.ingest_timestamp);
    const source = item.source || {};
    const ev = item.event || {};
    const net = item.network || {};
    const lineage = item.lineage || {};

    const rawVendor = source.vendor
      ? (source.product ? `${source.vendor} (${source.product})` : source.vendor)
      : (source.device_hostname || source.log_format || "Unknown");
    const vendorStr = escapeHtml(rawVendor);
    const vendorIcon = getVendorIconHtml(rawVendor, source.log_format || "");

    const rawAction = ev.action || ev.outcome || ev.event_type_vendor_specific || "unknown";
    const actionBadge = getActionBadgeHtml(String(rawAction), isPro);
    const categoryBadge = getCategoryBadgeHtml(ev.category, ev.event_type_vendor_specific);
    const sevNum = parseFloat(ev.severity_numeric !== undefined ? ev.severity_numeric : 5.0);

    let sevBadge = `<span class="severity-pill sev-low"><span class="sev-dot"></span>Low</span>`;
    if (sevNum >= 7.0) {
      sevBadge = `<span class="severity-pill sev-high"><span class="sev-dot"></span>High (${sevNum})</span>`;
    } else if (sevNum >= 4.0) {
      sevBadge = `<span class="severity-pill sev-med"><span class="sev-dot"></span>Med (${sevNum})</span>`;
    }

    const srcStr = net.src_ip ? `${net.src_ip}${net.src_port ? ":" + net.src_port : ""}` : "-";
    const dstStr = net.dst_ip ? `${net.dst_ip}${net.dst_port ? ":" + net.dst_port : ""}` : "-";
    const protoStr = net.protocol ? ` [${net.protocol.toUpperCase()}]` : "";
    const netFlow = `${srcStr} → ${dstStr}${protoStr}`;

    if (!isPro) {
      return `
        <div class="event-row${selectedClass}" data-index="${index}">
          <div class="event-col col-ts">${ts}</div>
          <div class="event-col col-vendor" style="font-weight: 600;" title="${vendorStr}">
            <span class="vendor-cell"><span class="vendor-icon">${vendorIcon}</span>${vendorStr}</span>
          </div>
          <div class="event-col col-action">${actionBadge}</div>
          <div class="event-col col-sev">${sevBadge}</div>
          <div class="event-col col-flow mono-text" title="${netFlow}">${netFlow}</div>
          <div class="event-col col-details" style="text-align: right;">
            <button class="btn-theme-mode" style="padding: 2px 8px; font-size: 0.75rem;">Inspect</button>
          </div>
        </div>
      `;
    } else {
      const eventIdShort = (item.event_id || "").substring(0, 8) + "...";
      return `
        <div class="event-row${selectedClass}" data-index="${index}">
          <div class="event-col col-ts mono-text" title="${item.ingest_timestamp}">${ts}</div>
          <div class="event-col col-vendor" style="font-weight: 600;" title="${vendorStr}">
            <span class="vendor-cell"><span class="vendor-icon">${vendorIcon}</span>${vendorStr}</span>
          </div>
          <div class="event-col col-category" title="${escapeHtml(ev.category || "unknown")}">${categoryBadge}</div>
          <div class="event-col col-action" title="${rawAction}">${actionBadge}</div>
          <div class="event-col col-sev">${sevBadge}</div>
          <div class="event-col col-flow mono-text" title="${netFlow}">${netFlow}</div>
          <div class="event-col col-parser" title="${escapeHtml(lineage.parser_name || "-")}"><span class="badge badge-subtle">${escapeHtml(lineage.parser_name || "-")}</span></div>
          <div class="event-col col-id mono-text" style="color: var(--text-muted);" title="${item.event_id || ""}">${eventIdShort}</div>
        </div>
      `;
    }
  }

  function selectRow(index) {
    state.selectedRowIndex = index;
    if (index >= 0 && index < state.events.length) {
      state.selectedEventId = state.events[index].event_id;
    }
    virtualScroller.render();
  }

  // --------------------------------------------------------------------------
  // Data Fetching & REST API Calls
  // --------------------------------------------------------------------------
  async function fetchStats() {
    try {
      const res = await fetch("/api/stats");
      if (!res.ok) return;
      const data = await res.json();
      state.stats = data;
      renderStats();
    } catch (err) {
      console.warn("Failed to fetch stats:", err);
    }
  }

  function renderStats() {
    const s = state.stats;
    const totalEl = document.getElementById("statTotalEvents");
    const issuesEl = document.getElementById("statIssuesCount");
    const topVendorsEl = document.getElementById("statTopVendors");
    const velocityEl = document.getElementById("statVelocity");

    if (totalEl) totalEl.textContent = (s.total_events || 0).toLocaleString();
    if (issuesEl) {
      issuesEl.textContent = (s.dead_letter_count || 0).toLocaleString();
      issuesEl.style.color = s.dead_letter_count > 0 ? "var(--color-danger)" : "var(--color-success)";
    }
    if (topVendorsEl) {
      const vendors = s.top_vendors || [];
      if (vendors.length === 0) {
        topVendorsEl.innerHTML = '<span class="vendor-pill">None</span>';
      } else {
        topVendorsEl.innerHTML = vendors
          .map((v) => `<span class="vendor-pill">${escapeHtml(v.vendor)} (${v.count})</span>`)
          .join("");
      }
    }
    if (velocityEl) velocityEl.textContent = `${s.events_last_1h || 0} / hr`;

    // Update tab badges in Pro mode
    const deadBadge = document.getElementById("tabDeadLetterBadge");
    if (deadBadge) deadBadge.textContent = s.dead_letter_count || 0;
  }

  async function fetchEvents(page = 1, resetScroll = true) {
    state.currentPage = page;
    if (resetScroll && virtualScroller) {
      virtualScroller.scrollToTop();
    }
    const params = new URLSearchParams({
      page: state.currentPage,
      page_size: state.pageSize,
      sort_by: state.sortColumn,
      sort_order: state.sortOrder,
    });

    if (state.filters.search) params.append("search", state.filters.search);
    if (state.filters.vendor) params.append("vendor", state.filters.vendor);
    if (state.filters.category) params.append("category", state.filters.category);
    if (state.filters.action) params.append("action", state.filters.action);
    if (state.filters.outcome) params.append("outcome", state.filters.outcome);
    if (state.filters.severityMin !== null) params.append("severity_min", state.filters.severityMin);
    if (state.filters.severityMax !== null) params.append("severity_max", state.filters.severityMax);
    if (state.filters.parserName) params.append("parser_name", state.filters.parserName);

    try {
      const res = await fetch(`/api/events?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to fetch events");
      const data = await res.json();

      state.events = data.events || [];
      state.totalEvents = data.total || 0;
      state.totalPages = data.total_pages || 1;
      state.selectedRowIndex = -1;

      renderPagination();
      virtualScroller.render();
    } catch (err) {
      console.error("Error loading events:", err);
    }
  }

  function renderPagination() {
    if (el.pageInfo) {
      const start = (state.currentPage - 1) * state.pageSize + (state.totalEvents > 0 ? 1 : 0);
      const end = Math.min(state.currentPage * state.pageSize, state.totalEvents);
      el.pageInfo.textContent = `Showing ${start}-${end} of ${state.totalEvents} events (Page ${state.currentPage} of ${state.totalPages})`;
    }
    if (el.prevPageBtn) el.prevPageBtn.disabled = state.currentPage <= 1;
    if (el.nextPageBtn) el.nextPageBtn.disabled = state.currentPage >= state.totalPages;
  }

  async function fetchParsersHealth() {
    try {
      const res = await fetch("/api/parsers");
      if (!res.ok) return;
      const data = await res.json();
      state.parsers = data.parsers || [];
      renderParsersHealth();
    } catch (err) {
      console.error("Failed to load parsers:", err);
    }
  }

  function renderParsersHealth() {
    const grid = document.getElementById("parsersGrid");
    if (!grid) return;

    if (state.parsers.length === 0) {
      grid.innerHTML = '<p style="color: var(--text-muted);">No parsers registered.</p>';
      return;
    }

    grid.innerHTML = state.parsers
      .map(
        (p) => `
        <div class="parser-health-card">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="font-size: 1rem;">${escapeHtml(p.name)}</strong>
            <span class="badge ${p.event_count > 0 ? "badge-allow" : "badge-unknown"}">${p.status}</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">
            <div>Version: <span class="mono-text">${escapeHtml(p.version)}</span></div>
            <div>Format: <span class="mono-text">${escapeHtml(p.log_format)}</span></div>
          </div>
          <div style="margin-top: var(--space-2); display: flex; justify-content: space-between; align-items: flex-end;">
            <span style="font-size: 0.75rem; color: var(--text-muted);">Processed Events</span>
            <strong style="font-size: 1.2rem; color: var(--accent);">${(p.event_count || 0).toLocaleString()}</strong>
          </div>
        </div>
      `
      )
      .join("");
  }

  async function fetchDeadLetterRecords(page = 1) {
    try {
      const res = await fetch(`/api/dead-letter?page=${page}&page_size=20`);
      if (!res.ok) return;
      const data = await res.json();
      state.deadLetters = data.records || [];
      state.deadLetterTotal = data.total || 0;
      renderDeadLetterRecords();
    } catch (err) {
      console.error("Failed to load dead letter records:", err);
    }
  }

  function renderDeadLetterRecords() {
    const container = document.getElementById("deadLetterList");
    if (!container) return;

    if (state.deadLetters.length === 0) {
      container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted); background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-md);">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--color-success)" stroke-width="1.5" style="margin-bottom: 8px;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
          </svg>
          <p style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">Zero Quarantine Events</p>
          <p style="font-size: 0.85rem;">All incoming raw perimeter logs successfully passed UES schema validation.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = state.deadLetters
      .map(
        (dl) => `
        <div class="dead-letter-card">
          <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-2);">
            <strong>Validation Failure on Event: <span class="mono-text">${escapeHtml(dl.event_id)}</span></strong>
            <span style="font-size: 0.8rem; color: var(--text-muted);">${formatTimestamp(dl.timestamp)}</span>
          </div>
          <div style="margin-bottom: var(--space-2);">
            <div style="font-size: 0.75rem; font-weight: 600; color: var(--color-danger); text-transform: uppercase;">Validation Errors:</div>
            <ul style="margin-left: 20px; font-size: 0.82rem; color: var(--text-primary);">
              ${(dl.errors || []).map((e) => `<li>${escapeHtml(e)}</li>`).join("")}
            </ul>
          </div>
          <div>
            <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Original Raw Payload:</div>
            <pre class="code-viewer" style="max-height: 90px; margin-top: 4px;">${escapeHtml(dl.raw_payload)}</pre>
          </div>
        </div>
      `
      )
      .join("");
  }

  // --------------------------------------------------------------------------
  // --------------------------------------------------------------------------
  // Event Inspection, Traceability & Crosswalk Split Modal
  // --------------------------------------------------------------------------
  let currentInspectedEvent = null;

  async function openEventInspector(eventId) {
    try {
      const res = await fetch(`/api/events/${eventId}`);
      if (!res.ok) throw new Error("Event not found");
      const data = await res.json();
      currentInspectedEvent = data;

      el.inspectEventId.textContent = data.event_id;
      el.inspectParser.textContent = data.parser_name;
      el.inspectRawFormat.textContent = data.raw_format;
      el.inspectRawHash.textContent = data.raw_hash;

      el.inspectRawPayload.textContent = data.raw_payload;
      el.inspectUesJson.textContent = JSON.stringify(data.normalized, null, 2);

      // Reset tabs styling
      const tabUes = document.getElementById("inspectTabUesBtn");
      const tabOcsf = document.getElementById("inspectTabOcsfBtn");
      const tabEcs = document.getElementById("inspectTabEcsBtn");
      if (tabUes) { tabUes.style.background = "var(--accent)"; tabUes.style.color = "white"; }
      if (tabOcsf) { tabOcsf.style.background = ""; tabOcsf.style.color = ""; }
      if (tabEcs) { tabEcs.style.background = ""; tabEcs.style.color = ""; }

      el.inspectorModal.classList.add("open");
    } catch (err) {
      alert("Failed to load event details: " + err.message);
    }
  }

  function setupCrosswalkTabs() {
    const tabUes = document.getElementById("inspectTabUesBtn");
    const tabOcsf = document.getElementById("inspectTabOcsfBtn");
    const tabEcs = document.getElementById("inspectTabEcsBtn");

    if (tabUes) {
      tabUes.addEventListener("click", () => {
        if (!currentInspectedEvent) return;
        tabUes.style.background = "var(--accent)"; tabUes.style.color = "white";
        if (tabOcsf) { tabOcsf.style.background = ""; tabOcsf.style.color = ""; }
        if (tabEcs) { tabEcs.style.background = ""; tabEcs.style.color = ""; }
        el.inspectUesJson.textContent = JSON.stringify(currentInspectedEvent.normalized, null, 2);
      });
    }

    if (tabOcsf) {
      tabOcsf.addEventListener("click", async () => {
        if (!currentInspectedEvent) return;
        tabOcsf.style.background = "var(--accent)"; tabOcsf.style.color = "white";
        if (tabUes) { tabUes.style.background = ""; tabUes.style.color = ""; }
        if (tabEcs) { tabEcs.style.background = ""; tabEcs.style.color = ""; }
        try {
          const res = await fetch(`/api/events/${currentInspectedEvent.event_id}/crosswalk?format=ocsf`);
          const d = await res.json();
          el.inspectUesJson.textContent = JSON.stringify(d.ocsf, null, 2);
        } catch (e) {
          el.inspectUesJson.textContent = "Error fetching OCSF format: " + e.message;
        }
      });
    }

    if (tabEcs) {
      tabEcs.addEventListener("click", async () => {
        if (!currentInspectedEvent) return;
        tabEcs.style.background = "var(--accent)"; tabEcs.style.color = "white";
        if (tabUes) { tabUes.style.background = ""; tabUes.style.color = ""; }
        if (tabOcsf) { tabOcsf.style.background = ""; tabOcsf.style.color = ""; }
        try {
          const res = await fetch(`/api/events/${currentInspectedEvent.event_id}/crosswalk?format=ecs`);
          const d = await res.json();
          el.inspectUesJson.textContent = JSON.stringify(d.ecs, null, 2);
        } catch (e) {
          el.inspectUesJson.textContent = "Error fetching ECS format: " + e.message;
        }
      });
    }
  }

  function closeInspector() {
    el.inspectorModal.classList.remove("open");
  }

  // --------------------------------------------------------------------------
  // Live SSE Streaming & Real-Time Broadcast Dispatcher
  // --------------------------------------------------------------------------
  let sseReconnectTimer = null;

  function setupSSE() {
    const liveBadge = document.getElementById("liveStreamBadge");
    if (!window.EventSource) return;

    if (state.sseEventSource) {
      try { state.sseEventSource.close(); } catch (e) {}
      state.sseEventSource = null;
    }

    const source = new EventSource("/api/stream");
    state.sseEventSource = source;

    source.onopen = () => {
      state.sseConnected = true;
      state.sseReconnectAttempts = 0;
      if (liveBadge) {
        liveBadge.style.display = "inline-flex";
        liveBadge.innerHTML = `<span class="pulse-dot"></span> Stream Live`;
        liveBadge.style.borderColor = "rgba(16, 185, 129, 0.4)";
      }
    };

    source.onmessage = (e) => {
      try {
        const payload = JSON.parse(e.data);

        // 1. Live Connection Telemetry update
        if (payload && payload.type === "connection_update") {
          handleConnectionUpdate(payload.data);
          return;
        }

        // 2. Source Health & Metrics update
        if (payload && payload.type === "source_health_update") {
          handleSourceHealthUpdate(payload.data);
          return;
        }

        // 3. Top Metrics update
        if (payload && payload.type === "metrics_update") {
          if (payload.data) {
            const s = payload.data;
            const totalEl = document.getElementById("statTotalEvents");
            const blockedEl = document.getElementById("statBlockedEvents");
            const highSevEl = document.getElementById("statHighSeverity");
            const velocityEl = document.getElementById("statVelocity");
            if (totalEl) totalEl.textContent = (s.total_events || 0).toLocaleString();
            if (blockedEl) blockedEl.textContent = (s.blocked_events || 0).toLocaleString();
            if (highSevEl) highSevEl.textContent = (s.high_severity_events || 0).toLocaleString();
            if (velocityEl) velocityEl.textContent = `${s.events_last_1h || 0} / hr`;
            const deadBadge = document.getElementById("tabDeadLetterBadge");
            if (deadBadge) deadBadge.textContent = s.dead_letter_count || 0;
          }
          return;
        }

        // 4. Ingested Event (either payload.data or raw event object)
        const newEvent = (payload && payload.type === "event_ingested") ? payload.data : payload;
        if (newEvent && (newEvent.event_id || newEvent.schema_version)) {
          if (state.currentPage === 1 && !state.filters.search) {
            state.events.unshift(newEvent);
            state.totalEvents += 1;
            if (virtualScroller) virtualScroller.render();
            renderPagination();
          }
          fetchStats();
        }
      } catch (err) {}
    };

    source.onerror = () => {
      state.sseConnected = false;
      if (liveBadge) {
        liveBadge.style.display = "inline-flex";
        liveBadge.innerHTML = `<span class="pulse-dot" style="background: #f59e0b;"></span> Reconnecting...`;
        liveBadge.style.borderColor = "rgba(245, 158, 11, 0.4)";
      }
      try { source.close(); } catch (e) {}

      // Auto-reconnect with exponential backoff (1s, 1.5s, 2.25s, max 10s)
      if (!sseReconnectTimer) {
        state.sseReconnectAttempts = (state.sseReconnectAttempts || 0) + 1;
        const delay = Math.min(10000, 1000 * Math.pow(1.5, Math.min(state.sseReconnectAttempts, 6)));
        sseReconnectTimer = setTimeout(() => {
          sseReconnectTimer = null;
          setupSSE();
        }, delay);
      }
    };
  }

  // --------------------------------------------------------------------------
  // Tab Switching Management
  // --------------------------------------------------------------------------
  function switchTab(target) {
    state.activeTab = target;
    if (el.proTabsBar) {
      el.proTabsBar.querySelectorAll(".pro-tab").forEach((t) => {
        t.classList.toggle("active", t.getAttribute("data-tab") === target);
      });
    }

    const sourcesPanel = document.getElementById("tabContentSources");
    const connectionsPanel = document.getElementById("tabContentConnections");
    if (sourcesPanel) sourcesPanel.style.display = target === "sources" ? "block" : "none";
    if (connectionsPanel) connectionsPanel.style.display = target === "connections" ? "block" : "none";
    if (el.eventsPanel) el.eventsPanel.style.display = target === "events" ? "flex" : "none";
    if (el.deadLetterPanel) el.deadLetterPanel.style.display = target === "deadletter" ? "block" : "none";
    if (el.parsersPanel) el.parsersPanel.style.display = target === "parsers" ? "block" : "none";
    if (el.filterSection) el.filterSection.style.display = (target === "sources" || target === "connections") ? "none" : "block";

    if (target === "sources") fetchSources();
    if (target === "connections") fetchConnections();
    if (target === "deadletter") fetchDeadLetterRecords();
    if (target === "parsers") fetchParsersHealth();
    if (target === "events") {
      if (virtualScroller) {
        virtualScroller.render();
        requestAnimationFrame(() => {
          virtualScroller.render();
        });
        setTimeout(() => {
          if (virtualScroller) virtualScroller.render();
        }, 50);
      }
    }
  }

  // --------------------------------------------------------------------------
  // Toast Notification & Clipboard Helpers
  // --------------------------------------------------------------------------
  function showToast(message, type = "success") {
    let toast = document.getElementById("ulpfToast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "ulpfToast";
      toast.className = "ulpf-toast";
      document.body.appendChild(toast);
    }
    toast.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${type === 'success' ? '#10b981' : '#f59e0b'}" stroke-width="2">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
      </svg>
      <span>${escapeHtml(message)}</span>
    `;
    toast.classList.add("show");
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
      toast.classList.remove("show");
    }, 2200);
  }

  function copyToClipboard(text, label = "Item") {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      showToast(`Copied ${label} to clipboard!`);
    }).catch(() => {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      showToast(`Copied ${label} to clipboard!`);
    });
  }

  // --------------------------------------------------------------------------
  // Live Sockets & Host Telemetry Management
  // --------------------------------------------------------------------------
  function handleConnectionUpdate(data) {
    if (!data) return;
    const conns = data.connections || [];
    const stats = data.stats || {};
    state.connections = conns;
    state.liveMonitorRunning = !!stats.running;
    state.liveMonitorStats = stats;

    const dbConns = conns.filter((c) => {
      const p = c.dst_port || c.src_port;
      const svc = (c.service_inferred || "").toLowerCase();
      return [3306, 5432, 1433, 1521, 27017, 6379].includes(p) || svc.includes("mysql") || svc.includes("database") || svc.includes("postgres") || svc.includes("redis");
    });
    const remoteConns = conns.filter((c) => !c.is_localhost);
    const cleanConns = conns.filter((c) => !(c.pid === 0 && (c.state === "TIME_WAIT" || c.state === "CLOSE_WAIT")));

    // Update connection badge on tab
    const badge = document.getElementById("tabConnectionsBadge");
    if (badge) {
      badge.textContent = cleanConns.length;
      badge.style.display = cleanConns.length > 0 ? "inline-block" : "none";
    }

    // Update Connection Metrics
    const totalEl = document.getElementById("connStatTotal");
    const dbEl = document.getElementById("connStatDB");
    const remoteEl = document.getElementById("connStatRemote");
    const lastScanEl = document.getElementById("connStatLastScan");

    const badgeClean = document.getElementById("badgeCleanCount");
    const badgeDB = document.getElementById("badgeDBCount");
    const badgeRemote = document.getElementById("badgeRemoteCount");

    if (totalEl) totalEl.textContent = conns.length.toLocaleString();
    if (dbEl) dbEl.textContent = dbConns.length.toLocaleString();
    if (remoteEl) remoteEl.textContent = remoteConns.length.toLocaleString();
    if (badgeClean) badgeClean.textContent = cleanConns.length;
    if (badgeDB) badgeDB.textContent = dbConns.length;
    if (badgeRemote) badgeRemote.textContent = remoteConns.length;

    if (lastScanEl) {
      if (stats.last_scan_time) {
        lastScanEl.textContent = formatTimestamp(stats.last_scan_time);
      } else if (conns.length > 0) {
        lastScanEl.textContent = "Live Stream (<5ms)";
      } else {
        lastScanEl.textContent = "--";
      }
    }

    // Update control button and alert banner
    updateLiveMonitorControls(stats);

    // If active tab is connections, re-render table
    if (state.activeTab === "connections") {
      renderConnectionsTable();
    }
  }

  function updateLiveMonitorControls(stats) {
    const btn = document.getElementById("btnToggleLiveMonitor");
    const statusText = document.getElementById("connStreamStatusText");
    const statusBadge = document.getElementById("connStreamStatus");
    const alertBox = document.getElementById("connPermissionAlert");
    const alertText = document.getElementById("connPermissionAlertText");

    const isRunning = !!(stats && stats.running);
    const permError = stats && stats.permission_error;

    if (btn) {
      if (isRunning) {
        btn.className = "btn-conn-stop";
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="2"></rect></svg> <span>Stop Monitor</span>`;
      } else {
        btn.className = "btn-conn-start";
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> <span>Start Live Monitor</span>`;
      }
    }

    if (statusText) {
      statusText.textContent = isRunning ? "Live Monitoring (0.5s)" : "Monitor Inactive";
    }
    if (statusBadge) {
      if (isRunning) {
        statusBadge.classList.add("active");
        statusBadge.style.color = "var(--color-success)";
      } else {
        statusBadge.classList.remove("active");
        statusBadge.style.color = "var(--text-muted)";
      }
    }

    if (alertBox && alertText) {
      if (permError) {
        alertText.textContent = permError;
        alertBox.style.display = "flex";
      } else {
        alertBox.style.display = "none";
      }
    }
  }

  async function fetchConnections() {
    const refreshBtn = document.getElementById("btnRefreshConnections");
    if (refreshBtn) refreshBtn.classList.add("spinning");
    try {
      const res = await fetch("/api/live-monitor/connections");
      if (!res.ok) return;
      const data = await res.json();
      handleConnectionUpdate(data);
      showToast("Refreshed socket snapshot", "success");
    } catch (e) {
      console.warn("fetchConnections error:", e);
    } finally {
      if (refreshBtn) {
        setTimeout(() => refreshBtn.classList.remove("spinning"), 500);
      }
    }
  }

  function getFilteredConnections() {
    let list = state.connections || [];
    const filter = (state.connFilters && state.connFilters.filter) ? state.connFilters.filter : "clean";
    const search = (state.connFilters && state.connFilters.search ? state.connFilters.search : "").toLowerCase();

    if (filter === "clean") {
      list = list.filter((c) => !(c.pid === 0 && (c.state === "TIME_WAIT" || c.state === "CLOSE_WAIT")));
    } else if (filter === "db") {
      list = list.filter((c) => {
        const p = c.dst_port || c.src_port;
        const svc = (c.service_inferred || "").toLowerCase();
        return [3306, 5432, 1433, 1521, 27017, 6379].includes(p) || svc.includes("mysql") || svc.includes("database") || svc.includes("postgres") || svc.includes("redis");
      });
    } else if (filter === "remote") {
      list = list.filter((c) => !c.is_localhost);
    } else if (filter === "localhost") {
      list = list.filter((c) => c.is_localhost);
    }

    if (search) {
      list = list.filter((c) => {
        const str = `${c.pid} ${c.process_name} ${c.src_ip} ${c.src_port} ${c.dst_ip} ${c.dst_port} ${c.service_inferred} ${c.state} ${c.proto}`.toLowerCase();
        return str.includes(search);
      });
    }
    return list;
  }

  function renderConnectionsTable() {
    const tbody = document.getElementById("connectionsTableBody");
    if (!tbody) return;

    if (!state.liveMonitorRunning && (!state.connections || state.connections.length === 0)) {
      tbody.innerHTML = `<tr><td colspan="9" class="host-empty">
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px; padding:24px 0;">
          <div style="font-size:1.8rem;">📡</div>
          <div style="font-weight:600; color:var(--text-primary);">Live Socket Monitor is Inactive</div>
          <div style="font-size:0.8rem; color:var(--text-muted); max-width:420px; text-align:center;">
            Click <strong>"Start Live Monitor"</strong> above to capture sub-second TCP/UDP socket activity, active MySQL sessions, and external telemetry with zero SIEM grid pollution.
          </div>
        </div>
      </td></tr>`;
      return;
    }

    const list = getFilteredConnections();

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="host-empty">
        <div style="padding:20px 0;">No active socket connections matching current filters.</div>
      </td></tr>`;
      return;
    }

    tbody.innerHTML = list
      .map((c) => {
        const isLocal = !!c.is_localhost;
        const scopeBadge = isLocal
          ? `<span class="badge badge-subtle" style="font-size:0.7rem; letter-spacing:0.02em;">Localhost</span>`
          : `<span class="badge" style="background:rgba(168,85,247,0.15); border:1px solid rgba(168,85,247,0.3); color:#c084fc; font-size:0.7rem; font-weight:600;">Remote</span>`;

        const svcLower = (c.service_inferred || "").toLowerCase();
        const isDB = svcLower.includes("mysql") ||
                     svcLower.includes("database") ||
                     svcLower.includes("postgres") ||
                     svcLower.includes("redis") ||
                     [3306, 5432, 1433, 1521, 27017, 6379].includes(c.dst_port) ||
                     [3306, 5432, 1433, 1521, 27017, 6379].includes(c.src_port);

        let svcBadge = `<span class="conn-badge-generic">🔹 ${escapeHtml(c.service_inferred || "TCP Socket")}</span>`;
        if (isDB) {
          svcBadge = `<span class="conn-badge-db">🗄️ ${escapeHtml(c.service_inferred || "Database")}</span>`;
        } else if (svcLower.includes("http") || svcLower.includes("api") || [80, 443, 8000, 8080, 5000].includes(c.dst_port) || [80, 443, 8000, 8080, 5000].includes(c.src_port)) {
          svcBadge = `<span class="conn-badge-http">🌐 ${escapeHtml(c.service_inferred || "HTTP / API")}</span>`;
        }

        const isEst = (c.state === "ESTABLISHED" || c.state === "5");
        const isListen = (c.state === "LISTEN" || c.state === "LISTENING");
        const dotClass = isEst ? "green" : (isListen ? "orange" : "gray");
        const stateHtml = `<span class="conn-state-pill"><span class="conn-state-dot ${dotClass}"></span>${escapeHtml(c.state || "ESTABLISHED")}</span>`;

        const pName = c.process_name || "system";
        const pPath = c.process_path ? ` title="${escapeHtml(c.process_path)}"` : "";
        const isTCP = (c.proto || "tcp").toLowerCase() === "tcp";
        const protoBadge = `<span class="badge" style="background:${isTCP ? 'rgba(56,189,248,0.12)' : 'rgba(192,132,252,0.12)'}; color:${isTCP ? '#38bdf8' : '#c084fc'}; border:1px solid ${isTCP ? 'rgba(56,189,248,0.25)' : 'rgba(192,132,252,0.25)'}; font-size:0.72rem; font-weight:700;">${(c.proto || "TCP").toUpperCase()}</span>`;

        const srcEndpoint = `${c.src_ip}:${c.src_port}`;
        const dstEndpoint = `${c.dst_ip}:${c.dst_port}`;
        const fiveTuple = `${srcEndpoint} -> ${dstEndpoint} (${c.proto || 'tcp'})`;

        return `
          <tr>
            <td>
              <div class="conn-process-badge"${pPath}>
                <span style="font-weight:600; color:var(--text-primary); font-size:0.84rem;">${escapeHtml(pName)}</span>
                <span class="conn-pid-tag">${c.pid}</span>
              </div>
            </td>
            <td>${protoBadge}</td>
            <td>
              <div class="conn-endpoint-pill btn-copy-src" data-val="${escapeHtml(srcEndpoint)}" title="Click to copy source endpoint">
                <span>${escapeHtml(srcEndpoint)}</span>
                <svg class="conn-copy-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </div>
            </td>
            <td style="color:var(--text-muted); text-align:center; font-size:0.85rem;">➔</td>
            <td>
              <div class="conn-endpoint-pill btn-copy-dst" data-val="${escapeHtml(dstEndpoint)}" title="Click to copy destination endpoint">
                <span style="font-weight:600;">${escapeHtml(dstEndpoint)}</span>
                <svg class="conn-copy-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </div>
            </td>
            <td>${svcBadge}</td>
            <td>${stateHtml}</td>
            <td>${scopeBadge}</td>
            <td style="text-align:center;">
              <button class="btn-action-copy btn-copy-5tuple" data-tuple="${escapeHtml(fiveTuple)}" title="Copy 5-tuple (${escapeHtml(fiveTuple)})">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
            </td>
          </tr>
        `;
      })
      .join("");

    // Attach copy listeners
    tbody.querySelectorAll(".btn-copy-src, .btn-copy-dst").forEach((pill) => {
      pill.addEventListener("click", () => {
        const val = pill.getAttribute("data-val");
        copyToClipboard(val, `endpoint "${val}"`);
      });
    });

    tbody.querySelectorAll(".btn-copy-5tuple").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tuple = btn.getAttribute("data-tuple");
        copyToClipboard(tuple, `connection 5-tuple`);
      });
    });
  }

  function setupConnectionsPanel() {
    const toggleBtn = document.getElementById("btnToggleLiveMonitor");
    const refreshBtn = document.getElementById("btnRefreshConnections");
    const copyListBtn = document.getElementById("btnCopyAllConns");
    const chips = document.getElementById("connFilterChips");
    const searchInp = document.getElementById("connSearchInput");

    state.connFilters = state.connFilters || { filter: "clean", search: "" };

    if (toggleBtn) {
      toggleBtn.addEventListener("click", async () => {
        const isRunning = state.liveMonitorRunning;
        const endpoint = isRunning ? "/api/live-monitor/stop" : "/api/live-monitor/start";
        toggleBtn.disabled = true;
        try {
          const res = await fetch(endpoint, { method: "POST" });
          if (res.ok) {
            const data = await res.json();
            handleConnectionUpdate(data);
            showToast(isRunning ? "Stopped Live Monitor" : "Started Live System Monitor", "success");
          }
        } catch (e) {
          console.warn("Toggle live monitor error:", e);
        } finally {
          toggleBtn.disabled = false;
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => fetchConnections());
    }

    if (copyListBtn) {
      copyListBtn.addEventListener("click", () => {
        const list = getFilteredConnections();
        if (!list || list.length === 0) {
          showToast("No active connections to copy", "warning");
          return;
        }
        const text = list.map((c) => `${c.proto || 'tcp'}\t${c.src_ip}:${c.src_port}\t->\t${c.dst_ip}:${c.dst_port}\t${c.process_name || 'system'}(PID:${c.pid})\t${c.service_inferred || 'socket'}\t${c.state}`).join("\n");
        copyToClipboard(text, `${list.length} connections`);
      });
    }

    if (chips) {
      chips.querySelectorAll(".conn-chip").forEach((chip) => {
        chip.addEventListener("click", () => {
          chips.querySelectorAll(".conn-chip").forEach((c) => c.classList.remove("active"));
          chip.classList.add("active");
          state.connFilters = state.connFilters || {};
          state.connFilters.filter = chip.getAttribute("data-conn-filter") || "clean";
          renderConnectionsTable();
        });
      });
    }

    if (searchInp) {
      searchInp.addEventListener(
        "input",
        debounce((e) => {
          state.connFilters = state.connFilters || {};
          state.connFilters.search = e.target.value;
          renderConnectionsTable();
        }, 120)
      );
    }
  }

  // --------------------------------------------------------------------------
  // Sources & Declarative Onboarding Engine
  // --------------------------------------------------------------------------
  function handleSourceHealthUpdate(data) {
    if (!data) return;
    state.sources = data.sources || [];
    state.sourceMetrics = data.metrics || {};
    if (state.activeTab === "sources") {
      renderSourcesTable(state.sources, state.sourceMetrics);
    }
  }

  async function fetchSources() {
    try {
      const res = await fetch("/api/sources");
      if (!res.ok) return;
      const data = await res.json();
      handleSourceHealthUpdate(data);
    } catch (err) {
      console.warn("fetchSources error:", err);
    }
  }

  function renderSourcesTable(sources, metrics) {
    const activeEl = document.getElementById("srcStatActive");
    const epsEl = document.getElementById("srcStatEPS");
    const valEl = document.getElementById("srcStatValidity");
    const dlqEl = document.getElementById("srcStatDLQ");
    const tbody = document.getElementById("sourcesTableBody");

    if (activeEl) activeEl.textContent = `${metrics.active_sources || 0} / ${metrics.total_sources_registered || 0}`;
    if (epsEl) epsEl.textContent = `${(metrics.total_events || 0).toLocaleString()} events`;
    if (valEl) valEl.textContent = `${metrics.validity_rate_pct || 100}%`;
    if (dlqEl) dlqEl.textContent = (metrics.total_dead_letter || 0).toLocaleString();

    if (!tbody) return;
    if (!sources || sources.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="host-empty">No log sources registered yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = sources
      .map((s) => {
        const isEnabled = s.enabled === 1;
        const statusBadge = isEnabled
          ? `<span class="badge badge-allow">ACTIVE</span>`
          : `<span class="badge badge-subtle">DISABLED</span>`;
        
        let healthBadge = `<span class="badge badge-allow">● Healthy</span>`;
        if (s.health_state === "warning" || s.dead_letter_count > 0) {
          healthBadge = `<span class="badge badge-cat-threat" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b;">● Warning (${s.dead_letter_count} DLQ)</span>`;
        } else if (s.health_state === "error") {
          healthBadge = `<span class="badge badge-deny">● Error</span>`;
        }

        const typeBadge = s.source_type === "declarative"
          ? `<span class="badge badge-cat-system" style="background: rgba(168, 85, 247, 0.15); color: #a855f7;">No-Code (${escapeHtml(s.input_type || "YAML")})</span>`
          : `<span class="badge badge-subtle">Built-in (${escapeHtml(s.input_type || "plugin")})</span>`;

        const lastEvent = s.last_event_at ? formatTimestamp(s.last_event_at) : "Never";

        return `
          <tr>
            <td>
              <strong style="color: var(--text-primary); font-size: 0.9rem;">${escapeHtml(s.name || s.source_id)}</strong>
              <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(s.vendor || "")} / ${escapeHtml(s.product || "")}</div>
            </td>
            <td>${typeBadge}</td>
            <td>${healthBadge}</td>
            <td class="mono-text" style="font-weight: 600;">${(s.events_processed || 0).toLocaleString()}</td>
            <td>${statusBadge}</td>
            <td class="mono-text" style="font-size: 0.75rem; color: var(--text-muted);">${lastEvent}</td>
            <td>
              <div style="display: flex; gap: 6px;">
                <button class="pagination-btn btn-toggle-src" data-id="${escapeHtml(s.source_id)}" data-enabled="${isEnabled ? '1' : '0'}" style="padding: 2px 8px; font-size: 0.75rem;">
                  ${isEnabled ? 'Disable' : 'Enable'}
                </button>
                ${s.source_type === 'declarative' ? `<button class="pagination-btn btn-del-src" data-id="${escapeHtml(s.source_id)}" style="padding: 2px 8px; font-size: 0.75rem; color: var(--color-danger);">Delete</button>` : ''}
              </div>
            </td>
          </tr>
        `;
      })
      .join("");

    // Attach action listeners
    tbody.querySelectorAll(".btn-toggle-src").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const sId = btn.getAttribute("data-id");
        const isEn = btn.getAttribute("data-enabled") === "1";
        const endpoint = isEn ? `/api/sources/${sId}/disable` : `/api/sources/${sId}/enable`;
        await fetch(endpoint, { method: "POST" });
        fetchSources();
      });
    });

    tbody.querySelectorAll(".btn-del-src").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const sId = btn.getAttribute("data-id");
        if (confirm(`Delete declarative source '${sId}'?`)) {
          await fetch(`/api/sources/${sId}`, { method: "DELETE" });
          fetchSources();
        }
      });
    });
  }

  function setupOnboardingWizard() {
    const modal = document.getElementById("onboardingModal");
    const openBtn = document.getElementById("openOnboardingBtn");
    const closeBtn = document.getElementById("closeOnboardingBtn");
    const cancelBtn = document.getElementById("cancelOnboardingBtn");
    const inferBtn = document.getElementById("wizardInferBtn");
    const testBtn = document.getElementById("wizardTestBtn");
    const saveBtn = document.getElementById("saveOnboardingBtn");

    const sampleArea = document.getElementById("wizardSampleEvent");
    const yamlArea = document.getElementById("wizardConfigYaml");
    const resultsBox = document.getElementById("wizardTestResults");
    const statusBadge = document.getElementById("wizardStatusBadge");
    const extractedPre = document.getElementById("wizardExtractedJson");
    const normalizedPre = document.getElementById("wizardNormalizedJson");

    const sampleKV = 'devtime="2024-03-15T10:22:45Z" hostname=fw-edge-01 srcip=192.168.1.55 dstip=10.0.0.12 srcport=54321 dstport=443 proto=TCP action=deny user=malicious_actor bytes_in=0 bytes_out=64';
    const sampleCSV = 'SECURE_PROXY_GW,2024-03-15T10:22:45Z,192.168.1.105,198.51.100.20,443,alice,CONNECT,200,1024,4096,allow';
    const sampleJSON = '{"auth_event_type":"login_failed","account_id":"acc-9921","timestamp":"2024-03-15T10:22:45Z","status":"failure","actor":{"username":"admin","ip":"203.0.113.88"},"policy":{"rule_id":"AUTH_RULE_01"}}';

    if (openBtn && modal) {
      openBtn.addEventListener("click", () => {
        if (!sampleArea.value.trim()) sampleArea.value = sampleKV;
        if (!yamlArea.value.trim()) {
          yamlArea.value = `name: custom_firewall\nvendor: CustomSec\nproduct: PerimeterGuard\nversion: "1.0.0"\nenabled: true\nlog_format: "custom_fw"\n\nframing:\n  type: line\n\ndetection:\n  contains:\n    - "srcip="\n    - "dstip="\n  contains_mode: all\n\nparser:\n  type: key_value\n  pair_delimiter: " "\n  kv_delimiter: "="\n\nfields:\n  timestamp: devtime\n  types:\n    srcport: port\n    dstport: port\n    bytes_in: int\n    bytes_out: int\n\nnormalize:\n  source.vendor: CustomSec\n  source.product: PerimeterGuard\n  source.device_hostname: hostname\n  event.category: network\n  event.action: action\n  event.outcome: action\n  event.severity_numeric: 5.0\n  network.src_ip: srcip\n  network.dst_ip: dstip\n  network.src_port: srcport\n  network.dst_port: dstport\n  network.protocol: proto\n  identity.username: user\n  retain_unmapped: true`;
        }
        modal.classList.add("open");
      });
    }

    if (closeBtn) closeBtn.addEventListener("click", () => modal.classList.remove("open"));
    if (cancelBtn) cancelBtn.addEventListener("click", () => modal.classList.remove("open"));

    document.getElementById("wizardLoadSampleKVBtn")?.addEventListener("click", () => {
      sampleArea.value = sampleKV;
      inferBtn?.click();
    });
    document.getElementById("wizardLoadSampleCSVBtn")?.addEventListener("click", () => {
      sampleArea.value = sampleCSV;
      inferBtn?.click();
    });
    document.getElementById("wizardLoadSampleJSONBtn")?.addEventListener("click", () => {
      sampleArea.value = sampleJSON;
      inferBtn?.click();
    });

    if (inferBtn) {
      inferBtn.addEventListener("click", async () => {
        const text = sampleArea.value.trim();
        if (!text) { alert("Please paste a sample log line first."); return; }
        inferBtn.textContent = "Inferring...";
        try {
          const res = await fetch("/api/sources/infer", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sample_event: text, name_hint: "custom_source" }),
          });
          const d = await res.json();
          if (d.draft_config) {
            // Format into YAML string or JSON
            yamlArea.value = JSON.stringify(d.draft_config, null, 2);
          }
        } catch (e) {
          alert("Inference failed: " + e.message);
        } finally {
          inferBtn.textContent = "⚡ Auto-Infer Configuration";
        }
      });
    }

    if (testBtn) {
      testBtn.addEventListener("click", async () => {
        const sample = sampleArea.value.trim();
        const cfgText = yamlArea.value.trim();
        if (!sample || !cfgText) { alert("Sample event and configuration are required."); return; }

        let parsedCfg = null;
        try {
          parsedCfg = JSON.parse(cfgText);
        } catch (e) {
          // If pure YAML, send as config dict or parse basic keys
          alert("Please verify configuration is formatted properly (valid JSON/YAML).");
          return;
        }

        testBtn.textContent = "Testing...";
        try {
          const res = await fetch("/api/sources/test", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ config: parsedCfg, sample_event: sample, tenant_id: "demo_tenant" }),
          });
          const result = await res.json();
          resultsBox.style.display = "block";
          if (result.valid) {
            statusBadge.innerHTML = `<span class="badge badge-allow" style="font-size: 0.85rem; padding: 4px 10px;">✔ VALIDATION PASSED — Matched Format: ${escapeHtml(result.detected_format)} (Hash: ${result.raw_hash.substring(0, 12)}...)</span>`;
          } else {
            statusBadge.innerHTML = `<span class="badge badge-deny" style="font-size: 0.85rem; padding: 4px 10px;">✖ VALIDATION FAILED: ${(result.errors || []).join("; ")}</span>`;
          }
          extractedPre.textContent = JSON.stringify(result.extracted_fields, null, 2);
          normalizedPre.textContent = JSON.stringify(result.normalized_event, null, 2);
        } catch (e) {
          alert("Test failed: " + e.message);
        } finally {
          testBtn.textContent = "▶ Test Mapping Against Sample";
        }
      });
    }

    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        const cfgText = yamlArea.value.trim();
        let parsedCfg = null;
        try {
          parsedCfg = JSON.parse(cfgText);
        } catch (e) {
          alert("Please ensure configuration is valid JSON/YAML.");
          return;
        }

        try {
          saveBtn.textContent = "Saving...";
          const res = await fetch("/api/sources", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ config: parsedCfg }),
          });
          const d = await res.json();
          if (res.ok) {
            alert(`Log Source '${parsedCfg.name}' successfully activated!`);
            modal.classList.remove("open");
            fetchSources();
          } else {
            alert(`Failed to save source: ${JSON.stringify(d.detail)}`);
          }
        } catch (e) {
          alert("Save error: " + e.message);
        } finally {
          saveBtn.textContent = "✔ Save & Activate Source";
        }
      });
    }
  }

  // --------------------------------------------------------------------------
  // Keyboard Shortcuts Manager
  // --------------------------------------------------------------------------
  function setupKeyboardShortcuts() {
    window.addEventListener("keydown", (e) => {
      // Ignore when typing inside input / select / textarea
      if (["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName)) {
        if (e.key === "Escape") e.target.blur();
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        el.searchInput.focus();
      } else if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        if (state.events.length > 0) {
          const nextIdx = Math.min(state.events.length - 1, state.selectedRowIndex + 1);
          selectRow(nextIdx);
        }
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        if (state.events.length > 0) {
          const prevIdx = Math.max(0, state.selectedRowIndex - 1);
          selectRow(prevIdx);
        }
      } else if (e.key === "Enter") {
        if (state.selectedRowIndex >= 0 && state.selectedRowIndex < state.events.length) {
          openEventInspector(state.events[state.selectedRowIndex].event_id);
        }
      } else if (e.key === "Escape") {
        closeInspector();
        el.shortcutsModal.classList.remove("open");
      } else if (e.key === "t" || e.key === "T") {
        toggleColorTheme();
      } else if (e.key === "v" || e.key === "V") {
        toggleViewMode();
      } else if (e.key === "d" || e.key === "D") {
        setViewMode("default");
      } else if (e.key === "p" || e.key === "P") {
        setViewMode("professional");
      } else if (e.key === "?") {
        el.shortcutsModal.classList.add("open");
      }
    });
  }

  // --------------------------------------------------------------------------
  // General Utility Functions
  // --------------------------------------------------------------------------
  function formatTimestamp(isoStr) {
    if (!isoStr) return "-";
    try {
      const dt = new Date(isoStr);
      if (isNaN(dt.getTime())) return isoStr;
      const pad = (n) => String(n).padStart(2, "0");
      return `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())} ${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())}:${pad(dt.getUTCSeconds())} UTC`;
    } catch {
      return isoStr;
    }
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function debounce(func, wait) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // --------------------------------------------------------------------------
  // Event Listeners & Initialization
  // --------------------------------------------------------------------------
  function init() {
    virtualScroller = new VirtualScroller(el.virtualViewport, el.virtualSpacer, el.virtualContent);
    setColorTheme(state.colorTheme);
    setViewMode(state.viewMode);

    // Search input debouncer
    el.searchInput.addEventListener(
      "input",
      debounce((e) => {
        state.filters.search = e.target.value;
        fetchEvents(1);
      }, 250)
    );

    // View Mode buttons
    if (el.viewDefaultBtn) el.viewDefaultBtn.addEventListener("click", () => setViewMode("default"));
    if (el.viewProBtn) el.viewProBtn.addEventListener("click", () => setViewMode("professional"));

    // Color Theme toggle button
    if (el.colorThemeBtn) el.colorThemeBtn.addEventListener("click", toggleColorTheme);

    // Pagination buttons
    if (el.prevPageBtn) el.prevPageBtn.addEventListener("click", () => fetchEvents(state.currentPage - 1));
    if (el.nextPageBtn) el.nextPageBtn.addEventListener("click", () => fetchEvents(state.currentPage + 1));

    // Modals
    el.closeInspectorBtn.addEventListener("click", closeInspector);
    el.closeShortcutsBtn.addEventListener("click", () => el.shortcutsModal.classList.remove("open"));
    el.shortcutsHelpBtn.addEventListener("click", () => el.shortcutsModal.classList.add("open"));

    // Copy buttons
    el.copyRawBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(el.inspectRawPayload.textContent);
      el.copyRawBtn.textContent = "Copied!";
      setTimeout(() => (el.copyRawBtn.textContent = "Copy Raw"), 1500);
    });

    el.copyJsonBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(el.inspectUesJson.textContent);
      el.copyJsonBtn.textContent = "Copied!";
      setTimeout(() => (el.copyJsonBtn.textContent = "Copy JSON"), 1500);
    });

    // Quick filter chips
    if (el.quickChips) {
      el.quickChips.querySelectorAll(".chip").forEach((chip) => {
        chip.addEventListener("click", () => {
          const filterType = chip.getAttribute("data-filter");

          if (filterType === "live_host") {
            switchTab("livehost");
            return;
          }

          if (state.activeTab !== "events") {
            switchTab("events");
          }

          el.quickChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
          chip.classList.add("active");

          if (filterType === "all") {
            state.filters.action = "";
            state.filters.severityMin = null;
          } else if (filterType === "blocked") {
            state.filters.action = "deny";
            state.filters.severityMin = null;
          } else if (filterType === "high_sev") {
            state.filters.severityMin = 7.0;
            state.filters.action = "";
          }
          fetchEvents(1);
        });
      });
    }

    // Pro Filter inputs
    if (el.vendorFilter) el.vendorFilter.addEventListener("change", (e) => { state.filters.vendor = e.target.value; fetchEvents(1); });
    if (el.categoryFilter) el.categoryFilter.addEventListener("change", (e) => { state.filters.category = e.target.value; fetchEvents(1); });
    if (el.actionFilter) el.actionFilter.addEventListener("change", (e) => { state.filters.action = e.target.value; fetchEvents(1); });
    if (el.outcomeFilter) el.outcomeFilter.addEventListener("change", (e) => { state.filters.outcome = e.target.value; fetchEvents(1); });
    if (el.parserFilter) el.parserFilter.addEventListener("change", (e) => { state.filters.parserName = e.target.value; fetchEvents(1); });

    // Navigation Tabs
    if (el.proTabsBar) {
      el.proTabsBar.querySelectorAll(".pro-tab").forEach((tab) => {
        tab.addEventListener("click", () => {
          const target = tab.getAttribute("data-tab");
          switchTab(target);
        });
      });
    }

    // Exports (passes active filters)
    function buildExportUrl(format) {
      const p = new URLSearchParams({ format });
      if (state.filters.search) p.append("search", state.filters.search);
      if (state.filters.vendor) p.append("vendor", state.filters.vendor);
      if (state.filters.category) p.append("category", state.filters.category);
      if (state.filters.action) p.append("action", state.filters.action);
      if (state.filters.outcome) p.append("outcome", state.filters.outcome);
      if (state.filters.parserName) p.append("parser_name", state.filters.parserName);
      return `/api/export?${p.toString()}`;
    }
    if (el.exportCsvBtn) el.exportCsvBtn.addEventListener("click", () => window.open(buildExportUrl("csv"), "_blank"));
    if (el.exportJsonBtn) el.exportJsonBtn.addEventListener("click", () => window.open(buildExportUrl("json"), "_blank"));


    setupKeyboardShortcuts();
    setupSSE();
    setupConnectionsPanel();
    setupCrosswalkTabs();
    setupOnboardingWizard();
    setupDensityToolbar();
    window.addEventListener("resize", debounce(() => virtualScroller.render(), 100));

    // Smooth 0% to 100% startup sequence
    runLoadingSequence();
  }

  // --------------------------------------------------------------------------
  // Loading Screen Animation (0% to 100%)
  // --------------------------------------------------------------------------
  async function runLoadingSequence() {
    const fill = document.getElementById("loadingProgressFill");
    const text = document.getElementById("loadingPercentText");
    const step = document.getElementById("loadingStepText");
    const screen = document.getElementById("loadingScreen");

    function setProgress(pct, msg) {
      if (fill) fill.style.width = `${pct}%`;
      if (text) text.textContent = `${pct}%`;
      if (step && msg) step.textContent = msg;
    }

    function dismissScreen() {
      if (screen && !screen.classList.contains("hidden")) {
        screen.classList.add("hidden");
        setTimeout(() => { screen.style.display = "none"; }, 400);
      }
    }

    // Safety timeout: ensure screen is ALWAYS dismissed even if network requests stall
    const safetyTimer = setTimeout(dismissScreen, 2500);

    try {
      setProgress(15, "Connecting to SQLite index cache...");
      await new Promise((r) => setTimeout(r, 80));

      setProgress(40, "Fetching Universal Event Schema metrics...");
      try { await fetchStats(); } catch (e) { console.warn(e); }
      await new Promise((r) => setTimeout(r, 80));

      setProgress(75, "Syncing perimeter normalized event store...");
      try { await fetchEvents(1); } catch (e) { console.warn(e); }
      await new Promise((r) => setTimeout(r, 80));

      setProgress(92, "Verifying parser plugin health...");
      try { await fetchParsersHealth(); } catch (e) { console.warn(e); }
      await new Promise((r) => setTimeout(r, 60));

      setProgress(100, "Pipeline ready!");
      await new Promise((r) => setTimeout(r, 100));
    } catch (e) {
      console.warn("Loading error:", e);
    } finally {
      clearTimeout(safetyTimer);
      dismissScreen();
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
