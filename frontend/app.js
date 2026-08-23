/**
 * ByteTrail — Enterprise SOC Threat Intelligence App Logic
 * Problem Statement ID: 26106 | Smart India Hackathon
 */

const API_BASE = "http://127.0.0.1:8000";

// State
let storedEmails = [];
let connectedMailboxes = [];
let activeFilter = "all";
let currentViewingId = null;
let radarMap = null;
let markerLayerGroup = null;
let graphData = { nodes: [], edges: [] };

// Provider instructions map
const PROVIDER_INFO = {
    gmail: {
        host: "imap.gmail.com",
        port: 993,
        instructions: "For Gmail: Use a 16-character Google App Password (myaccount.google.com/apppasswords)"
    },
    outlook: {
        host: "outlook.office365.com",
        port: 993,
        instructions: "For Outlook / Office 365: Use your Microsoft Account Password or App Password"
    },
    yahoo: {
        host: "imap.mail.yahoo.com",
        port: 993,
        instructions: "For Yahoo: Generate an App Password in Account Security Settings"
    },
    icloud: {
        host: "imap.mail.me.com",
        port: 993,
        instructions: "For iCloud: Generate an App-Specific Password at appleid.apple.com"
    },
    custom: {
        host: "",
        port: 993,
        instructions: "Enter your custom corporate IMAP server credentials"
    }
};

// Pre-defined Realistic Attack & Benign Scenarios
const SCENARIOS = {
    paypal: {
        sender: "security-dept@paypal-verify-user-account.com",
        subject: "URGENT ACTION REQUIRED: Account Access Suspended Immediately",
        headers: "From: PayPal Support <security-dept@paypal-verify-user-account.com>\nTo: target@victim-corp.com\nSubject: URGENT ACTION REQUIRED: Account Access Suspended Immediately\nDate: Sun, 23 Aug 2026 14:30:00 +0000\nReceived: from unknown (185.220.101.5) by mx.relay-gateway.net\nAuthentication-Results: mx.relay-gateway.net; spf=fail smtp.mailfrom=paypal-verify-user-account.com; dkim=fail; dmarc=fail\nMessage-ID: <992837198237@paypal-verify-user-account.com>",
        body: "Dear Customer,\n\nWe detected suspicious unauthorized login attempts on your account from IP address 185.220.101.5 (Moscow, Russia).\n\nTo prevent permanent account termination, please verify your identity and credit card details within 24 hours:\nhttp://paypal-verify-user-account.com/secure-login/login.php\n\nFailure to comply will lead to permanent account deactivation.\n\nPayPal Security Team"
    },
    ceo_bec: {
        sender: "ceo-update@corp-secure-finance.net",
        subject: "URGENT CONFIDENTIAL: Wire Transfer Required Before 4 PM",
        headers: "From: Executive Office <ceo-update@corp-secure-finance.net>\nReply-To: executive-wire-escrow@gmail.com\nTo: finance-lead@company.com\nReceived: from mail.cloud-relays.com (198.51.100.23) by mx.company.com\nAuthentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail\n",
        body: "Hi team,\n\nI am currently in an all-day acquisition board meeting. We need to execute an urgent confidential wire transfer of $84,500 to the vendor escrow account attached.\nPlease process immediately and confirm once transmitted.\n\nRegards,\nChief Executive Officer"
    },
    m365: {
        sender: "admin@m365-security-reauth-portal.com",
        subject: "CRITICAL: Microsoft 365 Password Expired — Re-authenticate Now",
        headers: "From: Microsoft Online Security <admin@m365-security-reauth-portal.com>\nTo: employee@company.com\nReceived: from relay-node.nigeria-net.ng (197.210.45.12) by mx.microsoft.com\nAuthentication-Results: mx.microsoft.com; spf=fail; dkim=none; dmarc=fail\n",
        body: "Your Microsoft 365 enterprise session has expired. All inbound corporate emails are placed on hold.\nPlease click below to keep your current password and restore email routing:\nhttps://m365-security-reauth-portal.com/login/auth-session.php\n\nMicrosoft IT Operations"
    },
    amazon: {
        sender: "tracking-update@amazon-shipment-reroute.com",
        subject: "Delivery Alert: Package #982-10293 Delivery Address Incomplete",
        headers: "From: Amazon Logistics <tracking-update@amazon-shipment-reroute.com>\nTo: customer@example.com\nReceived: from vps-node.amsterdam-relay.nl (188.166.50.21) by mx.mail.net\nAuthentication-Results: mx.mail.net; spf=neutral; dkim=fail; dmarc=fail\n",
        body: "We were unable to deliver your package due to an invalid street number. Please update payment and address information to reschedule delivery within 48 hours:\nhttp://amazon-shipment-reroute.com/update-address\n\nAmazon Shipping Services"
    },
    github_safe: {
        sender: "notifications@github.com",
        subject: "[GitHub] Security advisory alert: Update dependencies in ByteTrail",
        headers: "From: GitHub <notifications@github.com>\nTo: dev-team@company.com\nSubject: [GitHub] Security advisory alert: Update dependencies in ByteTrail\nReceived: from out-21.mail.github.com (192.30.252.204) by mx.google.com\nAuthentication-Results: mx.google.com; spf=pass header.i=@github.com; dkim=pass header.i=@github.com; dmarc=pass\nMessage-ID: <github/security-advisory/1029384@github.com>",
        body: "Hello,\n\nA new security advisory was published for a library used in your repository. We recommend reviewing the vulnerability severity and upgrading to the latest patched version.\n\nView advisory: https://github.com/ByteTrail/ByteTrail/security/advisories\n\nBest regards,\nThe GitHub Security Team"
    }
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    initNavTabs();
    initRadarMap();
    initEmlDropzone();
    checkBackendStatus();
    loadEmails();
    loadConnectedMailboxes();
    initEventListeners();

    // Auto health check polling
    setInterval(() => {
        checkBackendStatus();
        loadEmails(false); // Silent background refresh
    }, 10000);
});

// Setup Navigation Tabs
function initNavTabs() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            const targetTab = tab.dataset.tab;
            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });

            const activePane = document.getElementById(`pane-${targetTab}`);
            if (activePane) activePane.classList.add("active");

            // Leaflet map container fix on tab transition
            if (targetTab === "radar" && radarMap) {
                setTimeout(() => {
                    radarMap.invalidateSize();
                }, 200);
            }

            if (targetTab === "graph") {
                loadAndRenderCampaignGraph();
            }

            if (targetTab === "mailboxes") {
                loadConnectedMailboxes();
            }
        });
    });
}

// Setup Event Listeners
function initEventListeners() {
    // Ingestion Form
    const form = document.getElementById("ingest-form");
    if (form) form.addEventListener("submit", handleIngestSubmit);

    // Refresh Buttons
    const btnRefreshFeed = document.getElementById("btn-refresh-feed");
    if (btnRefreshFeed) btnRefreshFeed.addEventListener("click", () => loadEmails(true));

    const btnRefreshStream = document.getElementById("btn-refresh-stream");
    if (btnRefreshStream) btnRefreshStream.addEventListener("click", () => loadEmails(true));

    const btnRefreshGraph = document.getElementById("btn-refresh-graph");
    if (btnRefreshGraph) btnRefreshGraph.addEventListener("click", loadAndRenderCampaignGraph);

    const btnRefreshMailboxes = document.getElementById("btn-refresh-mailboxes");
    if (btnRefreshMailboxes) btnRefreshMailboxes.addEventListener("click", loadConnectedMailboxes);

    // Reset Map Zoom
    const btnResetZoom = document.getElementById("btn-reset-map-zoom");
    if (btnResetZoom) {
        btnResetZoom.addEventListener("click", () => {
            if (radarMap) radarMap.setView([25.0, 10.0], 2);
        });
    }

    // Modal Close
    const btnCloseModal = document.getElementById("btn-close-modal");
    const modalBackdrop = document.getElementById("modal-backdrop");
    if (btnCloseModal) btnCloseModal.addEventListener("click", closeForensicModal);
    if (modalBackdrop) modalBackdrop.addEventListener("click", closeForensicModal);

    // Connect Mailbox Modal Triggers
    const btnOpenConnectModal = document.getElementById("btn-open-connect-modal");
    const btnAddMailboxTab = document.getElementById("btn-add-mailbox-tab");
    const btnCloseConnectModal = document.getElementById("btn-close-connect-modal");
    const btnCancelConnectMb = document.getElementById("btn-cancel-connect-mb");
    const connectModalBackdrop = document.getElementById("connect-modal-backdrop");

    const openConnectModal = () => {
        document.getElementById("connect-mailbox-modal").classList.remove("hidden");
    };
    const closeConnectModal = () => {
        document.getElementById("connect-mailbox-modal").classList.add("hidden");
    };

    if (btnOpenConnectModal) btnOpenConnectModal.addEventListener("click", openConnectModal);
    if (btnAddMailboxTab) btnAddMailboxTab.addEventListener("click", openConnectModal);
    if (btnCloseConnectModal) btnCloseConnectModal.addEventListener("click", closeConnectModal);
    if (btnCancelConnectMb) btnCancelConnectMb.addEventListener("click", closeConnectModal);
    if (connectModalBackdrop) connectModalBackdrop.addEventListener("click", closeConnectModal);

    // Provider Dropdown Change
    const mbProviderSelect = document.getElementById("mb-provider");
    if (mbProviderSelect) {
        mbProviderSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            const info = PROVIDER_INFO[val] || PROVIDER_INFO.custom;
            document.getElementById("mb-instructions").textContent = info.instructions;

            const customFields = document.getElementById("custom-imap-fields");
            if (val === "custom") {
                customFields.classList.remove("hidden");
            } else {
                customFields.classList.add("hidden");
            }
        });
    }

    // Connect Mailbox Form Submit
    const connectMbForm = document.getElementById("connect-mailbox-form");
    if (connectMbForm) {
        connectMbForm.addEventListener("submit", handleConnectMailboxSubmit);
    }

    // Download PDF from Modal
    const modalDlBtn = document.getElementById("modal-dl-pdf-btn");
    if (modalDlBtn) {
        modalDlBtn.addEventListener("click", () => {
            if (currentViewingId) downloadReport(currentViewingId);
        });
    }

    // Filter Chips
    const filterChips = document.querySelectorAll(".filter-chip");
    filterChips.forEach(chip => {
        chip.addEventListener("click", () => {
            filterChips.forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            activeFilter = chip.dataset.filter;
            applyFeedFilters();
        });
    });

    // Search Input
    const searchInput = document.getElementById("feed-search");
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            applyFeedFilters();
        });
    }

    // Scenario Testbench Cards
    const scenarioCards = document.querySelectorAll(".scenario-card");
    scenarioCards.forEach(card => {
        const scenarioKey = card.dataset.scenario;
        const triggerBtn = card.querySelector(".scenario-trigger-btn");
        
        const loadHandler = () => {
            const data = SCENARIOS[scenarioKey];
            if (data) {
                document.getElementById("sender").value = data.sender;
                document.getElementById("subject").value = data.subject;
                document.getElementById("raw-headers").value = data.headers;
                document.getElementById("body-text").value = data.body;
                showToast(`Loaded scenario: ${card.querySelector(".scenario-title").textContent}`, "info");
                
                // Scroll form into view
                document.getElementById("ingest-form").scrollIntoView({ behavior: "smooth" });
            }
        };

        if (triggerBtn) triggerBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            loadHandler();
        });
        card.addEventListener("click", loadHandler);
    });

    // Copy Inbound Webhook URL
    const btnCopyWebhook = document.getElementById("btn-copy-webhook");
    if (btnCopyWebhook) {
        btnCopyWebhook.addEventListener("click", () => {
            navigator.clipboard.writeText(`${API_BASE}/api/v1/webhook/inbound`);
            showToast("📋 Webhook URL copied: http://127.0.0.1:8000/api/v1/webhook/inbound", "success");
        });
    }

    // Scan Inbound Folder Trigger
    const btnScanFolder = document.getElementById("btn-scan-folder");
    if (btnScanFolder) {
        btnScanFolder.addEventListener("click", async () => {
            showToast("Scanning backend/inbound_emails/ for dropped .eml files...", "info");
            try {
                const res = await fetch(`${API_BASE}/integrations/watcher/scan`, { method: "POST" });
                const data = await res.json();
                if (data.auto_ingested_count > 0) {
                    showToast(`✅ Auto-ingested ${data.auto_ingested_count} new email files!`, "success");
                    await loadEmails(true);
                } else {
                    showToast("No new files found in inbound folder.", "info");
                }
            } catch (e) {
                showToast(`Scan error: ${e.message}`, "error");
            }
        });
    }


}

// Setup EML Drag & Drop Zone
function initEmlDropzone() {
    const dropzone = document.getElementById("eml-dropzone");
    const fileInput = document.getElementById("eml-file-input");
    const btnBrowse = document.getElementById("btn-browse-eml");

    if (!dropzone || !fileInput) return;

    if (btnBrowse) {
        btnBrowse.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            fileInput.click();
        });
    }

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", async (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

// Upload Raw EML file to backend
async function handleFileUpload(file) {
    showToast(`Uploading & analyzing ${file.name}...`, "info");
    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch(`${API_BASE}/emails/upload-eml`, {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${response.status}`);
        }

        const data = await response.json();
        showToast(`✅ Case #${data.id} Ingested from EML: ${data.risk_level.toUpperCase()} THREAT (${data.final_score}/100)`, "success");
        await loadEmails(true);
        openForensicModal(data.id);
    } catch (err) {
        showToast(`❌ EML Upload failed: ${err.message}`, "error");
    }
}

// Initialize Leaflet Map
function initRadarMap() {
    try {
        radarMap = L.map("radar-map", {
            zoomControl: true,
            attributionControl: false
        }).setView([25.0, 10.0], 2);

        // Dark Matter tiles for Cybersecurity look
        L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            maxZoom: 18,
            subdomains: "abcd"
        }).addTo(radarMap);

        markerLayerGroup = L.layerGroup().addTo(radarMap);
    } catch (e) {
        console.error("Map error:", e);
    }
}

// Check Backend API Connection Status
async function checkBackendStatus() {
    const chip = document.getElementById("backend-status-chip");
    const label = document.getElementById("backend-status-label");
    try {
        const response = await fetch(`${API_BASE}/ping`);
        if (response.ok) {
            chip.className = "status-chip";
            label.textContent = "Pipeline Active • MySQL";
        } else {
            throw new Error();
        }
    } catch (e) {
        chip.className = "status-chip offline";
        label.textContent = "Pipeline Offline";
    }
}

// Load Ingested Emails from Backend
async function loadEmails(showFeedback = false) {
    const tbody = document.getElementById("feed-tbody");
    try {
        const res = await fetch(`${API_BASE}/emails`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const latest = await res.json();

        // Check if new emails arrived during auto-polling
        if (storedEmails.length > 0 && latest.length > storedEmails.length) {
            const newCount = latest.length - storedEmails.length;
            showToast(`🚨 ${newCount} New Inbound Email(s) Auto-Ingested & Scored!`, "success");
        }

        storedEmails = latest;
        
        updateTelemetryStats(storedEmails);
        renderStreamFeed(storedEmails);
        applyFeedFilters();
        updateMapMarkers(storedEmails);
        updateAnalyticsMatrix(storedEmails);

        document.getElementById("tab-feed-count").textContent = storedEmails.length;
        if (showFeedback) showToast("Feed refreshed from MySQL.", "info");
    } catch (err) {
        if (tbody && storedEmails.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="color: var(--threat-high);">⚠️ Could not retrieve records: ${err.message}</td></tr>`;
        }
    }
}

// Load Connected Mailboxes List
async function loadConnectedMailboxes() {
    const grid = document.getElementById("mailboxes-grid-list");
    const countBadge = document.getElementById("tab-mailbox-count");
    if (!grid) return;

    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        connectedMailboxes = await res.json();

        if (countBadge) countBadge.textContent = connectedMailboxes.length;

        if (connectedMailboxes.length === 0) {
            grid.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
                    <i class="fa-solid fa-inbox" style="font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.5;"></i>
                    <h4 style="color: var(--text-bright); margin-bottom: 0.35rem;">No Active Mailboxes Connected</h4>
                    <p style="font-size: 0.82rem; max-width: 440px; margin: 0 auto 1.25rem;">Connect your Gmail, Outlook, or corporate email account to continuously monitor and detect fraud on every incoming email in real-time.</p>
                    <button class="btn btn-cyber-primary" onclick="document.getElementById('connect-mailbox-modal').classList.remove('hidden')"><i class="fa-solid fa-plug"></i> Connect First Mailbox</button>
                </div>
            `;
            return;
        }

        grid.innerHTML = connectedMailboxes.map(mb => {
            const providerIcon = mb.provider === "gmail" ? "fa-google" : mb.provider === "outlook" ? "fa-microsoft" : mb.provider === "yahoo" ? "fa-yahoo" : "fa-envelope";
            
            return `
                <div class="card" style="padding: 1.25rem; background: var(--bg-surface);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                        <div style="display: flex; align-items: center; gap: 0.65rem;">
                            <div style="width: 36px; height: 36px; border-radius: 0.45rem; background: var(--primary-bg); border: 1px solid rgba(139, 92, 246, 0.3); display: flex; align-items: center; justify-content: center; color: var(--primary); font-size: 1.1rem;">
                                <i class="fa-brands ${providerIcon}"></i>
                            </div>
                            <div>
                                <h4 style="font-size: 0.9rem; color: var(--text-bright); font-weight: 600;">${escapeHtml(mb.email_address)}</h4>
                                <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(mb.host)}:${mb.port}</span>
                            </div>
                        </div>
                        <span class="badge-risk-pill low"><span class="pulse-dot"></span> LIVE POLLING</span>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; background: var(--bg-input); padding: 0.65rem 0.85rem; border-radius: 0.4rem; border: 1px solid var(--border-subtle); margin-bottom: 0.85rem; font-size: 0.76rem;">
                        <div>
                            <span style="color: var(--text-muted); display: block;">Threats Captured</span>
                            <strong style="color: var(--primary); font-family: var(--font-mono); font-size: 0.95rem;">${mb.total_ingested}</strong>
                        </div>
                        <div>
                            <span style="color: var(--text-muted); display: block;">Interval</span>
                            <span style="color: var(--text-primary); font-family: var(--font-mono);">Every 10s</span>
                        </div>
                    </div>

                    <div style="display: flex; gap: 0.4rem; justify-content: flex-end; flex-wrap: wrap;">
                        <button class="btn btn-sm btn-cyber-primary" onclick="deepScanConnectedMailbox(${mb.id})" title="Deep Scan All Historical Read and Unread Emails">
                            <i class="fa-solid fa-magnifying-glass"></i> Deep Scan (Read + Unread)
                        </button>
                        <button class="btn btn-sm btn-cyber-secondary" onclick="syncConnectedMailbox(${mb.id})" title="Scan New Unread Only">
                            <i class="fa-solid fa-rotate"></i> Sync New
                        </button>
                        <button class="btn btn-sm btn-cyber-secondary" style="color: var(--threat-high);" onclick="disconnectConnectedMailbox(${mb.id})" title="Disconnect Account">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Error loading mailboxes:", e);
    }
}

// Handle Connect Mailbox Form Submission
async function handleConnectMailboxSubmit(e) {
    e.preventDefault();

    const provider = document.getElementById("mb-provider").value;
    const emailAddress = document.getElementById("mb-email").value.trim();
    const password = document.getElementById("mb-password").value.trim();
    const host = document.getElementById("mb-host")?.value.trim() || null;
    const port = parseInt(document.getElementById("mb-port")?.value || "993");
    const skipVerify = document.getElementById("mb-skip-verify")?.checked || false;
    const scanHistory = document.getElementById("mb-scan-history")?.checked || false;
    const errBox = document.getElementById("connect-mb-error");

    if (errBox) {
        errBox.classList.add("hidden");
        errBox.textContent = "";
    }

    if (!emailAddress || !password) {
        showToast("Please fill in email and password.", "error");
        return;
    }

    const btn = document.getElementById("btn-submit-connect-mb");
    const spinner = document.getElementById("connect-mb-spinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");

    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/connect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email_address: emailAddress,
                password: password,
                provider: provider,
                host: host,
                port: port,
                scan_history: scanHistory
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Connection error ${res.status}`);
        }

        const data = await res.json();
        showToast(`✅ Successfully connected ${data.email_address}! Live monitoring activated.`, "success");
        document.getElementById("connect-mailbox-modal").classList.add("hidden");
        document.getElementById("connect-mailbox-form").reset();

        await loadEmails(true);
        await loadConnectedMailboxes();
    } catch (err) {
        if (errBox) {
            errBox.textContent = `❌ ${err.message}`;
            errBox.classList.remove("hidden");
        }
        showToast(`❌ Connection failed: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        spinner.classList.add("hidden");
    }
}

// Trigger Deep Historical Scan for Mailbox (Read + Unread)
window.deepScanConnectedMailbox = async function(id) {
    showToast("🔍 Performing deep scan of historical inbox emails (read + unread)...", "info");
    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/${id}/deep-scan?limit=50`, { method: "POST" });
        const data = await res.json();
        if (data.historical_emails_analyzed > 0) {
            showToast(`✅ Analyzed ${data.historical_emails_analyzed} historical emails! Threats plotted on Radar Map.`, "success");
            await loadEmails(true);
        } else {
            showToast("No new or unanalyzed emails found in inbox history.", "info");
        }
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Deep scan error: ${e.message}`, "error");
    }
};

// Trigger Manual Sync for Mailbox
window.syncConnectedMailbox = async function(id) {
    showToast("Syncing mailbox for new unread emails...", "info");
    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/${id}/sync`, { method: "POST" });
        const data = await res.json();
        if (data.new_emails_detected > 0) {
            showToast(`✅ Detected and analyzed ${data.new_emails_detected} new incoming emails!`, "success");
            await loadEmails(true);
        } else {
            showToast("No new unread emails found in mailbox.", "info");
        }
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Sync error: ${e.message}`, "error");
    }
};

// Disconnect Mailbox
window.disconnectConnectedMailbox = async function(id) {
    if (!confirm("Are you sure you want to disconnect this mailbox?")) return;
    try {
        await fetch(`${API_BASE}/api/v1/mailboxes/${id}`, { method: "DELETE" });
        showToast("Mailbox disconnected.", "info");
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Error disconnecting: ${e.message}`, "error");
    }
};

// Update Top Telemetry Stats Cards
function updateTelemetryStats(emails) {
    let criticalCount = 0;
    let suspiciousCount = 0;
    let benignCount = 0;

    emails.forEach(e => {
        const risk = (e.risk_level || "low").toLowerCase();
        if (risk === "high") criticalCount++;
        else if (risk === "medium") suspiciousCount++;
        else benignCount++;
    });

    const total = emails.length;
    document.getElementById("stat-total").textContent = total;
    document.getElementById("stat-critical").textContent = criticalCount;
    document.getElementById("stat-suspicious").textContent = suspiciousCount;
    document.getElementById("stat-benign").textContent = benignCount;

    const criticalPct = total > 0 ? Math.round((criticalCount / total) * 100) : 0;
    document.getElementById("stat-critical-pct").textContent = `${criticalPct}% of total payload`;

    document.getElementById("count-all").textContent = total;
    document.getElementById("count-high").textContent = criticalCount;
    document.getElementById("count-med").textContent = suspiciousCount;
    document.getElementById("count-low").textContent = benignCount;
}

// Render Threat Alert Stream Ticker
function renderStreamFeed(emails) {
    const streamContainer = document.getElementById("stream-feed-list");
    if (!streamContainer) return;

    if (!emails || emails.length === 0) {
        streamContainer.innerHTML = `<div class="stream-empty">No threat incidents logged yet.</div>`;
        return;
    }

    streamContainer.innerHTML = emails.slice(0, 15).map(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        const score = email.final_score !== null && email.final_score !== undefined ? email.final_score : 0;
        const country = email.country || "Unknown Origin";

        return `
            <div class="stream-item" onclick="openForensicModal(${email.id})">
                <div class="stream-top-row">
                    <span class="badge-risk-pill ${risk}">
                        ${risk === "high" ? "🔴" : risk === "medium" ? "🟡" : "🟢"} ${risk.toUpperCase()} (${score}/100)
                    </span>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">#${email.id}</span>
                </div>
                <span class="stream-subject" title="${escapeHtml(email.subject)}">${escapeHtml(email.subject)}</span>
                <div class="stream-meta">
                    <span class="stream-sender" title="${escapeHtml(email.sender)}"><i class="fa-solid fa-envelope"></i> ${escapeHtml(email.sender)}</span>
                    <span><i class="fa-solid fa-location-dot"></i> ${escapeHtml(country)}</span>
                </div>
            </div>
        `;
    }).join("");
}

// Filter and Render Feed Table
function applyFeedFilters() {
    const tbody = document.getElementById("feed-tbody");
    const searchQuery = (document.getElementById("feed-search")?.value || "").toLowerCase().trim();

    let filtered = storedEmails.filter(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        if (activeFilter !== "all" && risk !== activeFilter) return false;

        if (searchQuery) {
            const sender = (email.sender || "").toLowerCase();
            const subject = (email.subject || "").toLowerCase();
            const country = (email.country || "").toLowerCase();
            const ip = (email.ip_address || "").toLowerCase();
            return sender.includes(searchQuery) || subject.includes(searchQuery) || country.includes(searchQuery) || ip.includes(searchQuery);
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No matching threat records found.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        const score = email.final_score !== null && email.final_score !== undefined ? email.final_score : "N/A";
        const authStatus = email.header_valid ? "pass" : (email.spf_result === "fail" || email.dkim_result === "fail" ? "fail" : "none");
        const country = email.country || "Unknown";
        const ip = email.ip_address || "No IP";
        const asn = email.isp_asn || "Standard ASN";

        return `
            <tr>
                <td class="case-id-pill">#${email.id}</td>
                <td>
                    <span class="badge-risk-pill ${risk}">
                        ${risk === "high" ? "🔴" : risk === "medium" ? "🟡" : "🟢"} ${risk.toUpperCase()} (${score})
                    </span>
                </td>
                <td><span class="sender-pill" title="${escapeHtml(email.sender)}">${escapeHtml(email.sender)}</span></td>
                <td><span class="subject-cell" title="${escapeHtml(email.subject)}">${escapeHtml(email.subject)}</span></td>
                <td>
                    <div class="geo-cell">
                        <span class="geo-country">${escapeHtml(country)}</span>
                        <span class="geo-ip">${escapeHtml(ip)} • ${escapeHtml(asn.substring(0, 18))}</span>
                    </div>
                </td>
                <td style="text-align: center;">
                    <span class="auth-badge-tag ${authStatus}">${authStatus.toUpperCase()}</span>
                </td>
                <td style="text-align: center;">
                    <div style="display: flex; gap: 0.35rem; justify-content: center;">
                        <button class="btn btn-sm btn-cyber-secondary" onclick="openForensicModal(${email.id})" title="Inspect Forensics">
                            <i class="fa-solid fa-microscope"></i> View
                        </button>
                        <button class="btn btn-sm btn-cyber-primary" onclick="downloadReport(${email.id})" title="Download Official PDF Report">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join("");
}

// Update Map Pins
function updateMapMarkers(emails) {
    if (!markerLayerGroup || !radarMap) return;

    markerLayerGroup.clearLayers();
    const bounds = [];

    emails.forEach(email => {
        const lat = email.latitude;
        const lon = email.longitude;

        if (lat !== null && lon !== null && (lat !== 0 || lon !== 0)) {
            const risk = (email.risk_level || "low").toLowerCase();
            const pinClass = risk === "high" ? "pin-high" : (risk === "medium" ? "pin-medium" : "pin-low");
            const pinEmoji = risk === "high" ? "🔴" : (risk === "medium" ? "🟡" : "🟢");

            const customIcon = L.divIcon({
                className: "custom-map-pin-container",
                html: `<div class="custom-map-pin ${pinClass}">#${email.id}</div>`,
                iconSize: [24, 24],
                iconAnchor: [12, 12],
                popupAnchor: [0, -14]
            });

            const marker = L.marker([lat, lon], { icon: customIcon });

            const popupContent = `
                <div style="font-family: var(--font-sans); color: #f8fafc;">
                    <div style="font-weight: 700; font-size: 0.88rem; margin-bottom: 0.35rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.25rem; display: flex; justify-content: space-between;">
                        <span>${pinEmoji} Case #${email.id} (${risk.toUpperCase()})</span>
                        <span style="font-family: var(--font-mono); color: #a78bfa;">${escapeHtml(email.country || '')}</span>
                    </div>
                    <div style="font-size: 0.78rem; color: #94a3b8; line-height: 1.4; margin-bottom: 0.5rem;">
                        <strong>Sender:</strong> ${escapeHtml(email.sender)}<br/>
                        <strong>Subject:</strong> ${escapeHtml(email.subject)}<br/>
                        <strong>IP:</strong> <span style="font-family: var(--font-mono);">${escapeHtml(email.ip_address || 'N/A')}</span>
                    </div>
                    <div style="display: flex; gap: 0.35rem;">
                        <button style="background: rgba(139, 92, 246, 0.15); border: 1px solid rgba(139, 92, 246, 0.4); color: #a78bfa; padding: 0.25rem 0.55rem; border-radius: 0.3rem; font-size: 0.75rem; cursor: pointer;" onclick="openForensicModal(${email.id})">🔬 Inspect</button>
                        <button style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); color: #34d399; padding: 0.25rem 0.55rem; border-radius: 0.3rem; font-size: 0.75rem; cursor: pointer;" onclick="downloadReport(${email.id})">📄 PDF Report</button>
                    </div>
                </div>
            `;

            marker.bindPopup(popupContent);
            markerLayerGroup.addLayer(marker);
            bounds.push([lat, lon]);
        }
    });

    if (bounds.length > 0) {
        radarMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
    }
}

// Render Interactive Campaign Attribution Graph
async function loadAndRenderCampaignGraph() {
    const canvas = document.getElementById("campaign-graph-canvas");
    const container = document.getElementById("graph-canvas-container");
    if (!canvas || !container) return;

    try {
        const res = await fetch(`${API_BASE}/campaigns/graph`);
        if (!res.ok) throw new Error();
        graphData = await res.json();
    } catch (e) {
        return;
    }

    // Set canvas dimensions
    canvas.width = container.clientWidth || 900;
    canvas.height = container.clientHeight || 520;
    const ctx = canvas.getContext("2d");

    // Layout positions around center circle
    const nodes = graphData.nodes || [];
    const edges = graphData.edges || [];

    if (nodes.length === 0) {
        ctx.fillStyle = "#64748b";
        ctx.font = "14px Inter";
        ctx.textAlign = "center";
        ctx.fillText("No threat campaign nodes to correlate yet.", canvas.width / 2, canvas.height / 2);
        return;
    }

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 80;

    const nodePositions = {};
    nodes.forEach((n, idx) => {
        const angle = (idx / nodes.length) * 2 * Math.PI;
        nodePositions[n.id] = {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle),
            node: n
        };
    });

    // Clear
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw Edges
    ctx.lineWidth = 1.2;
    edges.forEach(e => {
        const src = nodePositions[e.source];
        const tgt = nodePositions[e.target];
        if (src && tgt) {
            ctx.strokeStyle = "rgba(148, 163, 184, 0.25)";
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.stroke();
        }
    });

    // Draw Nodes
    nodes.forEach(n => {
        const pos = nodePositions[n.id];
        if (!pos) return;

        let nodeColor = "#8b5cf6"; // Domain / standard
        let radius = 13;

        if (n.type === "email") {
            nodeColor = n.risk === "high" ? "#ef4444" : n.risk === "medium" ? "#f59e0b" : "#10b981";
            radius = 15;
        } else if (n.type === "ip") {
            nodeColor = "#a78bfa";
            radius = 11;
        }

        ctx.fillStyle = nodeColor;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, radius, 0, 2 * Math.PI);
        ctx.fill();

        ctx.strokeStyle = "#18181b";
        ctx.lineWidth = 2;
        ctx.stroke();

        // Node Label
        ctx.fillStyle = "#cbd5e1";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(n.label.substring(0, 22), pos.x, pos.y + radius + 14);
    });
}

// Update Threat Analytics Matrix
function updateAnalyticsMatrix(emails) {
    let spfPass = 0, spfFail = 0;
    let dkimPass = 0, dkimFail = 0;
    let dmarcPass = 0, dmarcFail = 0;
    const countryMap = {};

    emails.forEach(e => {
        if (e.spf_result === "pass") spfPass++;
        else if (e.spf_result === "fail" || e.spf_result === "softfail") spfFail++;

        if (e.dkim_result === "pass" || e.dkim_result === "present") dkimPass++;
        else if (e.dkim_result === "fail") dkimFail++;

        if (e.dmarc_result === "pass") dmarcPass++;
        else if (e.dmarc_result === "fail") dmarcFail++;

        const c = e.country || "Unknown";
        countryMap[c] = (countryMap[c] || 0) + 1;
    });

    // Update Counts & Meters
    document.getElementById("spf-pass-count").textContent = `${spfPass} Pass`;
    document.getElementById("spf-fail-count").textContent = `${spfFail} Fail`;
    const spfTotal = spfPass + spfFail;
    const spfPct = spfTotal > 0 ? (spfPass / spfTotal) * 100 : 50;
    document.getElementById("spf-meter").style.width = `${spfPct}%`;

    document.getElementById("dkim-pass-count").textContent = `${dkimPass} Pass`;
    document.getElementById("dkim-fail-count").textContent = `${dkimFail} Fail`;
    const dkimTotal = dkimPass + dkimFail;
    const dkimPct = dkimTotal > 0 ? (dkimPass / dkimTotal) * 100 : 50;
    document.getElementById("dkim-meter").style.width = `${dkimPct}%`;

    document.getElementById("dmarc-pass-count").textContent = `${dmarcPass} Pass`;
    document.getElementById("dmarc-fail-count").textContent = `${dmarcFail} Fail`;
    const dmarcTotal = dmarcPass + dmarcFail;
    const dmarcPct = dmarcTotal > 0 ? (dmarcPass / dmarcTotal) * 100 : 50;
    document.getElementById("dmarc-meter").style.width = `${dmarcPct}%`;

    // Top Countries List
    const sortedCountries = Object.entries(countryMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const countryContainer = document.getElementById("country-rank-list");
    if (countryContainer) {
        countryContainer.innerHTML = sortedCountries.map(([country, count], idx) => `
            <div class="country-rank-item">
                <span style="font-weight: 600;"><span style="color: var(--primary); font-family: var(--font-mono); margin-right: 0.4rem;">#${idx+1}</span> ${escapeHtml(country)}</span>
                <span style="font-family: var(--font-mono); background: rgba(255,255,255,0.06); padding: 0.15rem 0.5rem; border-radius: 0.3rem;">${count} incidents</span>
            </div>
        `).join("");
    }
}

// Handle Email Form Submission
async function handleIngestSubmit(e) {
    e.preventDefault();

    const sender = document.getElementById("sender").value.trim();
    const subject = document.getElementById("subject").value.trim();
    const rawHeaders = document.getElementById("raw-headers").value.trim() || null;
    const bodyText = document.getElementById("body-text").value.trim();

    if (!sender || !subject || !bodyText) {
        showToast("Please fill in all required fields.", "error");
        return;
    }

    const btn = document.getElementById("btn-submit-ingest");
    const spinner = document.getElementById("ingest-spinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");

    try {
        const response = await fetch(`${API_BASE}/emails`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender,
                subject,
                raw_headers: rawHeaders,
                body_text: bodyText
            })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server error ${response.status}`);
        }

        const data = await response.json();
        showToast(`✅ Case #${data.id} Ingested: ${data.risk_level.toUpperCase()} THREAT (${data.final_score}/100)`, "success");
        document.getElementById("ingest-form").reset();
        await loadEmails(true);
        openForensicModal(data.id);
    } catch (err) {
        showToast(`❌ Ingestion failed: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        spinner.classList.add("hidden");
    }
}

// Open Forensic Inspection HUD Modal
window.openForensicModal = function(id) {
    const email = storedEmails.find(e => e.id === id);
    if (!email) return;

    currentViewingId = email.id;
    document.getElementById("modal-title").textContent = `Forensic Incident Inspection`;
    document.getElementById("modal-case-subtitle").textContent = `Case #${email.id} — Ingested: ${formatTimestamp(email.received_at)}`;

    const risk = (email.risk_level || "low").toLowerCase();
    const fraudPct = Math.round((email.fraud_score || 0) * 100);
    const content = document.getElementById("modal-body-content");

    content.innerHTML = `
        <!-- Metrics Row -->
        <div class="hud-metrics-row">
            <div class="hud-stat-card">
                <div class="hud-stat-title">Aggregated Risk Level</div>
                <div class="hud-stat-val">
                    <span class="badge-risk-pill ${risk}">${risk.toUpperCase()}</span>
                </div>
                <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.35rem;">
                    Composite Score: <strong>${email.final_score || 0} / 100</strong>
                </div>
            </div>

            <div class="hud-stat-card">
                <div class="hud-stat-title">NLP Phishing Probability</div>
                <div class="hud-stat-val" style="color: ${fraudPct > 50 ? 'var(--threat-high)' : 'var(--threat-low)'};">
                    ${fraudPct}%
                </div>
                <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.35rem;">
                    Raw Coefficient: ${(email.fraud_score || 0).toFixed(2)}
                </div>
            </div>

            <div class="hud-stat-card">
                <div class="hud-stat-title">Cryptographic Authentication</div>
                <div style="display: flex; gap: 0.35rem; justify-content: center; margin-top: 0.35rem;">
                    <span class="auth-badge-tag ${email.spf_result === 'pass' ? 'pass' : email.spf_result === 'fail' ? 'fail' : 'none'}">SPF: ${email.spf_result || 'none'}</span>
                    <span class="auth-badge-tag ${email.dkim_result === 'pass' || email.dkim_result === 'present' ? 'pass' : email.dkim_result === 'fail' ? 'fail' : 'none'}">DKIM: ${email.dkim_result || 'none'}</span>
                    <span class="auth-badge-tag ${email.dmarc_result === 'pass' ? 'pass' : email.dmarc_result === 'fail' ? 'fail' : 'none'}">DMARC: ${email.dmarc_result || 'none'}</span>
                </div>
                <div style="font-size: 0.72rem; color: ${email.header_valid ? 'var(--threat-low)' : 'var(--threat-high)'}; margin-top: 0.35rem;">
                    ${email.header_valid ? '✅ Valid Signatures' : '⚠️ Unverified / Failed'}
                </div>
            </div>
        </div>

        <!-- GeoLocation Origin & ASN Box -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-location-crosshairs"></i> Relay Origin & Threat Intelligence</div>
            <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-input); padding: 0.75rem; border-radius: 0.4rem; border: 1px solid var(--border-subtle);">
                <div>
                    <strong style="color: var(--text-bright); font-size: 0.95rem;">📍 ${escapeHtml(email.country || 'Unknown')}${email.city ? ', ' + escapeHtml(email.city) : ''}</strong>
                    <span style="font-family: var(--font-mono); color: var(--primary); margin-left: 0.65rem;">[${escapeHtml(email.ip_address || 'No IP')}]</span>
                    <div style="font-size: 0.76rem; color: #a78bfa; margin-top: 0.2rem;">🏢 ${escapeHtml(email.isp_asn || 'Standard Autonomous System')}</div>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted); text-align: right;">
                    Lat: ${email.latitude || 0}, Lon: ${email.longitude || 0}<br/>
                    Actor: <strong style="color: #f8fafc;">${escapeHtml(email.threat_actor || 'Unattributed')}</strong>
                </div>
            </div>
        </div>

        <!-- Evidence Chain of Custody SHA-256 -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-fingerprint"></i> Evidence Integrity & Chain-of-Custody SHA-256 Fingerprint</div>
            <div style="font-family: var(--font-mono); font-size: 0.76rem; color: #34d399; background: var(--bg-input); padding: 0.55rem 0.75rem; border-radius: 0.35rem; border: 1px solid rgba(16, 185, 129, 0.3); word-break: break-all;">
                ${email.sha256_hash ? email.sha256_hash : 'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
            </div>
        </div>

        <!-- Envelope Info -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-envelope"></i> Envelope Metadata</div>
            <div style="display: flex; flex-direction: column; gap: 0.35rem; font-size: 0.83rem;">
                <div><span style="color: var(--text-muted); width: 80px; display: inline-block;">Sender:</span> <span style="font-family: var(--font-mono); color: #a78bfa;">${escapeHtml(email.sender)}</span></div>
                <div><span style="color: var(--text-muted); width: 80px; display: inline-block;">Subject:</span> <strong>${escapeHtml(email.subject)}</strong></div>
            </div>
        </div>

        <!-- Raw RFC 822 Headers -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-code"></i> Raw RFC 822 Network Headers</div>
            <pre class="hud-code-snippet">${email.raw_headers ? escapeHtml(email.raw_headers) : '<span style="color: var(--text-muted);">(No raw headers provided)</span>'}</pre>
        </div>

        <!-- Body Content -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-align-left"></i> Message Body Excerpt</div>
            <pre class="hud-code-snippet">${escapeHtml(email.body_text || "")}</pre>
        </div>
    `;

    document.getElementById("forensic-modal").classList.remove("hidden");
};

function closeForensicModal() {
    document.getElementById("forensic-modal").classList.add("hidden");
    currentViewingId = null;
}

// Download PDF Report Endpoint
window.downloadReport = function(id) {
    const url = `${API_BASE}/emails/${id}/report`;
    window.open(url, "_blank");
    showToast(`📄 Downloading Forensic Incident Report for Case #${id}...`, "info");
};

// Toast Notifications
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast-msg toast-${type}`;
    
    let icon = "fa-circle-info";
    if (type === "success") icon = "fa-circle-check";
    if (type === "error") icon = "fa-triangle-exclamation";

    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(20px)";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatTimestamp(ts) {
    if (!ts) return "N/A";
    try {
        const date = new Date(ts);
        if (isNaN(date.getTime())) return ts;
        return date.toLocaleString();
    } catch {
        return ts;
    }
}
