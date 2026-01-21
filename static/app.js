/**
 * Leonard's Blackbook - Frontend v3
 * "Remember Sammy Jankis"
 * 
 * Memento-themed WiFi hunting interface
 */

// ═══════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════

const Utils = {
    timestamp: () => new Date().toTimeString().split(' ')[0],

    formatTime: (iso) => {
        if (!iso) return '';
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    formatShortDate: (iso) => {
        if (!iso) return '';
        const d = new Date(iso);
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
            d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    escape: (text) => {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    signalClass: (power) => {
        const p = parseInt(power);
        if (p >= -50) return 'strong';
        if (p >= -70) return 'medium';
        return 'weak';
    },

    fingerprint: (data) => JSON.stringify(data),

    debounce: (fn, ms) => {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), ms);
        };
    },

    copyToClipboard: (text) => {
        navigator.clipboard.writeText(text).then(() => {
            Log.add(`Copied: ${text}`, 'info');
        });
    },
};

// ═══════════════════════════════════════════════════════════════
// STATE MANAGEMENT
// ═══════════════════════════════════════════════════════════════

// Virtual wordlists (mask attacks treated as wordlists)
const VIRTUAL_WORDLISTS = [
    {
        path: '__MASK_8DIGIT__',
        name: '8-digit numbers (bruteforce)',
        size_human: '100M combos',
        is_virtual: true,
    },
];

// Helper to get all wordlists (virtual + real)
const getAllWordlists = () => [...VIRTUAL_WORDLISTS, ...State.wordlists];

const State = {
    // Data from server
    networks: [],
    devices: [],
    hashes: [],
    wordlists: [],
    rules: [],

    // Data fingerprints (for change detection)
    fingerprints: {
        status: '',
        networks: '',
        hashes: '',
    },

    // Last known server state (prevents flickering)
    lastStatus: {
        scanning: false,
        attacking: false,
        cracking: false,
        vigilant: false,
        rolling_cracking: false,
    },

    // UI state
    autoScroll: true,
    sortBy: 'power',
    hashSortBy: 'time-desc',

    // Runtime flags
    isScanning: false,
    isAttacking: false,
    isCracking: false,
    isVigilant: false,

    // Selection state
    selectionMode: null,  // null | 'attack' | 'crack'
    selectedCrackHashes: new Set(),
    selectedNetworks: new Set(),
    hashWordlistPrefs: new Map(),
    hashRulePrefs: new Map(),

    // Operation state
    isScanning: false,
    isAttacking: false,
    isCracking: false,

    // SSE
    eventSource: null,

    // Polling
    statusInterval: null,
    dataInterval: null,

    // Remote / Base Station
    remoteMode: localStorage.getItem('remoteMode') || 'standalone', // standalone, base, field
    remoteUrl: localStorage.getItem('remoteUrl') || '',
};


// ═══════════════════════════════════════════════════════════════
// API CLIENT
// ═══════════════════════════════════════════════════════════════

const API = {
    async get(endpoint) {
        const res = await fetch(`/api/${endpoint}`);
        return res.json();
    },

    async post(endpoint, data = {}) {
        const res = await fetch(`/api/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        return res.json();
    },

    async uploadRemote(url, file, password, autoCrack = true) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('auto_crack', autoCrack);

        const headers = {};
        if (password) {
            headers['X-Base-Password'] = password;
        }

        // Allow self-signed certs (browser warning must be accepted first)
        const res = await fetch(`${url}/api/remote/upload`, {
            method: 'POST',
            body: formData,
            headers: headers
        });
        return res.json();
    },

    async checkRemote(url) {
        try {
            const res = await fetch(`${url}/api/remote/info`, { method: 'GET', signal: AbortSignal.timeout(3000) });
            return await res.json();
        } catch (e) {
            throw e;
        }
    },
};


// ═══════════════════════════════════════════════════════════════
// DOM REFERENCES (cached)
// ═══════════════════════════════════════════════════════════════

const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

let DOM = {};

function cacheDOM() {
    DOM = {
        statusPill: $('status-pill'),
        statusText: $('status-text'),
        interfacePill: $('interface-pill'),

        statScanned: $('stat-scanned'),
        statAttacked: $('stat-attacked'),
        statCaptured: $('stat-captured'),
        statCracked: $('stat-cracked'),
        statUptime: $('stat-uptime'),

        btnScan: $('btn-scan'),
        btnStop: $('btn-stop'),
        btnVigilance: $('btn-vigilance'),
        vigilanceLabel: $('vigilance-label'),
        btnAttack: $('btn-attack'),
        attackLabel: $('attack-label'),
        attackMenu: $('attack-menu'),
        btnCancelSelection: $('btn-cancel-selection'),

        // btnCrackQueue removed - now using only Solve Cases dropdown
        // btnCrackQueue: $('btn-crack-queue'),
        crackQueueLabel: $('crack-queue-label'),
        btnCrackAll: $('btn-crack-all'),
        crackAllLabel: $('crack-all-label'),
        crackAllMenu: $('crack-all-menu'),
        btnCancelCrackSelection: $('btn-cancel-crack-selection'),
        crackAllModal: $('crack-all-modal'),
        crackAllWordlist: $('crack-all-wordlist'),
        crackAllRule: $('crack-all-rule'),
        crackAllCount: $('crack-all-count'),
        btnExecuteCrackAll: $('btn-execute-crack-all'),
        crackAllClose: $('crack-all-close'),
        crackAllCancel: $('crack-all-cancel'),

        networksContainer: $('networks-container'),
        networkCount: $('network-count'),
        hashesContainer: $('hashes-container'),
        hashCount: $('hash-count'),
        hashSort: $('hash-sort'),
        btnDeduplicate: $('btn-deduplicate'),
        logContainer: $('log-container'),

        filterEssid: $('filter-essid'),
        filterSort: $('filter-sort'),
        filterClients: $('filter-clients'),
        filterCached: $('filter-cached'),
        powerFilter: $('power-filter'),
        powerDisplay: $('power-display'),

        logAutoscroll: $('log-autoscroll'),
        btnClearLog: $('btn-clear-log'),
        btnSettings: $('btn-settings'),
        pressureLevel: $('pressure-level'),

        settingsModal: $('settings-modal'),
        settingBand: $('setting-band'),
        settingInterface: $('setting-interface'),
        btnSaveSettings: $('btn-save-settings'),
        modalClose: $('modal-close'),
        modalCancel: $('modal-cancel'),

        // Auto-Solve
        btnAutoSolve: $('btn-auto-solve'),
        autoSolveLabel: $('auto-solve-label'),

        // Wordlist Generator (brgen)
        btnWordlist: $('btn-wordlist'),
        wordlistModal: $('wordlist-modal'),
        wordlistClose: $('wordlist-close'),
        wordlistCancel: $('wordlist-cancel'),
        wordlistCount: $('wordlist-count'),
        wordlistMode: $('wordlist-mode'),
        wordlistTemperature: $('wordlist-temperature'),
        wordlistBeam: $('wordlist-beam'),
        temperatureGroup: $('temperature-group'),
        beamGroup: $('beam-group'),
        tempDisplay: $('temp-display'),
        wordlistStatus: $('wordlist-status'),
        wordlistStatusText: $('wordlist-status-text'),
        btnWordlistGenerate: $('btn-wordlist-generate'),

        // Auto-Solve Configuration Modal
        autosolveModal: $('autosolve-modal'),
        autosolveClose: $('autosolve-close'),
        autosolveCancel: $('autosolve-cancel'),
        autosolveQueue: $('autosolve-queue'),
        btnAutosolveStart: $('btn-autosolve-start'),

        // Phantom Gate (Evil Portal)
        portalModal: $('portal-modal'),
        portalClose: $('portal-close'),
        portalCancel: $('portal-cancel'),
        portalTargetEssid: $('portal-target-essid'),
        portalTargetBssid: $('portal-target-bssid'),
        portalTargetChannel: $('portal-target-channel'),
        portalInAdapter: $('portal-in-adapter'),
        portalOutAdapter: $('portal-out-adapter'),
        portalMode: $('portal-mode'),
        portalPasswordGroup: $('portal-password-group'),
        portalPassword: $('portal-password'),
        portalCloneBssid: $('portal-clone-bssid'),
        portalStrategy: $('portal-strategy'),
        portalDeauth: $('portal-deauth'),
        portalLiveStatus: $('portal-live-status'),
        portalStatusText: $('portal-status-text'),
        portalCredsList: $('portal-creds-list'),
        btnPortalLaunch: $('btn-portal-launch'),
        portalLaunchText: $('portal-launch-text'),

        // Portal Status Banner
        portalBanner: $('portal-banner'),
        portalBannerSsid: $('portal-banner-ssid'),
        portalBannerMac: $('portal-banner-mac'),
        portalBannerChannel: $('portal-banner-channel'),
        portalBannerCaptured: $('portal-banner-captured'),
        btnPortalStop: $('btn-portal-stop'),

        // Portal Settings
        settingPortalIn: $('setting-portal-in'),
        settingPortalOut: $('setting-portal-out'),
        settingPortalCapture: $('setting-portal-capture'),
        settingPortalForced: $('setting-portal-forced'),

        // Remote / Base Station
        settingRemoteMode: $('setting-remote-mode'),
        settingRemoteUrl: $('setting-remote-url'),
        settingRemotePass: $('setting-remote-pass'),
        configBase: $('config-base'),
        configField: $('config-field'),
        basePublicIp: $('base-public-ip'),
        btnRefreshIp: $('btn-refresh-ip'),
        btnTestConnection: $('btn-test-connection'),
        connectionStatus: $('connection-status'),
        btnUploadRemote: $('btn-upload-remote'),
    };
}


// ═══════════════════════════════════════════════════════════════
// LOGGING - Field Notes (faster throughput)
// ═══════════════════════════════════════════════════════════════

const Log = {
    pendingEntries: [],
    flushTimer: null,

    add(message, level = 'info') {
        this.pendingEntries.push({ message, level, time: Utils.timestamp() });

        // Flush immediately if we have several entries or after short delay
        if (this.pendingEntries.length >= 5) {
            this.flush();
        } else if (!this.flushTimer) {
            this.flushTimer = setTimeout(() => this.flush(), 50);
        }
    },

    flush() {
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }

        const container = DOM.logContainer;
        if (!container || this.pendingEntries.length === 0) return;

        // Use DocumentFragment for batch insert
        const fragment = document.createDocumentFragment();

        for (const entry of this.pendingEntries) {
            const div = document.createElement('div');
            div.className = `log-entry log-${entry.level}`;
            div.innerHTML = `
                <span class="log-time">${entry.time}</span>
                <span class="log-msg">${Utils.escape(entry.message)}</span>
            `;
            fragment.appendChild(div);
        }

        container.appendChild(fragment);
        this.pendingEntries = [];

        // Limit entries
        while (container.children.length > 500) {
            container.firstChild.remove();
        }

        // Auto-scroll
        if (State.autoScroll) {
            container.scrollTop = container.scrollHeight;
        }
    },

    clear() {
        this.pendingEntries = [];
        if (DOM.logContainer) {
            DOM.logContainer.innerHTML = `
                <div class="log-entry log-info">
                    <span class="log-time">${Utils.timestamp()}</span>
                    <span class="log-msg">Notes burned</span>
                </div>
            `;
        }
    },
};


// ═══════════════════════════════════════════════════════════════
// RENDER FUNCTIONS (with smart diffing)
// ═══════════════════════════════════════════════════════════════

const Render = {
    shouldUpdate(key, data) {
        const fp = Utils.fingerprint(data);
        if (State.fingerprints[key] === fp) return false;
        State.fingerprints[key] = fp;
        return true;
    },

    status(data) {
        if (!data) return;

        // Update status pill
        if (DOM.statusPill && DOM.statusText) {
            const active = data.scanning || data.attacking || data.cracking || data.vigilant;
            DOM.statusPill.classList.toggle('active', active);

            let statusText = 'Dormant';
            if (data.vigilant) statusText = 'Watching...';
            else if (data.scanning) statusText = 'Remembering...';
            else if (data.attacking) statusText = 'Interrogating...';
            else if (data.cracking) statusText = 'Solving...';
            else if (data.stats?.current_operation && data.stats.current_operation !== 'Idle') {
                statusText = data.stats.current_operation;
            }
            DOM.statusText.textContent = statusText;
        }

        // Update interface
        if (DOM.interfacePill && data.monitor_interface) {
            DOM.interfacePill.textContent = data.monitor_interface;
        }

        // Update stats
        const stats = data.stats || {};
        if (DOM.statScanned) DOM.statScanned.textContent = stats.networks_scanned || 0;
        if (DOM.statAttacked) DOM.statAttacked.textContent = stats.networks_attacked || 0;
        if (DOM.statCaptured) DOM.statCaptured.textContent = stats.handshakes_captured || 0;
        if (DOM.statCracked) DOM.statCracked.textContent = stats.hashes_cracked || 0;

        this._updateUptime(stats);

        // Update local state flags
        State.lastStatus.scanning = !!data.scanning;
        State.lastStatus.attacking = !!data.attacking;
        State.lastStatus.cracking = !!data.cracking;
        State.lastStatus.vigilant = !!data.vigilant;
        State.lastStatus.rolling_cracking = !!data.rolling_cracking;

        State.isScanning = data.scanning;
        State.isAttacking = data.attacking;
        State.isCracking = data.cracking;
        State.isVigilant = data.vigilant;
        State.isRollingCracking = data.rolling_cracking;

        // Button states
        if (DOM.btnScan) DOM.btnScan.disabled = data.scanning || data.attacking || data.vigilant;
        if (DOM.btnStop) DOM.btnStop.disabled = !data.scanning && !data.attacking && !data.cracking && !data.vigilant;

        // Vigilance button active state
        if (DOM.btnVigilance) {
            DOM.btnVigilance.classList.toggle('active', !!data.vigilant);
            if (DOM.vigilanceLabel) {
                DOM.vigilanceLabel.textContent = data.vigilant ? 'Watching' : 'Vigilance';
            }
        }

        // Auto-Solve button active state
        if (DOM.btnAutoSolve) {
            DOM.btnAutoSolve.classList.toggle('active', !!data.rolling_cracking);
            if (DOM.autoSolveLabel) {
                DOM.autoSolveLabel.textContent = data.rolling_cracking ? 'Solving...' : 'Anterograde Amnesia';
            }
        }
    },

    _updateUptime(stats) {
        if (!DOM.statUptime || !stats?.scan_start_time) return;
        const start = new Date(stats.scan_start_time);
        const diff = Math.floor((Date.now() - start) / 1000);
        const mins = Math.floor(diff / 60);
        const secs = diff % 60;
        DOM.statUptime.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    },

    networks() {
        const container = DOM.networksContainer;
        if (!container) return;

        const { networks, selectedNetworks, selectionMode } = State;

        if (DOM.networkCount) {
            DOM.networkCount.textContent = networks.length;
        }

        if (networks.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">~</div>
                    <p>No suspects found</p>
                    <small>Click Remember to scan your surroundings</small>
                </div>
            `;
            return;
        }

        const html = networks.map(net => {
            const isSelected = selectedNetworks.has(net.bssid);
            const isCracked = net.status?.cracked || net.manual_cracked;
            const hasHash = net.status?.has_hash;
            const hashCount = (net.hash_ids || []).length;
            const stations = net.stations || [];

            const classes = [
                'network-item',
                net.cached ? 'cached' : '',
                isCracked ? 'cracked' : '',
                isSelected ? 'selected' : '',
            ].filter(Boolean).join(' ');

            // Build clients badge with tooltip
            let clientsBadge = '';
            if (net.has_clients && stations.length > 0) {
                const macList = stations.slice(0, 10).map(m => Utils.escape(m)).join('<br>');
                const more = stations.length > 10 ? `<br>+${stations.length - 10} more...` : '';
                const clientWord = net.clients === 1 ? 'client' : 'clients';
                clientsBadge = `
                    <span class="badge clients" title="${stations.join(', ')}">
                        ${net.clients} ${clientWord}
                        <span class="client-tooltip">${macList}${more}</span>
                    </span>
                `;
            } else if (net.has_clients) {
                const clientWord = net.clients === 1 ? 'client' : 'clients';
                clientsBadge = `<span class="badge clients">${net.clients} ${clientWord}</span>`;
            }

            return `
                <div class="${classes}" data-bssid="${net.bssid}">
                    <div class="network-row">
                        <div class="network-main">
                            <div class="network-essid">${Utils.escape(net.essid || net.bssid)}</div>
                            <div class="network-meta">
                                <span>CH ${net.channel}</span>
                                <span>${net.encryption}</span>
                                <span>${net.bssid}</span>
                            </div>
                        </div>
                        <div class="network-actions">
                            <div class="network-signal ${Utils.signalClass(net.power)}">${net.power} dBm</div>
                            <button class="network-portal-btn" data-bssid="${net.bssid}" 
                                    data-essid="${Utils.escape(net.essid || '')}" 
                                    data-channel="${net.channel}"
                                    data-password="${isCracked && net.cracked_password ? Utils.escape(net.cracked_password) : ''}"
                                    title="Phantom Gate">👻</button>
                            ${!isCracked ? `
                                <button class="network-interrogate-btn" data-bssid="${net.bssid}" title="Interrogate">
                                    !
                                </button>
                            ` : ''}
                        </div>
                    </div>
                    ${net.has_clients || hasHash || isCracked ? `
                        <div class="network-badges">
                            ${clientsBadge}
                            ${hasHash ? `<span class="badge hash">${hashCount} ${hashCount === 1 ? 'hash' : 'hashes'}</span>` : ''}
                            ${isCracked ? '<span class="badge cracked">SOLVED</span>' : ''}
                            ${net.cached ? '<span class="badge">Ghost</span>' : ''}
                        </div>
                    ` : ''}
                    ${isCracked && net.cracked_password ? `
                        <div class="network-password">[${Utils.escape(net.cracked_password)}]</div>
                    ` : ''}
                    <div class="cracked-toggle">
                        <input type="checkbox" 
                               id="cracked-${net.bssid}" 
                               data-bssid="${net.bssid}"
                               ${isCracked ? 'checked' : ''}
                               class="manual-cracked-checkbox">
                        <label for="cracked-${net.bssid}">Mark as solved</label>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = `<div class="network-list">${html}</div>`;

        // Click handlers for network items - ONLY toggle selection, don't attack
        container.querySelectorAll('.network-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Don't trigger if clicking checkbox, label, interrogate or portal button
                if (e.target.closest('.cracked-toggle') || e.target.closest('.network-interrogate-btn') || e.target.closest('.network-portal-btn')) return;
                const bssid = item.dataset.bssid;
                Handlers.networkClick(bssid);
            });
        });

        // Interrogate button handlers
        container.querySelectorAll('.network-interrogate-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                Handlers.interrogateNetwork(btn.dataset.bssid);
            });
        });

        // Phantom Gate portal button handlers
        container.querySelectorAll('.network-portal-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                Handlers.openPortalModal(
                    btn.dataset.bssid,
                    btn.dataset.essid,
                    btn.dataset.channel,
                    btn.dataset.password
                );
            });
        });

        // Manual cracked checkbox handlers
        container.querySelectorAll('.manual-cracked-checkbox').forEach(cb => {
            cb.addEventListener('change', (e) => {
                e.stopPropagation();
                Handlers.toggleManualCracked(cb.dataset.bssid, cb.checked);
            });
        });

        this.applyNetworkFilters();
    },

    applyNetworkFilters() {
        const filterText = DOM.filterEssid?.value.toLowerCase() || '';
        const clientsOnly = DOM.filterClients?.checked || false;
        const showCached = DOM.filterCached?.checked ?? true;
        const minPower = parseInt(DOM.powerFilter?.value || '-99');

        document.querySelectorAll('.network-item').forEach(item => {
            const bssid = item.dataset.bssid;
            const network = State.networks.find(n => n.bssid === bssid);
            if (!network) return;

            const essid = (network.essid || '').toLowerCase();
            const power = parseInt(network.power);
            const hasClients = network.has_clients;
            const isCached = network.cached;

            const show = (
                (!filterText || essid.includes(filterText) || bssid.toLowerCase().includes(filterText)) &&
                (!clientsOnly || hasClients) &&
                (showCached || !isCached) &&
                (power >= minPower)
            );

            item.style.display = show ? '' : 'none';
        });
    },

    hashes() {
        const container = DOM.hashesContainer;
        if (!container) return;

        const { hashes, hashWordlistPrefs, hashRulePrefs, selectionMode } = State;
        const allWordlists = getAllWordlists();  // Includes virtual wordlists

        if (DOM.hashCount) {
            DOM.hashCount.textContent = hashes.length;
        }

        if (hashes.length === 0) {
            container.innerHTML = `
                <div class="empty-state compact">
                    <p>No evidence yet</p>
                    <small>Capture handshakes first</small>
                </div>
            `;
            this.updateCrackUI();
            return;
        }

        if (State.wordlists.length === 0) {
            container.innerHTML = `
                <div class="empty-state compact">
                    <p>No wordlists found</p>
                    <small>Add files to wordlists/ folder</small>
                </div>
            `;
            this.updateCrackUI();
            return;
        }

        const html = hashes.map(hash => {
            const isCracked = hash.cracked;
            const isSelected = State.selectedCrackHashes.has(hash.path);
            const selectedWordlist = hashWordlistPrefs.get(hash.path) || allWordlists[0]?.path || '';
            const selectedRule = hashRulePrefs.get(hash.path) || '';

            // Cracking attempts (no limit)
            const attempts = hash.cracking_attempts || [];
            const attemptCount = attempts.length;

            const classes = [
                'hash-item',
                isCracked ? 'cracked' : '',
                isSelected ? 'crack-selected' : '',
            ].filter(Boolean).join(' ');

            // Use allWordlists which includes virtual wordlists automatically
            const wordlistOptions = allWordlists.map(w => `
                <option value="${Utils.escape(w.path)}" ${w.path === selectedWordlist ? 'selected' : ''}>
                    ${Utils.escape(w.name)} (${w.size_human})
                </option>
            `).join('');

            const ruleOptions = '<option value="">No rules</option>' +
                (State.rules || []).map(r => `
                    <option value="${Utils.escape(r.path)}" ${r.path === selectedRule ? 'selected' : ''}>
                        ${Utils.escape(r.name)} (${r.multiplier}x)
                    </option>
                `).join('');

            // Build meta line with datetime
            const timestamp = hash.timestamp ? Utils.formatShortDate(hash.timestamp) : '';
            let attemptsBadge = '';
            if (attemptCount > 0) {
                attemptsBadge = `<span class="hash-attempts clickable" data-hash="${Utils.escape(hash.path)}" title="Click to view attempt history">${attemptCount} attempts</span>`;
            }

            return `
                <div class="${classes}" data-hash="${Utils.escape(hash.path)}">
                    <div class="hash-row">
                        <div class="hash-info">
                            <div class="hash-essid">${Utils.escape(hash.essid || 'Unknown')}</div>
                            <div class="hash-meta">
                                <span>${Utils.escape(hash.name)}</span>
                                <span>${hash.size_human || ''}</span>
                                ${timestamp ? `<span class="hash-datetime">${timestamp}</span>` : ''}
                                ${attemptsBadge}
                            </div>
                        </div>
                        ${isCracked ? '<span class="badge cracked">Solved</span>' : ''}
                    </div>
                    ${isCracked && hash.cracked_password ? `
                        <div class="hash-password">[${Utils.escape(hash.cracked_password)}]</div>
                    ` : ''}
                    <div class="hash-actions">
                        <select class="hash-wordlist" data-hash="${Utils.escape(hash.path)}" ${isCracked ? 'disabled' : ''}>
                            ${wordlistOptions}
                        </select>
                        <select class="hash-rule" data-hash="${Utils.escape(hash.path)}" ${isCracked ? 'disabled' : ''}>
                            ${ruleOptions}
                        </select>
                        <button class="hash-btn secondary" data-action="copy" data-path="${Utils.escape(hash.path)}">Copy</button>
                        <button class="hash-btn danger" data-action="remove" data-hash="${Utils.escape(hash.path)}" title="Delete hash file">X</button>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = `<div class="hash-list">${html}</div>`;

        // Event listeners
        container.querySelectorAll('.hash-wordlist').forEach(select => {
            select.addEventListener('mousedown', e => e.stopPropagation());
            select.addEventListener('change', e => {
                e.stopPropagation();
                const hashPath = select.dataset.hash;
                State.hashWordlistPrefs.set(hashPath, select.value);
            });
        });

        container.querySelectorAll('.hash-rule').forEach(select => {
            select.addEventListener('mousedown', e => e.stopPropagation());
            select.addEventListener('change', e => {
                e.stopPropagation();
                const hashPath = select.dataset.hash;
                State.hashRulePrefs.set(hashPath, select.value);
            });
        });

        container.querySelectorAll('.hash-btn[data-action="copy"]').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                Utils.copyToClipboard(btn.dataset.path);
            });
        });

        container.querySelectorAll('.hash-btn[data-action="remove"]').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                Handlers.removeHash(btn.dataset.hash);
            });
        });

        // Click handler for crack selection mode
        container.querySelectorAll('.hash-item').forEach(item => {
            item.addEventListener('click', e => {
                if (e.target.closest('button') || e.target.closest('select') || e.target.closest('.hash-attempts')) return;

                const hashPath = item.dataset.hash;
                if (State.selectionMode === 'crack') {
                    Handlers.toggleCrackSelection(hashPath);
                }
            });
        });

        // Click handler for attempts badge - show attempt history
        container.querySelectorAll('.hash-attempts.clickable').forEach(badge => {
            badge.addEventListener('click', e => {
                e.stopPropagation();
                Handlers.showAttemptsHistory(badge.dataset.hash);
            });
        });

        this.updateCrackUI();
    },

    updateAttackUI() {
        const { selectionMode, selectedNetworks, isAttacking } = State;

        if (!DOM.btnAttack || !DOM.attackLabel) return;

        if (isAttacking) {
            DOM.btnAttack.disabled = true;
            DOM.attackLabel.textContent = 'Hunting...';
            DOM.btnAttack.classList.remove('execute-mode');
            DOM.btnCancelSelection.style.display = 'none';
            return;
        }

        DOM.btnAttack.disabled = false;

        if (selectionMode === 'attack' && selectedNetworks.size > 0) {
            DOM.btnAttack.classList.add('execute-mode');
            DOM.attackLabel.textContent = `Execute(${selectedNetworks.size})`;
            DOM.btnCancelSelection.style.display = '';
        } else {
            DOM.btnAttack.classList.remove('execute-mode');
            DOM.attackLabel.textContent = 'Interrogate';
            DOM.btnCancelSelection.style.display = 'none';
        }
    },

    updateCrackUI() {
        const { hashes, wordlists, selectedCrackHashes, isCracking, selectionMode } = State;

        if (!DOM.btnCrackAll || !DOM.crackAllLabel) return;

        const hasAssets = hashes.length > 0 && wordlists.length > 0;

        if (isCracking) {
            DOM.btnCrackAll.disabled = true;
            DOM.crackAllLabel.textContent = 'Solving...';
            DOM.btnCancelCrackSelection.style.display = 'none';
            return;
        }

        DOM.btnCrackAll.disabled = !hasAssets;

        // Show Execute(N) when in crack selection mode (even with 0 selected)
        if (selectionMode === 'crack') {
            DOM.btnCrackAll.classList.add('execute-mode');
            DOM.crackAllLabel.textContent = `Execute(${selectedCrackHashes.size})`;
            DOM.btnCancelCrackSelection.style.display = '';
        } else {
            DOM.btnCrackAll.classList.remove('execute-mode');
            DOM.crackAllLabel.textContent = 'Solve Cases';
            DOM.btnCancelCrackSelection.style.display = 'none';
        }
    },
};


// ═══════════════════════════════════════════════════════════════
// DATA LOADING (with change detection)
// ═══════════════════════════════════════════════════════════════

const Data = {
    async loadStatus() {
        try {
            const data = await API.get('status');
            Render.status(data);

            // Start polling if any active operation
            if (data.scanning || data.vigilant) {
                this.startDataPolling();
            } else if (!data.attacking && !data.cracking) {
                this.stopDataPolling();
                this.loadNetworks();
                this.loadHashes();
            }
        } catch (e) {
            console.error('Status load error:', e);
        }
    },

    async loadNetworks() {
        try {
            const data = await API.get('networks');
            const networks = (data.networks || []).map(n => ({
                ...n,
                status: n.status || {},
                hash_ids: n.hash_ids || [],
                stations: n.stations || [],
            }));

            const sort = State.sortBy;
            networks.sort((a, b) => {
                if (sort === 'power') return parseInt(b.power) - parseInt(a.power);
                if (sort === 'newest') {
                    const aTime = a.last_seen || a.first_seen || '';
                    const bTime = b.last_seen || b.first_seen || '';
                    return bTime.localeCompare(aTime);  // Newest first
                }
                return (a.essid || '').localeCompare(b.essid || '');
            });

            if (Render.shouldUpdate('networks', networks)) {
                State.networks = networks;
                Render.networks();
            }
        } catch (e) {
            console.error('Networks load error:', e);
        }
    },

    async loadHashes() {
        try {
            const data = await API.get('cracking_assets');
            const hashes = data.hashes || [];
            const wordlists = data.wordlists || [];

            // Get rules from the same endpoint
            State.rules = data.rules || [];

            // Set default wordlist preferences
            if (wordlists.length > 0) {
                const defaultWl = wordlists[0].path;
                hashes.forEach(h => {
                    if (!State.hashWordlistPrefs.has(h.path)) {
                        State.hashWordlistPrefs.set(h.path, defaultWl);
                    }
                });
            }

            // Clean up cracked from selection
            hashes.forEach(h => {
                if (h.cracked) State.selectedCrackHashes.delete(h.path);
            });

            // Sort hashes based on user preference
            const sortBy = State.hashSortBy;
            hashes.sort((a, b) => {
                if (sortBy === 'time-desc') {
                    return (b.timestamp || '').localeCompare(a.timestamp || '');
                } else if (sortBy === 'time-asc') {
                    return (a.timestamp || '').localeCompare(b.timestamp || '');
                } else if (sortBy === 'essid-asc') {
                    return (a.essid || '').localeCompare(b.essid || '');
                } else if (sortBy === 'essid-desc') {
                    return (b.essid || '').localeCompare(a.essid || '');
                }
                return 0;
            });

            if (Render.shouldUpdate('hashes', { hashes, wordlists })) {
                State.hashes = hashes;
                State.wordlists = wordlists;
                Render.hashes();
            }
        } catch (e) {
            console.error('Hashes load error:', e);
        }
    },

    async loadInterfaces() {
        try {
            const data = await API.get('interfaces');
            if (data.interfaces?.length && DOM.settingInterface) {
                DOM.settingInterface.innerHTML = '<option value="">Auto-detect</option>';
                data.interfaces.forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface;
                    opt.textContent = iface;
                    DOM.settingInterface.appendChild(opt);
                });
            }
        } catch (e) {
            console.error('Interfaces load error:', e);
        }
    },

    startStatusPolling() {
        if (!State.statusInterval) {
            State.statusInterval = setInterval(() => this.loadStatus(), 2000);
            this.loadStatus();
        }
    },

    startDataPolling() {
        if (!State.dataInterval) {
            State.dataInterval = setInterval(() => {
                this.loadNetworks();
                this.loadHashes();
            }, 3000);
        }
    },

    stopDataPolling() {
        if (State.dataInterval) {
            clearInterval(State.dataInterval);
            State.dataInterval = null;
        }
    },
};


// ═══════════════════════════════════════════════════════════════
// EVENT HANDLERS
// ═══════════════════════════════════════════════════════════════

const Handlers = {
    async startScan() {
        const res = await API.post('start_scan');
        if (res.success) {
            Log.add('Beginning reconnaissance...', 'success');
            Data.loadStatus();
            Data.startDataPolling();
        } else {
            Log.add(res.error || 'Failed to initiate scan', 'error');
        }
    },

    async stopScan() {
        const res = await API.post('stop_scan');
        if (res.success) {
            Log.add('Operations halted', 'info');
            Data.loadStatus();
        }
    },

    async toggleVigilance() {
        const wasVigilant = State.lastStatus.vigilant;
        const action = wasVigilant ? 'stop' : 'start';
        const res = await API.post('vigilance', { action });

        if (res.success) {
            if (!wasVigilant) {
                Log.add('Vigilance activated - watching the airwaves...', 'success');
                Data.startDataPolling();
            } else {
                Log.add('Vigilance deactivated', 'info');
            }
            Data.loadStatus();
        } else {
            Log.add(res.error || 'Vigilance toggle failed', 'error');
        }
    },

    async toggleAutoSolve() {
        const wasActive = State.lastStatus.rolling_cracking;

        if (wasActive) {
            // Stop immediately without modal
            const res = await API.post('rolling', { action: 'stop' });
            if (res.success) {
                Log.add('Anterograde Amnesia stopped', 'info');
                Data.loadStatus();
            } else {
                Log.add(res.error || 'Auto-Solve toggle failed', 'error');
            }
        } else {
            // Show configuration modal before starting
            this.openAutoSolveConfig();
        }
    },

    async openAutoSolveConfig() {
        // Get all wordlists including virtual (mask attacks)
        const wordlists = getAllWordlists();
        const rules = State.rules || [];

        // Build the wordlist queue UI
        const queue = DOM.autosolveQueue;
        if (!queue) return;

        queue.innerHTML = '';

        wordlists.forEach((wl, idx) => {
            const name = wl.name || wl.path?.split('/').pop() || 'Unknown';
            const item = this._createQueueItem(name, wl.path, idx, wl.word_count, queue);
            queue.appendChild(item);
        });

        // Build the rule queue UI
        const ruleQueue = $('autosolve-rule-queue');
        if (ruleQueue) {
            ruleQueue.innerHTML = '';

            // Add "(no rule)" option first
            const noRule = this._createQueueItem('(no rule)', '', 0, null, ruleQueue);
            ruleQueue.appendChild(noRule);

            // Add brazilian_wifi.rule at top if it exists
            const brazilianRule = rules.find(r => r.name?.includes('brazilian_wifi'));
            if (brazilianRule) {
                const item = this._createQueueItem(brazilianRule.name, brazilianRule.path, 1, null, ruleQueue);
                ruleQueue.appendChild(item);
            }

            // Add other rules
            rules.forEach((r, idx) => {
                if (r.name?.includes('brazilian_wifi')) return; // Already added
                const item = this._createQueueItem(r.name, r.path, idx + 2, null, ruleQueue);
                ruleQueue.appendChild(item);
            });
        }

        // Reset context status
        State.globalContextWords = '';
        const contextStatus = $('autosolve-context-status');
        if (contextStatus) contextStatus.textContent = '';

        DOM.autosolveModal?.classList.add('show');
    },

    _createQueueItem(name, path, idx, wordCount, container) {
        const item = document.createElement('div');
        item.className = 'wordlist-queue-item';
        item.draggable = true;
        item.dataset.name = name;
        item.dataset.path = path || '';

        const sizeText = wordCount ? (wordCount / 1000).toFixed(0) + 'k' : '';
        item.innerHTML = `
            <span class="wordlist-queue-drag">≡</span>
            <span class="wordlist-queue-num">${idx + 1}</span>
            <span class="wordlist-name">${name}</span>
            <span class="wordlist-size">${sizeText}</span>
        `;

        // Drag events for reordering
        item.addEventListener('dragstart', (e) => {
            item.classList.add('dragging');
            e.dataTransfer.setData('text/plain', name);
        });
        item.addEventListener('dragend', () => {
            item.classList.remove('dragging');
            this._updateQueueNumbers(container);
        });
        item.addEventListener('dragover', (e) => {
            e.preventDefault();
            const dragging = container.querySelector('.dragging');
            if (dragging && dragging !== item) {
                const rect = item.getBoundingClientRect();
                const midY = rect.top + rect.height / 2;
                if (e.clientY < midY) {
                    container.insertBefore(dragging, item);
                } else {
                    container.insertBefore(dragging, item.nextSibling);
                }
            }
        });

        return item;
    },

    _updateQueueNumbers(container) {
        const items = container?.querySelectorAll('.wordlist-queue-item');
        items?.forEach((item, idx) => {
            const num = item.querySelector('.wordlist-queue-num');
            if (num) num.textContent = idx + 1;
        });
    },

    updateQueueNumbers() {
        this._updateQueueNumbers(DOM.autosolveQueue);
        this._updateQueueNumbers($('autosolve-rule-queue'));
    },

    closeAutoSolveConfig() {
        DOM.autosolveModal?.classList.remove('show');
    },

    openAIContextModal() {
        const modal = $('ai-context-modal');
        modal?.classList.add('show');
    },

    closeAIContextModal() {
        const modal = $('ai-context-modal');
        modal?.classList.remove('show');
    },

    saveAIContext() {
        const response = $('ai-response-text')?.value || '';
        State.globalContextWords = response.trim();

        const contextStatus = $('autosolve-context-status');
        if (contextStatus) {
            const count = response.split(',').filter(w => w.trim()).length;
            contextStatus.textContent = count > 0 ? `${count} words` : '';
        }

        this.closeAIContextModal();
        Log.add(`Saved ${State.globalContextWords.split(',').length} AI context words`, 'info');
    },

    copyAIPrompt() {
        const prompt = $('ai-prompt-text')?.value || '';
        navigator.clipboard.writeText(prompt).then(() => {
            Log.add('Prompt copied to clipboard', 'info');
        });
    },

    async startAutoSolveWithOrder() {
        // Get ordered wordlist names from the queue
        const wlItems = DOM.autosolveQueue?.querySelectorAll('.wordlist-queue-item');
        const orderedWordlists = Array.from(wlItems || []).map(item => item.dataset.name);

        // Get ordered rule names from the queue
        const ruleQueue = $('autosolve-rule-queue');
        const ruleItems = ruleQueue?.querySelectorAll('.wordlist-queue-item');
        const orderedRules = Array.from(ruleItems || []).map(item => item.dataset.name);

        this.closeAutoSolveConfig();

        // Start with the ordered list
        const res = await API.post('rolling', {
            action: 'start',
            wordlist_order: orderedWordlists,
            rule_order: orderedRules,
            context_words: State.globalContextWords || '',
        });

        if (res.success) {
            Log.add('Anterograde Amnesia activated - cracking cases in background...', 'success');
            Data.loadStatus();
        } else {
            Log.add(res.error || 'Auto-Solve start failed', 'error');
        }
    },


    networkClick(bssid) {
        // Click on network row now ONLY toggles selection, doesn't attack
        const network = State.networks.find(n => n.bssid === bssid);
        if (!network) return;

        if (network.status?.cracked || network.manual_cracked) {
            Log.add(`${network.essid || bssid} case already solved`, 'info');
            return;
        }

        // Enter selection mode if not already in it
        if (State.selectionMode !== 'attack') {
            State.selectionMode = 'attack';
        }

        // Toggle selection
        if (State.selectedNetworks.has(bssid)) {
            State.selectedNetworks.delete(bssid);
        } else {
            State.selectedNetworks.add(bssid);
        }

        // Exit selection mode if nothing selected
        if (State.selectedNetworks.size === 0) {
            State.selectionMode = null;
        }

        Render.networks();
        Render.updateAttackUI();
    },

    interrogateNetwork(bssid) {
        // Attack button clicked - immediately attack this network
        const network = State.networks.find(n => n.bssid === bssid);
        if (!network) return;

        if (network.status?.cracked || network.manual_cracked) {
            Log.add(`${network.essid || bssid} case already solved`, 'info');
            return;
        }

        this.attackSingle(bssid, network);
    },

    async attackSingle(bssid, network) {
        Log.add(`Interrogating ${network.essid || bssid}...`, 'info');
        const res = await API.post('attack_network', { bssid, network });
        if (!res.success) {
            Log.add(res.error || 'Interrogation failed', 'error');
        }
    },

    async toggleManualCracked(bssid, checked) {
        try {
            const res = await API.post(`network/${bssid}/cracked`, { cracked: checked });
            if (res.success) {
                Log.add(`${bssid} ${checked ? 'marked as solved' : 'reopened'}`, 'info');
                // Update local state
                const net = State.networks.find(n => n.bssid === bssid);
                if (net) net.manual_cracked = checked;
                Render.networks();
            }
        } catch (e) {
            Log.add('Failed to update status', 'error');
        }
    },

    showAttackMenu() {
        if (State.selectionMode === 'attack' && State.selectedNetworks.size > 0) {
            this.executeBatchAttack();
        } else {
            DOM.attackMenu?.classList.toggle('show');
        }
    },

    selectAttackMode(mode) {
        DOM.attackMenu?.classList.remove('show');

        State.selectedNetworks.clear();
        State.selectionMode = 'attack';

        const visible = Array.from(document.querySelectorAll('.network-item'))
            .filter(el => el.style.display !== 'none')
            .map(el => el.dataset.bssid);

        if (mode === 'visible') {
            visible.forEach(bssid => {
                const net = State.networks.find(n => n.bssid === bssid);
                if (net && !net.status?.cracked && !net.manual_cracked) {
                    State.selectedNetworks.add(bssid);
                }
            });
        } else if (mode === 'no-hash') {
            visible.forEach(bssid => {
                const net = State.networks.find(n => n.bssid === bssid);
                if (net && !net.status?.has_hash && !net.status?.cracked && !net.manual_cracked) {
                    State.selectedNetworks.add(bssid);
                }
            });
        }

        if (State.selectedNetworks.size > 0 || mode === 'selected') {
            Render.networks();
            Render.updateAttackUI();
            Log.add(`${State.selectedNetworks.size} suspect(s) marked`, 'info');
        } else {
            State.selectionMode = null;
            Log.add('No matching suspects', 'warning');
        }
    },

    cancelSelection() {
        State.selectionMode = null;
        State.selectedNetworks.clear();
        Render.networks();
        Render.updateAttackUI();
        Log.add('Selection cleared', 'info');
    },

    async executeBatchAttack() {
        if (State.selectedNetworks.size === 0) return;

        const networks = Array.from(State.selectedNetworks)
            .map(bssid => State.networks.find(n => n.bssid === bssid))
            .filter(n => n && !n.status?.cracked && !n.manual_cracked);

        if (networks.length === 0) {
            Log.add('No eligible suspects', 'warning');
            return;
        }

        State.selectionMode = null;
        State.selectedNetworks.clear();
        Render.networks();
        Render.updateAttackUI();

        Log.add(`Batch interrogating ${networks.length} suspect(s)...`, 'info');
        const res = await API.post('batch_attack', { networks });

        if (res.success) {
            Log.add(res.message || 'Batch complete', 'success');
        } else {
            Log.add(res.error || 'Batch failed', 'error');
        }
    },

    async deduplicateHashes() {
        if (!confirm('This will merge multiple files for the same network and remove duplicate hash lines. Continue?')) return;

        Log.add('Deduplicating evidence locker...', 'info');
        try {
            const res = await API.post('deduplicate_hashes');
            if (res.success) {
                Log.add(res.message, 'success');
                await Data.loadHashes();
            } else {
                Log.add(res.error || 'Deduplication failed', 'error');
            }
        } catch (e) {
            Log.add(`Error: ${e}`, 'error');
        }
    },

    async removeHash(hashPath) {
        const hash = State.hashes.find(h => h.path === hashPath);
        if (!hash) return;

        if (!confirm(`Delete hash file "${hash.name}"?`)) return;

        try {
            const res = await API.post('delete_hash', { hash_path: hashPath });
            if (res.success) {
                Log.add(`Deleted ${hash.name}`, 'success');
                State.selectedCrackHashes.delete(hashPath);
                await Data.loadHashes();
            } else {
                Log.add(res.error || 'Failed to delete hash', 'error');
            }
        } catch (e) {
            Log.add(`Error deleting hash: ${e}`, 'error');
        }
    },

    async executeCrack() {
        if (State.selectedHashes.size === 0) return;

        const tasks = Array.from(State.selectedHashes.entries())
            .filter(([hashPath]) => {
                const hash = State.hashes.find(h => h.path === hashPath);
                return hash && !hash.cracked;  // No attempt limit
            })
            .map(([hash, wordlist]) => {
                const rule_file = State.hashRulePrefs.get(hash) || '';
                return {
                    hash,
                    wordlist,
                    rule_file: rule_file || undefined
                };
            });

        if (tasks.length === 0) {
            Log.add('No eligible evidence', 'warning');
            return;
        }

        State.selectedHashes.clear();
        Render.hashes();

        Log.add(`Solving ${tasks.length} case(s)...`, 'info');
        const res = await API.post('crack_hashes', { tasks });

        if (res.success) {
            Log.add(res.message || 'Processing complete', 'success');
            await Data.loadHashes();
        } else {
            Log.add(res.error || 'Processing failed', 'error');
        }
    },

    // ─────────────────────────────────────────────────────────
    // Solve Cases (Crack All) Handlers
    // ─────────────────────────────────────────────────────────

    showAttemptsHistory(hashPath) {
        const hash = State.hashes.find(h => h.path === hashPath);
        if (!hash) return;

        const attempts = hash.cracking_attempts || [];
        if (attempts.length === 0) {
            Log.add('No attempts recorded for this hash', 'info');
            return;
        }

        const list = attempts.map((a, i) =>
            `${i + 1}. ${a.wordlist}${a.rule ? ' + ' + a.rule : ' (no rules)'}`
        ).join('\n');

        alert(`Cracking Attempts for ${hash.essid || 'Unknown'} (${attempts.length}):\n\n${list}`);
    },

    showCrackAllMenu() {
        if (State.selectionMode === 'crack' && State.selectedCrackHashes.size > 0) {
            this.openCrackAllModal();
        } else {
            DOM.crackAllMenu?.classList.toggle('show');
        }
    },

    selectCrackMode(mode) {
        DOM.crackAllMenu?.classList.remove('show');
        State.selectedCrackHashes.clear();
        State.selectionMode = 'crack';

        if (mode === 'all') {
            // Select all unsolved hashes
            State.hashes.forEach(h => {
                if (!h.cracked) {
                    State.selectedCrackHashes.add(h.path);
                }
            });

            if (State.selectedCrackHashes.size === 0) {
                State.selectionMode = null;
                Log.add('No unsolved cases found', 'warning');
                return;
            }
        }

        // Both modes: render and show selection count
        Render.hashes();
        Render.updateCrackUI();
        const msg = mode === 'all'
            ? `${State.selectedCrackHashes.size} unsolved case(s) selected`
            : 'Click cases to select, then click Execute';
        Log.add(msg, 'info');
    },

    toggleCrackSelection(hashPath) {
        const hash = State.hashes.find(h => h.path === hashPath);
        if (!hash || hash.cracked) return;

        // No limit check - allow unlimited attempts

        if (State.selectedCrackHashes.has(hashPath)) {
            State.selectedCrackHashes.delete(hashPath);
        } else {
            State.selectedCrackHashes.add(hashPath);
        }

        if (State.selectedCrackHashes.size === 0) State.selectionMode = null;
        Render.hashes();
        Render.updateCrackUI();
    },

    cancelCrackSelection() {
        State.selectionMode = null;
        State.selectedCrackHashes.clear();
        Render.hashes();
        Render.updateCrackUI();
        Log.add('Selection cleared', 'info');
    },

    openCrackAllModal() {
        if (State.selectedCrackHashes.size === 0) {
            Log.add('No evidence selected', 'warning');
            return;
        }

        if (DOM.crackAllWordlist) {
            const allWordlists = getAllWordlists();  // Includes virtual wordlists
            DOM.crackAllWordlist.innerHTML = '<option value="">Select wordlist...</option>';
            allWordlists.forEach(w => {
                const opt = document.createElement('option');
                opt.value = w.path;
                opt.textContent = `${w.name} (${w.size_human})`;
                DOM.crackAllWordlist.appendChild(opt);
            });
            if (allWordlists.length > 0) DOM.crackAllWordlist.value = allWordlists[0].path;

            // Show/hide rule dropdown based on selection
            DOM.crackAllWordlist.onchange = () => {
                const ruleGroup = document.getElementById('crack-rule-group');
                if (ruleGroup) {
                    ruleGroup.style.display = DOM.crackAllWordlist.value.startsWith('__MASK_') ? 'none' : '';
                }
            };
        }

        if (DOM.crackAllRule) {
            DOM.crackAllRule.innerHTML = '<option value="">None</option>';
            (State.rules || []).forEach(r => {
                const opt = document.createElement('option');
                opt.value = r.path;
                opt.textContent = `${r.name} (${r.multiplier}x)`;
                DOM.crackAllRule.appendChild(opt);
            });
        }

        if (DOM.crackAllCount) DOM.crackAllCount.textContent = State.selectedCrackHashes.size;
        DOM.crackAllModal?.classList.add('show');
    },

    closeCrackAllModal() {
        DOM.crackAllModal?.classList.remove('show');
    },

    async executeCrackAll() {
        const wordlist = DOM.crackAllWordlist?.value;
        const rule = DOM.crackAllRule?.value;

        if (!wordlist) {
            Log.add('Select an attack mode', 'warning');
            return;
        }

        const isMaskAttack = wordlist.startsWith('__MASK_');

        const tasks = Array.from(State.selectedCrackHashes)
            .filter(hashPath => {
                const hash = State.hashes.find(h => h.path === hashPath);
                return hash && !hash.cracked;  // No attempt limit
            })
            .map(hashPath => {
                if (isMaskAttack) {
                    return {
                        hash: hashPath,
                        mask_type: wordlist,  // e.g., '__MASK_8DIGIT__'
                    };
                }
                return {
                    hash: hashPath,
                    wordlist: wordlist,
                    rule_file: rule || undefined
                };
            });

        if (tasks.length === 0) {
            Log.add('No eligible evidence', 'warning');
            return;
        }

        this.closeCrackAllModal();
        State.selectionMode = null;
        State.selectedCrackHashes.clear();
        Render.hashes();
        Render.updateCrackUI();

        Log.add(`Solving ${tasks.length} case(s)...`, 'info');
        const res = await API.post('crack_hashes', { tasks });

        if (res.success) {
            Log.add(res.message || 'Processing complete', 'success');
            await Data.loadHashes();
        } else {
            Log.add(res.error || 'Processing failed', 'error');
        }
    },

    async openSettings() {
        try {
            const settings = await API.get('settings');
            if (DOM.settingBand) DOM.settingBand.value = settings.band || 'abg';
            if (DOM.settingInterface && settings.interface) {
                DOM.settingInterface.value = settings.interface;
            }

            // Load portal settings
            if (DOM.settingPortalCapture) {
                DOM.settingPortalCapture.checked = settings.portal_capture_traffic !== false;
            }
            if (DOM.settingPortalForced) {
                DOM.settingPortalForced.checked = settings.portal_forced_mode === true;
            }

            // Load adapter options for portal
            await this.loadPortalAdapters(settings);
        } catch (e) { console.error('Settings load error:', e); }

        DOM.settingsModal?.classList.add('show');
    },

    async loadPortalAdapters(settings) {
        try {
            const adapters = await API.get('adapters');

            // Populate internet source dropdown
            if (DOM.settingPortalIn) {
                DOM.settingPortalIn.innerHTML = '<option value="">Select adapter...</option>';
                (adapters.internet || []).forEach(a => {
                    const opt = document.createElement('option');
                    opt.value = a.name;
                    opt.textContent = `${a.name} (${a.type}${a.has_internet ? ' ✓' : ''})`;
                    if (settings?.portal_in_adapter === a.name) opt.selected = true;
                    DOM.settingPortalIn.appendChild(opt);
                });
            }

            // Populate evil twin adapter dropdown
            if (DOM.settingPortalOut) {
                DOM.settingPortalOut.innerHTML = '<option value="">Select adapter...</option>';
                (adapters.wireless || []).forEach(a => {
                    const opt = document.createElement('option');
                    opt.value = a.name;
                    opt.textContent = `${a.name} (wireless${a.supports_ap ? ' AP✓' : ''})`;
                    if (settings?.portal_out_adapter === a.name) opt.selected = true;
                    DOM.settingPortalOut.appendChild(opt);
                });
            }
        } catch (e) {
            console.error('Failed to load adapters:', e);
        }
    },

    closeSettings() {
        DOM.settingsModal?.classList.remove('show');
    },

    async saveSettings() {
        const settings = {
            band: DOM.settingBand?.value,
            interface: DOM.settingInterface?.value,
            // Portal settings
            portal_in_adapter: DOM.settingPortalIn?.value || null,
            portal_out_adapter: DOM.settingPortalOut?.value || null,
            portal_capture_traffic: DOM.settingPortalCapture?.checked ?? true,
            portal_forced_mode: DOM.settingPortalForced?.checked ?? false,
        };

        const res = await API.post('settings', settings);
        if (res.success) {
            Log.add('Configuration saved', 'success');
            this.closeSettings();
            Data.loadNetworks();
        } else {
            Log.add(res.error || 'Failed to save', 'error');
        }
    },

    async updatePressure() {
        const level = parseInt(DOM.pressureLevel?.value || '16');
        const res = await API.post('settings', { deauth_count: level });
        if (res.success) {
            const names = { 8: 'Gentle', 16: 'Firm', 32: 'Heavy', 64: 'Brutal' };
            Log.add(`Pressure set to ${names[level] || level} (${level} packets)`, 'info');
        }
    },

    // ─────────────────────────────────────────────────────────
    // Phantom Gate (Evil Portal)
    // ─────────────────────────────────────────────────────────

    portalTarget: null,  // Current portal target {bssid, essid, channel, password}
    portalPolling: null, // Status polling interval

    async openPortalModal(bssid, essid, channel, password) {
        this.portalTarget = { bssid, essid, channel, password };

        if (DOM.portalTargetEssid) DOM.portalTargetEssid.textContent = essid || 'Unknown';
        if (DOM.portalTargetBssid) DOM.portalTargetBssid.textContent = bssid;
        if (DOM.portalTargetChannel) DOM.portalTargetChannel.textContent = channel;

        // Load adapters from API
        try {
            const adapters = await API.get('adapters');
            const settings = await API.get('settings');

            // Populate internet source dropdown
            if (DOM.portalInAdapter) {
                DOM.portalInAdapter.innerHTML = '<option value="">-- Select adapter --</option>';
                (adapters.internet || []).forEach(a => {
                    const opt = document.createElement('option');
                    opt.value = a.name;
                    opt.textContent = `${a.name} (${a.type}${a.has_internet ? ' ✓' : ''})`;
                    if (settings?.portal_in_adapter === a.name) opt.selected = true;
                    DOM.portalInAdapter.appendChild(opt);
                });
            }

            // Populate evil twin dropdown
            if (DOM.portalOutAdapter) {
                DOM.portalOutAdapter.innerHTML = '<option value="">-- Select adapter --</option>';
                (adapters.wireless || []).forEach(a => {
                    const opt = document.createElement('option');
                    opt.value = a.name;
                    opt.textContent = `${a.name} (wireless${a.supports_ap ? ' AP✓' : ''})`;
                    if (settings?.portal_out_adapter === a.name) opt.selected = true;
                    DOM.portalOutAdapter.appendChild(opt);
                });
            }

            // Set Strategy default from settings
            if (DOM.portalStrategy) {
                // Map old boolean setting to new strategy if needed
                let stratum = settings?.portal_strategy || 'karma';
                if (!settings?.portal_strategy && settings?.portal_forced_mode !== undefined) {
                    stratum = settings.portal_forced_mode ? 'karma' : 'passive';
                }
                DOM.portalStrategy.value = stratum;
            }

            // Warn if no adapters found
            if ((adapters.internet || []).length === 0) {
                Log.add('No internet adapters detected', 'warning');
            }
            if ((adapters.wireless || []).length === 0) {
                Log.add('No wireless adapters detected - plug in your adapter', 'warning');
            }
        } catch (e) {
            console.error('Failed to load adapters:', e);
            Log.add('Failed to load adapters', 'error');
        }

        // Check if portal is already running
        try {
            const status = await API.get('portal/status');
            if (status.active) {
                // Portal is running - show live status
                if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'block';
                if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Close Gate';
                if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;
                this.startPortalPolling();
            } else {
                // Portal not running - show config
                if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'none';
                if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Open Gate';
                if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;
            }
        } catch (e) {
            // Assume not running on error
            if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'none';
            if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Open Gate';
        }

        // If password is known, default to WPA2 mode
        if (password && DOM.portalMode) {
            DOM.portalMode.value = 'wpa2';
            if (DOM.portalPasswordGroup) DOM.portalPasswordGroup.style.display = 'block';
            if (DOM.portalPassword) DOM.portalPassword.value = password;
        } else {
            if (DOM.portalMode) DOM.portalMode.value = 'open';
            if (DOM.portalPasswordGroup) DOM.portalPasswordGroup.style.display = 'none';
            if (DOM.portalPassword) DOM.portalPassword.value = '';
        }

        if (DOM.portalCredsList) DOM.portalCredsList.innerHTML = '';

        DOM.portalModal?.classList.add('show');
    },

    closePortalModal() {
        // Just close the modal - don't stop the portal
        // Portal continues running in background
        DOM.portalModal?.classList.remove('show');
        // Keep polling if portal is active (for status bar indicator later)
    },

    async launchPortal() {
        if (!this.portalTarget) return;

        // Get adapter values from modal dropdowns
        const inAdapter = DOM.portalInAdapter?.value || '';
        const outAdapter = DOM.portalOutAdapter?.value || '';

        // Validate adapters are selected
        if (!inAdapter) {
            Log.add('Select an internet source adapter', 'warning');
            return;
        }
        if (!outAdapter) {
            Log.add('Select an evil twin adapter', 'warning');
            return;
        }
        if (inAdapter === outAdapter) {
            Log.add('Internet and Evil Twin adapters must be different', 'warning');
            return;
        }

        const mode = DOM.portalMode?.value || 'open';
        const password = DOM.portalPassword?.value || '';
        const cloneBssid = DOM.portalCloneBssid?.checked ?? true;
        const strategy = DOM.portalStrategy?.value || 'karma';
        const enableDeauth = DOM.portalDeauth?.checked ?? false;

        if (mode === 'wpa2' && !password) {
            Log.add('Password required for WPA2 mode', 'warning');
            return;
        }

        if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = true;
        if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Starting...';

        const res = await API.post('portal/start', {
            bssid: this.portalTarget.bssid,
            essid: this.portalTarget.essid,
            channel: this.portalTarget.channel,
            in_adapter: inAdapter,
            out_adapter: outAdapter,
            mode,
            password: mode === 'wpa2' ? password : null,
            clone_bssid: cloneBssid,
            strategy: strategy,
            deauth: enableDeauth,
        });

        if (res.success) {
            Log.add(`Phantom Gate opened for ${this.portalTarget.essid}`, 'success');
            if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'block';
            if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Close Gate';
            if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;

            // Start polling for captured credentials
            this.startPortalPolling();
        } else {
            Log.add(res.error || 'Failed to open portal', 'error');
            if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Open Gate';
            if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;
        }
    },

    async stopPortal() {
        if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = true;
        if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Closing...';
        if (DOM.btnPortalStop) DOM.btnPortalStop.disabled = true;

        const res = await API.post('portal/stop');

        if (res.success) {
            Log.add('Phantom Gate closed', 'info');
            if (this.portalPolling) {
                clearInterval(this.portalPolling);
                this.portalPolling = null;
            }
            // Hide banner
            if (DOM.portalBanner) DOM.portalBanner.style.display = 'none';
            if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'none';
            if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Open Gate';
            if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;
            if (DOM.btnPortalStop) DOM.btnPortalStop.disabled = false;
        } else {
            Log.add(res.error || 'Failed to close portal', 'error');
            if (DOM.btnPortalLaunch) DOM.btnPortalLaunch.disabled = false;
            if (DOM.btnPortalStop) DOM.btnPortalStop.disabled = false;
        }
    },

    startPortalPolling() {
        if (this.portalPolling) clearInterval(this.portalPolling);

        // Immediately show banner with known target info
        if (DOM.portalBanner && this.portalTarget) {
            DOM.portalBanner.style.display = 'flex';
            if (DOM.portalBannerSsid) DOM.portalBannerSsid.textContent = this.portalTarget.essid || '--';
            if (DOM.portalBannerChannel) DOM.portalBannerChannel.textContent = this.portalTarget.channel || '--';
        }

        this.portalPolling = setInterval(async () => {
            try {
                const status = await API.get('portal/status');

                if (!status.active) {
                    clearInterval(this.portalPolling);
                    this.portalPolling = null;
                    if (DOM.portalBanner) DOM.portalBanner.style.display = 'none';
                    if (DOM.portalLiveStatus) DOM.portalLiveStatus.style.display = 'none';
                    if (DOM.portalLaunchText) DOM.portalLaunchText.textContent = 'Open Gate';
                    return;
                }

                // Update banner with live status
                if (DOM.portalBanner) DOM.portalBanner.style.display = 'flex';
                if (DOM.portalBannerSsid) DOM.portalBannerSsid.textContent = status.target_essid || '--';
                if (DOM.portalBannerMac) DOM.portalBannerMac.textContent = status.spoofed_mac || status.target_bssid || '--';
                if (DOM.portalBannerChannel) DOM.portalBannerChannel.textContent = status.target_channel || '--';
                if (DOM.portalBannerCaptured) DOM.portalBannerCaptured.textContent = status.credentials_captured || 0;

                // Update captured credentials in modal
                if (DOM.portalCredsList && status.credentials) {
                    DOM.portalCredsList.innerHTML = status.credentials.map(c => `
                        <div class="cred-item">
                            <span class="cred-email">${Utils.escape(c.email || '?')}</span>
                            <span class="cred-pass">${Utils.escape(c.password || '?')}</span>
                            <span class="cred-time">${Utils.formatTime(c.timestamp)}</span>
                        </div>
                    `).join('') || '<div class="cred-empty">Waiting for victims...</div>';
                }

                if (DOM.portalStatusText) {
                    DOM.portalStatusText.textContent = `Portal active - ${status.credentials_captured || 0} captured`;
                }
            } catch (e) {
                console.error('Portal status poll error:', e);
            }
        }, 2000);
    },

    handlePortalModeChange() {
        const mode = DOM.portalMode?.value || 'open';
        if (DOM.portalPasswordGroup) {
            DOM.portalPasswordGroup.style.display = mode === 'wpa2' ? 'block' : 'none';
        }
    },

    // ─────────────────────────────────────────────────────────
    // Neural Fabrication (Brgen Password Generator)
    // ─────────────────────────────────────────────────────────

    openWordlistGenerator() {
        // Reset form state
        if (DOM.wordlistStatus) DOM.wordlistStatus.style.display = 'none';
        if (DOM.btnWordlistGenerate) DOM.btnWordlistGenerate.disabled = false;

        // Update mode-specific visibility
        this.updateBrgenModeUI();

        DOM.wordlistModal?.classList.add('show');
    },

    closeWordlistGenerator() {
        DOM.wordlistModal?.classList.remove('show');
    },

    updateBrgenModeUI() {
        const mode = DOM.wordlistMode?.value || 'random';
        const isOrdered = mode === 'ordered';

        // Show/hide temperature vs beam width based on mode
        if (DOM.temperatureGroup) {
            DOM.temperatureGroup.style.display = isOrdered ? 'none' : 'block';
        }
        if (DOM.beamGroup) {
            DOM.beamGroup.style.display = isOrdered ? 'block' : 'none';
        }
    },

    updateTemperatureDisplay() {
        const temp = DOM.wordlistTemperature?.value || '1.0';
        if (DOM.tempDisplay) {
            DOM.tempDisplay.textContent = temp;
        }
    },

    async generateWordlist() {
        const count = parseInt(DOM.wordlistCount?.value) || 10000;
        const mode = DOM.wordlistMode?.value || 'random';
        const temperature = parseFloat(DOM.wordlistTemperature?.value) || 1.0;
        const beamWidth = parseInt(DOM.wordlistBeam?.value) || 50;
        const ordered = mode === 'ordered';

        if (DOM.wordlistStatus) {
            DOM.wordlistStatus.style.display = 'flex';
            DOM.wordlistStatusText.textContent = ordered
                ? 'Running SOPG beam search...'
                : 'Generating passwords...';
        }
        if (DOM.btnWordlistGenerate) DOM.btnWordlistGenerate.disabled = true;

        const modeDesc = ordered ? 'SOPG ordered' : 'random';
        Log.add(`Generating ${count.toLocaleString()} passwords (${modeDesc})...`, 'info');

        try {
            const res = await API.post('wordlist/generate', {
                count,
                ordered,
                temperature,
                beam_width: beamWidth,
            });

            if (res.success) {
                Log.add(`Generated ${res.word_count?.toLocaleString() || '?'} passwords`, 'success');
                if (res.filename) {
                    Log.add(`Saved: ${res.filename}`, 'info');
                }
                this.closeWordlistGenerator();
                await Data.loadHashes();
            } else {
                Log.add(`Error: ${res.error || 'Generation failed'}`, 'error');
            }
        } catch (e) {
            Log.add(`Error: ${e.message}`, 'error');
        } finally {
            if (DOM.wordlistStatus) DOM.wordlistStatus.style.display = 'none';
            if (DOM.btnWordlistGenerate) DOM.btnWordlistGenerate.disabled = false;
        }
    },

    toggleRemoteMode() {
        const mode = DOM.settingRemoteMode.value;
        State.remoteMode = mode;
        localStorage.setItem('remoteMode', mode);

        DOM.configBase.style.display = mode === 'base' ? 'block' : 'none';
        DOM.configField.style.display = mode === 'field' ? 'block' : 'none';

        // Update UI visibility
        if (DOM.btnUploadRemote) {
            DOM.btnUploadRemote.style.display = mode === 'field' ? 'inline-flex' : 'none';
        }

        if (mode === 'base') {
            this.fetchBaseInfo();
        }
    },

    async fetchBaseInfo() {
        DOM.basePublicIp.textContent = 'Fetching...';
        try {
            const data = await API.get('remote/info');
            DOM.basePublicIp.textContent = `${data.protocol}://${data.public_ip}:${data.port}`;
        } catch (e) {
            DOM.basePublicIp.textContent = 'Error fetching IP';
        }
    },

    async testConnection() {
        const url = DOM.settingRemoteUrl.value.replace(/\/$/, '');
        const pass = DOM.settingRemotePass?.value || '';

        DOM.connectionStatus.textContent = 'Testing...';
        DOM.connectionStatus.className = 'status-text';

        if (!url) {
            DOM.connectionStatus.textContent = 'Enter URL first';
            return;
        }

        try {
            const data = await API.checkRemote(url);
            DOM.connectionStatus.textContent = `Connected! (Base IP: ${data.public_ip})`;
            DOM.connectionStatus.className = 'status-text ok';
            State.remoteUrl = url;
            localStorage.setItem('remoteUrl', url);

            if (pass) {
                State.remotePass = pass;
                localStorage.setItem('remotePass', pass);
            }
        } catch (e) {
            DOM.connectionStatus.textContent = 'Connection failed (Check SSL/URL)';
            DOM.connectionStatus.className = 'status-text err';
        }
    },

    async uploadSelectedToRemote() {
        if (State.selectedCrackHashes.size === 0) {
            alert("Select evidence to upload first.");
            return;
        }

        const url = State.remoteUrl;
        const pass = State.remotePass || localStorage.getItem('remotePass') || '';

        if (!url) {
            alert("Configure Base Station URL in Settings first.");
            DOM.settingsModal.classList.add('show');
            return;
        }

        // Warn if no password set (though maybe user disabled auth on server?)
        // if (!pass) alert("Note: No password set for Base Station.");

        let count = 0;
        const total = State.selectedCrackHashes.size;

        Log.add(`Initiating upload of ${total} files to Base Station...`);

        for (const path of State.selectedCrackHashes) {
            try {
                // Fetch content
                const res = await fetch(`/api/hash/content?path=${encodeURIComponent(path)}`);
                if (!res.ok) throw new Error("Local fetch failed");
                const blob = await res.blob();

                // Upload to Remote
                const filename = path.split('/').pop();
                const file = new File([blob], filename, { type: "text/plain" });

                await API.uploadRemote(url, file, pass);
                count++;
                Log.add(`Uploaded ${filename} successfully.`, 'success');

            } catch (e) {
                Log.add(`Failed to upload ${path}: ${e.message}`, 'error');
            }
        }

        if (count > 0) {
            alert(`Uploaded ${count}/${total} evidence files to Base Station.`);
            State.selectedCrackHashes.clear();
            Render.hashes(); // Clear selection
        }
    },

};


// ═══════════════════════════════════════════════════════════════
// SSE (Server-Sent Events)
// ═══════════════════════════════════════════════════════════════

const SSE = {
    init() {
        State.eventSource = new EventSource('/api/stream');

        State.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'log') {
                    Log.add(data.data.message, data.data.level);
                } else if (data.type === 'status') {
                    Render.status({
                        scanning: State.lastStatus.scanning,
                        attacking: State.lastStatus.attacking,
                        cracking: State.lastStatus.cracking,
                        vigilant: State.lastStatus.vigilant,
                        rolling_cracking: State.lastStatus.rolling_cracking,
                        stats: data.data,
                    });
                }
            } catch (e) { }
        };

        State.eventSource.onerror = () => {
            console.log('SSE disconnected, reconnecting...');
            setTimeout(() => this.init(), 5000);
        };
    },
};


// ═══════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    cacheDOM();

    // ─────────────────────────────────────────────────────────
    // Event Listeners
    // ─────────────────────────────────────────────────────────

    // Scan controls
    DOM.btnScan?.addEventListener('click', () => Handlers.startScan());
    DOM.btnStop?.addEventListener('click', () => Handlers.stopScan());
    DOM.btnVigilance?.addEventListener('click', () => Handlers.toggleVigilance());
    DOM.btnAutoSolve?.addEventListener('click', () => Handlers.toggleAutoSolve());

    // Attack controls
    DOM.btnAttack?.addEventListener('click', (e) => {
        e.stopPropagation();
        Handlers.showAttackMenu();
    });

    DOM.attackMenu?.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            Handlers.selectAttackMode(item.dataset.mode);
        });
    });

    DOM.btnCancelSelection?.addEventListener('click', () => Handlers.cancelSelection());

    // Close dropdown on outside click
    document.addEventListener('click', () => {
        DOM.attackMenu?.classList.remove('show');
        DOM.crackAllMenu?.classList.remove('show');
    });

    // Crack controls
    DOM.btnCrackAll?.addEventListener('click', (e) => {
        e.stopPropagation();
        Handlers.showCrackAllMenu();
    });

    DOM.crackAllMenu?.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            Handlers.selectCrackMode(item.dataset.mode);
        });
    });

    DOM.btnCancelCrackSelection?.addEventListener('click', () => Handlers.cancelCrackSelection());

    // Crack All modal
    DOM.btnExecuteCrackAll?.addEventListener('click', () => Handlers.executeCrackAll());
    DOM.crackAllClose?.addEventListener('click', () => Handlers.closeCrackAllModal());
    DOM.crackAllCancel?.addEventListener('click', () => Handlers.closeCrackAllModal());
    DOM.crackAllModal?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closeCrackAllModal();
    });

    // Filters
    const debouncedFilter = Utils.debounce(() => Render.applyNetworkFilters(), 150);

    DOM.filterEssid?.addEventListener('input', debouncedFilter);
    DOM.filterClients?.addEventListener('change', debouncedFilter);
    DOM.filterCached?.addEventListener('change', debouncedFilter);
    DOM.powerFilter?.addEventListener('input', () => {
        if (DOM.powerDisplay) DOM.powerDisplay.textContent = DOM.powerFilter.value;
        debouncedFilter();
    });

    DOM.filterSort?.addEventListener('change', () => {
        State.sortBy = DOM.filterSort.value;
        State.fingerprints.networks = '';
        Data.loadNetworks();
    });

    // Hash sort
    DOM.hashSort?.addEventListener('change', () => {
        State.hashSortBy = DOM.hashSort.value;
        State.fingerprints.hashes = '';  // Force re-render
        Data.loadHashes();
    });

    DOM.btnDeduplicate?.addEventListener('click', () => Handlers.deduplicateHashes());

    // Log controls
    DOM.logAutoscroll?.addEventListener('change', (e) => {
        State.autoScroll = e.target.checked;
    });
    DOM.btnClearLog?.addEventListener('click', () => Log.clear());

    // Settings modal
    DOM.btnSettings?.addEventListener('click', () => Handlers.openSettings());
    DOM.modalClose?.addEventListener('click', () => Handlers.closeSettings());
    DOM.modalCancel?.addEventListener('click', () => Handlers.closeSettings());
    DOM.btnSaveSettings?.addEventListener('click', () => Handlers.saveSettings());
    DOM.pressureLevel?.addEventListener('change', () => Handlers.updatePressure());

    DOM.settingsModal?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closeSettings();
    });

    // Wordlist Generator modal (brgen)
    DOM.btnWordlist?.addEventListener('click', () => Handlers.openWordlistGenerator());
    DOM.wordlistClose?.addEventListener('click', () => Handlers.closeWordlistGenerator());
    DOM.wordlistCancel?.addEventListener('click', () => Handlers.closeWordlistGenerator());
    DOM.btnWordlistGenerate?.addEventListener('click', () => Handlers.generateWordlist());

    // Mode change toggles temperature vs beam width visibility
    DOM.wordlistMode?.addEventListener('change', () => Handlers.updateBrgenModeUI());

    // Temperature slider updates display
    DOM.wordlistTemperature?.addEventListener('input', () => Handlers.updateTemperatureDisplay());

    DOM.wordlistModal?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closeWordlistGenerator();
    });

    // Auto-Solve Configuration modal
    DOM.autosolveClose?.addEventListener('click', () => Handlers.closeAutoSolveConfig());
    DOM.autosolveCancel?.addEventListener('click', () => Handlers.closeAutoSolveConfig());
    DOM.btnAutosolveStart?.addEventListener('click', () => Handlers.startAutoSolveWithOrder());
    DOM.autosolveModal?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closeAutoSolveConfig();
    });

    // AI Context button in autosolve modal
    $('btn-autosolve-ai')?.addEventListener('click', () => Handlers.openAIContextModal());

    // AI Context modal
    $('ai-context-close')?.addEventListener('click', () => Handlers.closeAIContextModal());
    $('ai-context-cancel')?.addEventListener('click', () => Handlers.closeAIContextModal());
    $('btn-ai-context-save')?.addEventListener('click', () => Handlers.saveAIContext());
    $('btn-copy-prompt')?.addEventListener('click', () => Handlers.copyAIPrompt());
    $('ai-context-modal')?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closeAIContextModal();
    });

    // Phantom Gate (Evil Portal) modal
    DOM.portalClose?.addEventListener('click', () => Handlers.closePortalModal());
    DOM.portalCancel?.addEventListener('click', () => Handlers.closePortalModal());
    DOM.btnPortalLaunch?.addEventListener('click', () => {
        // Toggle between launch and stop based on button text
        const text = DOM.portalLaunchText?.textContent || '';
        if (text.includes('Close')) {
            Handlers.stopPortal();
        } else {
            Handlers.launchPortal();
        }
    });
    DOM.portalMode?.addEventListener('change', () => Handlers.handlePortalModeChange());
    DOM.portalModal?.querySelector('.modal-backdrop')?.addEventListener('click', () => {
        Handlers.closePortalModal();
    });

    // Portal banner stop button
    DOM.btnPortalStop?.addEventListener('click', () => Handlers.stopPortal());

    // Remote / Base Station Controls
    DOM.btnUploadRemote?.addEventListener('click', () => Handlers.uploadSelectedToRemote());
    DOM.settingRemoteMode?.addEventListener('change', () => Handlers.toggleRemoteMode());
    DOM.btnRefreshIp?.addEventListener('click', () => Handlers.fetchBaseInfo());
    DOM.btnTestConnection?.addEventListener('click', () => Handlers.testConnection());

    // Initialize Remote Mode UI
    Handlers.toggleRemoteMode();

    // ─────────────────────────────────────────────────────────
    // Start
    // ─────────────────────────────────────────────────────────

    SSE.init();
    Data.startStatusPolling();
    Data.loadInterfaces();
    Data.loadNetworks();
    Data.loadHashes();

    // Check if portal is already running (e.g., page refresh)
    (async () => {
        try {
            const status = await API.get('portal/status');
            if (status.active) {
                // Restore banner
                if (DOM.portalBanner) DOM.portalBanner.style.display = 'flex';
                if (DOM.portalBannerSsid) DOM.portalBannerSsid.textContent = status.target_essid || '--';
                if (DOM.portalBannerMac) DOM.portalBannerMac.textContent = status.spoofed_mac || status.target_bssid || '--';
                if (DOM.portalBannerChannel) DOM.portalBannerChannel.textContent = status.target_channel || '--';
                if (DOM.portalBannerCaptured) DOM.portalBannerCaptured.textContent = status.credentials_captured || 0;
                Handlers.startPortalPolling();
                Log.add(`Phantom Gate active for ${status.target_essid}`, 'info');
            }
        } catch (e) {
            // Portal API not responding, ignore
        }
    })();

    Log.add('Blackbook ready. What do you remember?', 'success');
});
