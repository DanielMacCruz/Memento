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
                // Don't trigger if clicking checkbox, label, or interrogate button
                if (e.target.closest('.cracked-toggle') || e.target.closest('.network-interrogate-btn')) return;
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

            // Load available hashcat rules
            try {
                const rulesData = await API.get('wordlist/rules');
                State.rules = rulesData.rules || [];
            } catch (e) {
                console.error('Failed to load rules:', e);
                State.rules = [];
            }

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

        // Build the queue UI - all wordlists are always available
        const queue = DOM.autosolveQueue;
        if (!queue) return;

        queue.innerHTML = '';

        wordlists.forEach((wl, idx) => {
            const name = wl.name || wl.path?.split('/').pop() || 'Unknown';

            const item = document.createElement('div');
            item.className = 'wordlist-queue-item';
            item.draggable = true;
            item.dataset.name = name;
            item.dataset.path = wl.path || '';

            item.innerHTML = `
                <span class="wordlist-queue-drag">≡</span>
                <span class="wordlist-queue-num">${idx + 1}</span>
                <span class="wordlist-name">${name}</span>
                <span class="wordlist-size">${wl.word_count ? (wl.word_count / 1000).toFixed(0) + 'k' : ''}</span>
                <span class="wordlist-status pending">Pending</span>
            `;

            // Drag events for reordering
            item.addEventListener('dragstart', (e) => {
                item.classList.add('dragging');
                e.dataTransfer.setData('text/plain', name);
            });
            item.addEventListener('dragend', () => {
                item.classList.remove('dragging');
                this.updateQueueNumbers();
            });
            item.addEventListener('dragover', (e) => {
                e.preventDefault();
                const dragging = queue.querySelector('.dragging');
                if (dragging && dragging !== item) {
                    const rect = item.getBoundingClientRect();
                    const midY = rect.top + rect.height / 2;
                    if (e.clientY < midY) {
                        queue.insertBefore(dragging, item);
                    } else {
                        queue.insertBefore(dragging, item.nextSibling);
                    }
                }
            });

            queue.appendChild(item);
        });

        DOM.autosolveModal?.classList.add('show');
    },

    updateQueueNumbers() {
        const items = DOM.autosolveQueue?.querySelectorAll('.wordlist-queue-item');
        items?.forEach((item, idx) => {
            const num = item.querySelector('.wordlist-queue-num');
            if (num) num.textContent = idx + 1;
        });
    },

    closeAutoSolveConfig() {
        DOM.autosolveModal?.classList.remove('show');
    },

    async startAutoSolveWithOrder() {
        // Get ordered wordlist names from the queue
        const items = DOM.autosolveQueue?.querySelectorAll('.wordlist-queue-item:not(.completed)');
        const orderedWordlists = Array.from(items || []).map(item => ({
            name: item.dataset.name,
            path: item.dataset.path,
        }));

        this.closeAutoSolveConfig();

        // Start with the ordered list
        const res = await API.post('rolling', {
            action: 'start',
            wordlist_order: orderedWordlists.map(w => w.name),
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
            const res = await API.post(`network / ${bssid}/cracked`, { cracked: checked });
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
        } catch (e) { }

        DOM.settingsModal?.classList.add('show');
    },

    closeSettings() {
        DOM.settingsModal?.classList.remove('show');
    },

    async saveSettings() {
        const settings = {
            band: DOM.settingBand?.value,
            interface: DOM.settingInterface?.value,
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

    // ─────────────────────────────────────────────────────────
    // Start
    // ─────────────────────────────────────────────────────────

    SSE.init();
    Data.startStatusPolling();
    Data.loadInterfaces();
    Data.loadNetworks();
    Data.loadHashes();

    Log.add('Blackbook ready. What do you remember?', 'success');
});
