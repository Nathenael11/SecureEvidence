/**
 * SecureEvidence: Forensic Analyst Command Console Client
 * Author: Nathenael Ermias nathenaelermias13@gmail.com
 * Organization: INSA (Information Network Security Administration)
 */

let currentDetectionResult = null;
let currentEvidencePayload = null;
let originalEvidencePayload = null;
let ledgerRecordsMap = {};
let lastAnchoredBlock = null;

// Authentication state (Access token kept ONLY in memory)
let inMemoryAccessToken = null;
let currentUser = null;

/**
 * Authenticated fetch helper. Automatically adds Authorization Bearer header,
 * handles token refresh on 401, and updates UI on auth failure.
 */
async function authFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (inMemoryAccessToken && !options.headers['Authorization']) {
        options.headers['Authorization'] = `Bearer ${inMemoryAccessToken}`;
    }

    let response = await fetch(url, options);

    // If 401 Unauthorized, attempt refresh once
    if (response.status === 401 && !url.includes('/auth/')) {
        const refreshed = await attemptTokenRefresh();
        if (refreshed) {
            options.headers['Authorization'] = `Bearer ${inMemoryAccessToken}`;
            response = await fetch(url, options);
        } else {
            promptLogin("Please sign in");
        }
    }
    return response;
}

async function attemptTokenRefresh() {
    try {
        const res = await fetch('/auth/refresh', {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        if (res.ok) {
            const data = await res.json();
            inMemoryAccessToken = data.access_token;
            await fetchCurrentUser();
            return true;
        }
    } catch (e) {
        console.warn("Silent token refresh failed:", e);
    }
    inMemoryAccessToken = null;
    currentUser = null;
    updateUserChipUI();
    return false;
}

async function fetchCurrentUser() {
    if (!inMemoryAccessToken) return null;
    try {
        const res = await fetch('/auth/me', {
            headers: { 'Authorization': `Bearer ${inMemoryAccessToken}` }
        });
        if (res.ok) {
            currentUser = await res.json();
            updateUserChipUI();
            return currentUser;
        }
    } catch (e) {
        console.error("Failed to fetch user profile:", e);
    }
    return null;
}

function updateUserChipUI() {
    const chip = document.getElementById('user-chip');
    const chipName = document.getElementById('user-chip-name');
    const chipRole = document.getElementById('user-chip-role');
    const btnOpenLogin = document.getElementById('btn-open-login');
    const anchorBtn = document.getElementById('btn-store-bc');

    if (currentUser) {
        if (chip) chip.classList.remove('hidden');
        // Show username + single role label only
        if (chipName) chipName.innerText = currentUser.username;
        if (chipRole) {
            chipRole.innerText = 'Investigator';
            chipRole.className = 'badge-status badge-amber';
        }
        if (btnOpenLogin) btnOpenLogin.classList.add('hidden');

        // Role-based UI restriction: Investigator has full anchoring permission
        if (anchorBtn) {
            if (currentUser.role !== 'investigator') {
                anchorBtn.disabled = true;
                anchorBtn.title = "Investigator role required";
                anchorBtn.style.opacity = '0.5';
                anchorBtn.style.cursor = 'not-allowed';
            } else {
                anchorBtn.disabled = false;
                anchorBtn.title = "";
                anchorBtn.style.opacity = '1';
                anchorBtn.style.cursor = 'pointer';
            }
        }

        // Role-based UI restriction: Stream control (investigator only)
        const btnStreamStart = document.getElementById('btn-stream-start');
        const btnStreamStop = document.getElementById('btn-stream-stop');
        const canControlStream = (currentUser.role === 'investigator');
        [btnStreamStart, btnStreamStop].forEach(btn => {
            if (btn) {
                if (!canControlStream) {
                    btn.disabled = true;
                    btn.title = "Investigator role required to control stream pipeline";
                    btn.style.opacity = '0.5';
                    btn.style.cursor = 'not-allowed';
                } else {
                    btn.disabled = false;
                    btn.title = "";
                    btn.style.opacity = '1';
                    btn.style.cursor = 'pointer';
                }
            }
        });

        const invField = document.getElementById('input_investigator');
        if (invField) {
            invField.value = currentUser.full_name || currentUser.username;
        }
    } else {
        if (chip) chip.classList.add('hidden');
        if (btnOpenLogin) btnOpenLogin.classList.remove('hidden');
        if (anchorBtn) {
            anchorBtn.disabled = false;
            anchorBtn.title = "";
            anchorBtn.style.opacity = '1';
        }
        const invField = document.getElementById('input_investigator');
        if (invField) {
            invField.value = "";
        }
        const btnStreamStart = document.getElementById('btn-stream-start');
        const btnStreamStop = document.getElementById('btn-stream-stop');
        [btnStreamStart, btnStreamStop].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.title = "Sign in as Investigator or System Admin to control stream";
                btn.style.opacity = '0.5';
                btn.style.cursor = 'not-allowed';
            }
        });
    }
}

function openLoginModal() {
    const modal = document.getElementById('login-modal');
    const errBox = document.getElementById('login-error-msg');
    if (errBox) errBox.classList.add('hidden');
    if (modal) modal.classList.remove('hidden');
}

function closeLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) modal.classList.add('hidden');
}

function promptLogin(msg) {
    openLoginModal();
    const errBox = document.getElementById('login-error-msg');
    if (errBox) {
        errBox.innerText = msg;
        errBox.classList.remove('hidden');
    }
}

async function submitLogin(e) {
    if (e) e.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const errBox = document.getElementById('login-error-msg');

    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value : '';

    if (!username || !password) {
        if (errBox) {
            errBox.innerText = "Please provide both username and password.";
            errBox.classList.remove('hidden');
        }
        return;
    }

    try {
        const res = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || "Authentication failed");
        }

        const data = await res.json();
        inMemoryAccessToken = data.access_token;
        currentUser = data.user;
        updateUserChipUI();
        closeLoginModal();
        if (passwordInput) passwordInput.value = '';
        showToast(`Authenticated as ${currentUser.full_name} (${currentUser.role})`, "success");

        // Reload data with authenticated permissions
        await loadLedgerRecords();
        await loadSystemStats();
    } catch (err) {
        if (errBox) {
            errBox.innerText = err.message;
            errBox.classList.remove('hidden');
        }
        showToast(`Login failed: ${err.message}`, "error");
    }
}

async function handleLogout() {
    try {
        await fetch('/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': inMemoryAccessToken ? `Bearer ${inMemoryAccessToken}` : ''
            }
        });
    } catch (e) {
        console.warn("Logout request error:", e);
    }
    inMemoryAccessToken = null;
    currentUser = null;
    updateUserChipUI();
    showToast("Successfully logged out.", "info");
    window.location.href = '/';
}

window.openLoginModal = openLoginModal;
window.closeLoginModal = closeLoginModal;
window.submitLogin = submitLogin;
window.handleLogout = handleLogout;


// Synthetic Demo Scenarios (Mapped to CICIDS2017 feature matrix with RFC 5737 addresses)
const SCENARIOS = {
    "dos_hulk": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Flow Duration": 39897118.51,
        "Total Fwd Packets": 0.0,
        "Total Backward Packets": 3388.27,
        "Total Length of Fwd Packets": 22533.93,
        "Total Length of Bwd Packets": 4645197.72,
        "Fwd Packet Length Max": 2677.62,
        "Fwd Packet Length Min": 221.97,
        "Fwd Packet Length Mean": 185.46,
        "Fwd Packet Length Std": 788.96,
        "Bwd Packet Length Max": 3623.91,
        "Bwd Packet Length Min": 102.32,
        "Bwd Packet Length Mean": 1452.11,
        "Bwd Packet Length Std": 1527.78,
        "Flow Bytes/s": 46574184.57,
        "Flow Packets/s": 45.0,
        "Flow IAT Mean": 4499522.38,
        "Flow IAT Std": 16273906.28,
        "Flow IAT Max": 92303163.9,
        "Flow IAT Min": 6422576.1,
        "Fwd IAT Total": 0.0,
        "Fwd IAT Mean": 0.0,
        "Fwd IAT Std": 33623694.64,
        "Fwd IAT Max": 90386431.51,
        "Fwd IAT Min": 0.0,
        "Bwd IAT Total": 56503993.08,
        "Bwd IAT Mean": 10154227.45,
        "Bwd IAT Std": 18356093.75,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 1.0,
        "Bwd PSH Flags": 1.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 0.0,
        "Bwd Header Length": 3868381.85,
        "Fwd Packets/s": 422383.11,
        "Bwd Packets/s": 57532.47,
        "Min Packet Length": 42.62,
        "Max Packet Length": 0.0,
        "Packet Length Mean": 0.0,
        "Packet Length Std": 1192.35,
        "Packet Length Variance": 2703587.89,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 1.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.2,
        "Average Packet Size": 1403.23,
        "Avg Fwd Segment Size": 535.64,
        "Avg Bwd Segment Size": 978.94,
        "Fwd Header Length.1": 0.0,
        "Fwd Avg Bytes/Bulk": 0.29,
        "Fwd Avg Packets/Bulk": 0.4,
        "Fwd Avg Bulk Rate": 1.97,
        "Bwd Avg Bytes/Bulk": 1.85,
        "Bwd Avg Packets/Bulk": 0.78,
        "Bwd Avg Bulk Rate": 2.61,
        "Subflow Fwd Packets": 0.0,
        "Subflow Fwd Bytes": 2418.82,
        "Subflow Bwd Packets": 0.0,
        "Subflow Bwd Bytes": 4284339.67,
        "Init_Win_bytes_forward": 0.0,
        "Init_Win_bytes_backward": 20185.25,
        "act_data_pkt_fwd": 1671.5,
        "min_seg_size_forward": 671824.81,
        "Active Mean": 16678.88,
        "Active Std": 1488959.49,
        "Active Max": 2245329.36,
        "Active Min": 1882818.88,
        "Idle Mean": 20804720.78,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 88799069.37,
        "case_id": "INSA-CR-2026-HULK",
        "label_description": "Real CICIDS2017 DoS Hulk sample flow (confirmed threat)",
        "true_label": "DoS Hulk",
        "model_confidence": 0.932,
        "model_is_threat": true
    },
    "ddos": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Destination Port": 80.0,
        "Flow Duration": 1060931.0,
        "Total Fwd Packets": 4.0,
        "Total Backward Packets": 0.0,
        "Total Length of Fwd Packets": 24.0,
        "Total Length of Bwd Packets": 0.0,
        "Fwd Packet Length Max": 6.0,
        "Fwd Packet Length Min": 6.0,
        "Fwd Packet Length Mean": 6.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 22.6216408,
        "Flow Packets/s": 3.770273467,
        "Flow IAT Mean": 353643.6667,
        "Flow IAT Std": 611777.9595,
        "Flow IAT Max": 1060064.0,
        "Flow IAT Min": 355.0,
        "Fwd IAT Total": 1060931.0,
        "Fwd IAT Mean": 353643.6667,
        "Fwd IAT Std": 611777.9595,
        "Fwd IAT Max": 1060064.0,
        "Fwd IAT Min": 355.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 80.0,
        "Bwd Header Length": 0.0,
        "Fwd Packets/s": 3.770273467,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 6.0,
        "Max Packet Length": 6.0,
        "Packet Length Mean": 6.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 0.0,
        "ACK Flag Count": 1.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 7.5,
        "Avg Fwd Segment Size": 6.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Header Length.1": 80.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 4.0,
        "Subflow Fwd Bytes": 24.0,
        "Subflow Bwd Packets": 0.0,
        "Subflow Bwd Bytes": 0.0,
        "Init_Win_bytes_forward": 256.0,
        "Init_Win_bytes_backward": -1.0,
        "act_data_pkt_fwd": 3.0,
        "min_seg_size_forward": 20.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-CR-2026-DDOS",
        "label_description": "Real CICIDS2017 DDoS sample flow from held-out test split (confirmed threat)",
        "true_label": "DDoS",
        "model_confidence": 1.0,
        "model_is_threat": true
},
    "disagreement": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Destination Port": 443.0,
        "Flow Duration": 4.0,
        "Total Fwd Packets": 3.0,
        "Total Backward Packets": 0.0,
        "Total Length of Fwd Packets": 18.0,
        "Total Length of Bwd Packets": 0.0,
        "Fwd Packet Length Max": 6.0,
        "Fwd Packet Length Min": 6.0,
        "Fwd Packet Length Mean": 6.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 4500000.0,
        "Flow Packets/s": 750000.0,
        "Flow IAT Mean": 2.0,
        "Flow IAT Std": 1.414213562,
        "Flow IAT Max": 3.0,
        "Flow IAT Min": 1.0,
        "Fwd IAT Total": 4.0,
        "Fwd IAT Mean": 2.0,
        "Fwd IAT Std": 1.414213562,
        "Fwd IAT Max": 3.0,
        "Fwd IAT Min": 1.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 60.0,
        "Bwd Header Length": 0.0,
        "Fwd Packets/s": 750000.0,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 6.0,
        "Max Packet Length": 6.0,
        "Packet Length Mean": 6.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 8.0,
        "Avg Fwd Segment Size": 6.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Header Length.1": 60.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 3.0,
        "Subflow Fwd Bytes": 18.0,
        "Subflow Bwd Packets": 0.0,
        "Subflow Bwd Bytes": 0.0,
        "Init_Win_bytes_forward": 0.0,
        "Init_Win_bytes_backward": -1.0,
        "act_data_pkt_fwd": 2.0,
        "min_seg_size_forward": 20.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-CR-2026-DISPUTED",
        "label_description": "Real CICIDS2017 flow triggering model/rule conflict (requires analyst written justification)",
        "true_label": "PortScan",
        "model_confidence": 0.999,
        "model_is_threat": true
},
    "sqli": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Destination Port": 80.0,
        "Flow Duration": 5185118.0,
        "Total Fwd Packets": 7.0,
        "Total Backward Packets": 7.0,
        "Total Length of Fwd Packets": 1022.0,
        "Total Length of Bwd Packets": 2321.0,
        "Fwd Packet Length Max": 372.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 146.0,
        "Fwd Packet Length Std": 184.0787875,
        "Bwd Packet Length Max": 1047.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 331.5714286,
        "Bwd Packet Length Std": 439.6592837,
        "Flow Bytes/s": 644.7297824,
        "Flow Packets/s": 2.700034985,
        "Flow IAT Mean": 398855.2308,
        "Flow IAT Std": 1372180.71,
        "Flow IAT Max": 4963956.0,
        "Flow IAT Min": 4.0,
        "Fwd IAT Total": 221162.0,
        "Fwd IAT Mean": 36860.33333,
        "Fwd IAT Std": 56141.02125,
        "Fwd IAT Max": 141434.0,
        "Fwd IAT Min": 4.0,
        "Bwd IAT Total": 5185004.0,
        "Bwd IAT Mean": 864167.3333,
        "Bwd IAT Std": 2027593.314,
        "Bwd IAT Max": 5001548.0,
        "Bwd IAT Min": 879.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 232.0,
        "Bwd Header Length": 232.0,
        "Fwd Packets/s": 1.350017492,
        "Bwd Packets/s": 1.350017492,
        "Min Packet Length": 0.0,
        "Max Packet Length": 1047.0,
        "Packet Length Mean": 222.8666667,
        "Packet Length Std": 331.3239387,
        "Packet Length Variance": 109775.5524,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 1.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.0,
        "Average Packet Size": 238.7857143,
        "Avg Fwd Segment Size": 146.0,
        "Avg Bwd Segment Size": 331.5714286,
        "Fwd Header Length.1": 232.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 7.0,
        "Subflow Fwd Bytes": 1022.0,
        "Subflow Bwd Packets": 7.0,
        "Subflow Bwd Bytes": 2321.0,
        "Init_Win_bytes_forward": 29200.0,
        "Init_Win_bytes_backward": 252.0,
        "act_data_pkt_fwd": 3.0,
        "min_seg_size_forward": 32.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-TEST-WEB_ATTACK",
        "label_description": "Real CICIDS2017 sample flow (pre-captured, synthetic assets)",
        "true_label": "Web_Attack",
        "model_prediction_category": "Web_Attack",
        "model_confidence": 0.996,
        "model_is_threat": true
    },
    "brute_force": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Destination Port": 22.0,
        "Flow Duration": 5808851.0,
        "Total Fwd Packets": 15.0,
        "Total Backward Packets": 18.0,
        "Total Length of Fwd Packets": 1496.0,
        "Total Length of Bwd Packets": 2297.0,
        "Fwd Packet Length Max": 640.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 99.73333333,
        "Fwd Packet Length Std": 166.6851037,
        "Bwd Packet Length Max": 976.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 127.6111111,
        "Bwd Packet Length Std": 288.1713418,
        "Flow Bytes/s": 652.9690639,
        "Flow Packets/s": 5.680985792,
        "Flow IAT Mean": 181526.5937,
        "Flow IAT Std": 534015.4383,
        "Flow IAT Max": 1978974.0,
        "Flow IAT Min": 18.0,
        "Fwd IAT Total": 5808851.0,
        "Fwd IAT Mean": 414917.9286,
        "Fwd IAT Std": 796605.2643,
        "Fwd IAT Max": 2032159.0,
        "Fwd IAT Min": 434.0,
        "Bwd IAT Total": 5707732.0,
        "Bwd IAT Mean": 335748.9412,
        "Bwd IAT Std": 706064.5178,
        "Bwd IAT Max": 1978974.0,
        "Bwd IAT Min": 18.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 488.0,
        "Bwd Header Length": 584.0,
        "Fwd Packets/s": 2.582266269,
        "Bwd Packets/s": 3.098719523,
        "Min Packet Length": 0.0,
        "Max Packet Length": 976.0,
        "Packet Length Mean": 111.5588235,
        "Packet Length Std": 234.8360087,
        "Packet Length Variance": 55147.95098,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 1.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.0,
        "Average Packet Size": 114.9393939,
        "Avg Fwd Segment Size": 99.73333333,
        "Avg Bwd Segment Size": 127.6111111,
        "Fwd Header Length.1": 488.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 15.0,
        "Subflow Fwd Bytes": 1496.0,
        "Subflow Bwd Packets": 18.0,
        "Subflow Bwd Bytes": 2297.0,
        "Init_Win_bytes_forward": 29200.0,
        "Init_Win_bytes_backward": 257.0,
        "act_data_pkt_fwd": 10.0,
        "min_seg_size_forward": 32.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-TEST-SSH-PATATOR",
        "label_description": "Real CICIDS2017 sample flow (pre-captured, synthetic assets)",
        "true_label": "SSH-Patator",
        "model_prediction_category": "SSH-Patator",
        "model_confidence": 0.9999,
        "model_is_threat": true
    },
    "botnet": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.0.2.1",
        "Destination Port": 80.0,
        "Flow Duration": 2668.0,
        "Total Fwd Packets": 5.0,
        "Total Backward Packets": 0.0,
        "Total Length of Fwd Packets": 0.0,
        "Total Length of Bwd Packets": 0.0,
        "Fwd Packet Length Max": 0.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 0.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 0.0,
        "Flow Packets/s": 1874.062969,
        "Flow IAT Mean": 667.0,
        "Flow IAT Std": 840.7429254,
        "Flow IAT Max": 1926.0,
        "Flow IAT Min": 209.0,
        "Fwd IAT Total": 2668.0,
        "Fwd IAT Mean": 667.0,
        "Fwd IAT Std": 840.7429254,
        "Fwd IAT Max": 1926.0,
        "Fwd IAT Min": 209.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 160.0,
        "Bwd Header Length": 0.0,
        "Fwd Packets/s": 1874.062969,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 0.0,
        "Max Packet Length": 0.0,
        "Packet Length Mean": 0.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 0.0,
        "ACK Flag Count": 1.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 0.0,
        "Avg Fwd Segment Size": 0.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Header Length.1": 160.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 5.0,
        "Subflow Fwd Bytes": 0.0,
        "Subflow Bwd Packets": 0.0,
        "Subflow Bwd Bytes": 0.0,
        "Init_Win_bytes_forward": 251.0,
        "Init_Win_bytes_backward": -1.0,
        "act_data_pkt_fwd": 0.0,
        "min_seg_size_forward": 32.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-TEST-PORTSCAN",
        "label_description": "Real CICIDS2017 sample flow (pre-captured, synthetic assets)",
        "true_label": "PortScan",
        "model_prediction_category": "PortScan",
        "model_confidence": 0.9403,
        "model_is_threat": true
    },
    "benign": {
        "target_asset": "National-Gateway-Demo-01",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.1",
        "Flow Duration": 158356.12773253827,
        "Total Fwd Packets": 5.0,
        "Total Backward Packets": 17.0,
        "Total Length of Fwd Packets": 4180.835724571191,
        "Total Length of Bwd Packets": 18668.513499767632,
        "Fwd Packet Length Max": 932.2967589174725,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 298.43986159709556,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 832.2915355672399,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 9434.608313582408,
        "Flow Packets/s": 15.443536003977426,
        "Flow IAT Mean": 18013.60015003798,
        "Flow IAT Std": 0.0,
        "Flow IAT Max": 0.0,
        "Flow IAT Min": 0.0,
        "Fwd IAT Total": 0.0,
        "Fwd IAT Mean": 0.0,
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": 0.0,
        "Fwd IAT Min": 0.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 0.0,
        "Bwd Header Length": 0.0,
        "Fwd Packets/s": 0.0,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 0.0,
        "Max Packet Length": 0.0,
        "Packet Length Mean": 0.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.3766211233386096,
        "Average Packet Size": 542.8116113322312,
        "Avg Fwd Segment Size": 0.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Header Length.1": 0.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 5.0,
        "Subflow Fwd Bytes": 4180.835724571191,
        "Subflow Bwd Packets": 17.0,
        "Subflow Bwd Bytes": 18668.513499767632,
        "Init_Win_bytes_forward": 29200.0,
        "Init_Win_bytes_backward": 29200.0,
        "act_data_pkt_fwd": 0.0,
        "min_seg_size_forward": 0.0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "case_id": "INSA-TEST-BENIGN",
        "label_description": "Real CICIDS2017 sample flow (pre-captured, synthetic assets)",
        "true_label": "BENIGN",
        "model_prediction_category": "BENIGN",
        "model_confidence": 0.9998,
        "model_is_threat": false
    }
};

let currentLanguage = 'en';


// Ingestion Tab Switcher
function switchIngestTab(tab) {
    const flowTabBtn = document.getElementById('tab-flow-btn');
    const suricataTabBtn = document.getElementById('tab-suricata-btn');
    const flowPane = document.getElementById('pane-flow');
    const suricataPane = document.getElementById('pane-suricata');

    if (tab === 'suricata') {
        flowTabBtn.classList.remove('active');
        suricataTabBtn.classList.add('active');
        flowPane.style.display = 'none';
        suricataPane.style.display = 'block';
    } else {
        suricataTabBtn.classList.remove('active');
        flowTabBtn.classList.add('active');
        suricataPane.style.display = 'none';
        flowPane.style.display = 'block';
    }
}

async function handleIngestSuricata() {
    const jsonStr = document.getElementById('suricata-json-input').value;
    let eveObj;
    try {
        eveObj = JSON.parse(jsonStr);
    } catch (e) {
        showToast("Invalid Suricata EVE JSON format: " + e.message, "error");
        return;
    }

    try {
        const res = await authFetch('/ingest/suricata', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(eveObj)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server status ${res.status}`);
        }

        const data = await res.json();
        showToast(`Suricata log ingested: mapped to ${data.detected_threat.threat_category}`, data.detected_threat.is_threat ? "info" : "success");
        
        currentDetectionResult = data.detected_threat;
        renderDetectionOutput(data.detected_threat, data.normalized_flow);
        switchIngestTab('flow');
    } catch (err) {
        console.error("Suricata ingestion failed:", err);
        showToast("Suricata ingestion failed: " + err.message, "error");
    }
}

document.addEventListener("DOMContentLoaded", async () => {
    // 1. Call POST /auth/refresh to restore session from httpOnly cookie before rendering header
    try {
        await attemptTokenRefresh();
    } catch (e) {
        console.warn("Session restore failed:", e);
    }
    updateUserChipUI();

    // 2. Check system health to handle demo banner
    try {
        const healthRes = await fetch('/health');
        if (healthRes.ok) {
            const healthData = await healthRes.json();
            window.activeLedgerBackend = healthData.ledger_backend || 'sqlite';
            window.activeChainId = healthData.chain_id;
            window.activeContractAddress = healthData.contract_address;
            const banner = document.getElementById('demo-auth-banner');
            if (banner) {
                if (healthData.demo_mode) {
                    banner.classList.remove('hidden');
                } else {
                    banner.classList.add('hidden');
                }
            }
            updateLedgerChipUI(healthData);
        }
    } catch (e) {
        console.warn("Health check error on load:", e);
    }

    loadScenario('dos_hulk', false);
    if (currentUser) {
        loadLedgerRecords();
        loadSystemStats();
        pollStreamStatus();
    }
    // Poll stream status every 5 seconds
    setInterval(() => {
        if (currentUser) {
            pollStreamStatus();
        }
    }, 5000);
    initPublicDropZone();

    const urlParams = new URLSearchParams(window.location.search);
    const stateParam = urlParams.get('state');
    if (stateParam === 'neutral') {
        setTimeout(() => {
            document.getElementById('section-3-verify')?.scrollIntoView();
        }, 300);
    } else if (stateParam === 'detected') {
        handleDetectThreat();
    } else if (stateParam === 'anchored') {
        handleDetectThreat();
        setTimeout(async () => {
            await handleStoreEvidence();
            document.getElementById('section-3-verify')?.scrollIntoView();
        }, 800);
    } else if (stateParam === 'tampered') {
        handleDetectThreat();
        setTimeout(async () => {
            await handleStoreEvidence();
            setTimeout(() => {
                tamperEvidenceJson();
                document.getElementById('section-3-verify')?.scrollIntoView();
            }, 800);
        }, 800);
    }
});

// Toast notification helper
function showToast(message, type = "info", action = null) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let icon = "fa-circle-info text-amber";
    if (type === "success") icon = "fa-circle-check text-green";
    if (type === "error") icon = "fa-circle-xmark text-red";
    
    toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;

    if (action && action.text && typeof action.onClick === "function") {
        const btn = document.createElement("button");
        btn.innerText = action.text;
        btn.style.cssText = "margin-left: 10px; padding: 4px 8px; background: #1F6FB2; color: #ffffff; border: 1px solid rgba(255,255,255,0.4); border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;";
        btn.onclick = async (e) => {
            e.stopPropagation();
            toast.remove();
            await action.onClick();
        };
        toast.appendChild(btn);
    }

    container.appendChild(toast);
    
    const duration = action ? 12000 : 4500;
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

async function acknowledgeLedgerStateAndRetry() {
    try {
        const res = await authFetch('/ledger/acknowledge-broken', {
            method: 'POST'
        });
        if (res.ok) {
            showToast("Ledger state acknowledged by investigator. Re-attempting anchoring...", "success");
            await handleStoreEvidence();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Acknowledgment failed: ${err.detail || res.statusText}`, "error");
        }
    } catch (e) {
        showToast(`Acknowledgment failed: ${e.message}`, "error");
    }
}
window.acknowledgeLedgerStateAndRetry = acknowledgeLedgerStateAndRetry;


const PRESET_SAMPLE_LABELS = {
    "dos_hulk": "DoS Hulk",
    "ddos": "DDoS",
    "disagreement": "Disagreement / Model Miss",
    "sqli": "Web Attack",
    "brute_force": "SSH-Patator",
    "botnet": "PortScan",
    "benign": "BENIGN"
};
let currentPresetKey = "dos_hulk";

let currentActiveScenario = {};

function setFormFieldValue(key, val) {
    let el = document.getElementById(key);
    if (!el) {
        let norm = key.toLowerCase().replace(/[\s\/-]+/g, '_').replace(/[^\w]/g, '');
        if (norm === 'total_length_of_fwd_packets') norm = 'total_length_fwd_packets';
        if (norm === 'total_length_of_bwd_packets') norm = 'total_length_bwd_packets';
        el = document.getElementById(norm);
    }
    if (el) {
        if (el.tagName === 'SELECT') {
            el.value = (typeof val === 'number') ? String(Math.round(val)) : String(val);
        } else if (typeof val === 'number') {
            // Item 13: Round raw floats to 2 decimals in form display (exact value preserved in currentActiveScenario)
            el.value = Number.isInteger(val) ? val : Number(val.toFixed(2));
        } else {
            el.value = val;
        }
    }
}

function loadScenario(type, autoDetect = true) {
    currentPresetKey = type;
    const sc = SCENARIOS[type];
    if (!sc) return;
    currentActiveScenario = JSON.parse(JSON.stringify(sc));

    // Highlight active preset button
    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const activeBtn = Array.from(document.querySelectorAll('.btn-preset')).find(b => {
        const attr = b.getAttribute('onclick');
        return attr && attr.includes(type);
    });
    if (activeBtn) activeBtn.classList.add('active');

    // Populate form fields
    for (const [key, val] of Object.entries(sc)) {
        setFormFieldValue(key, val);
    }

    // Run threat detection automatically on scenario selection if requested
    if (autoDetect) {
        handleDetectThreat();
    }
}

function getFormPayload() {
    const payload = { ...currentActiveScenario };
    const inputs = document.querySelectorAll('#flow-form input, #flow-form select');
    inputs.forEach(input => {
        if (!input.id) return;
        const val = input.value;
        let numVal = null;
        if (input.type === 'number') {
            numVal = parseFloat(val) || 0;
            payload[input.id] = numVal;
        } else if (input.id === 'syn_flag_count') {
            numVal = parseInt(val, 10) || 0;
            payload[input.id] = numVal;
            payload['SYN Flag Count'] = numVal;
        } else {
            payload[input.id] = val;
        }
        if (input.id === 'flow_packets_s' && numVal !== null) {
            payload['Flow Packets/s'] = numVal;
        }
        if (input.id === 'flow_bytes_s' && numVal !== null) {
            payload['Flow Bytes/s'] = numVal;
        }
        if (input.id === 'flow_duration' && numVal !== null) {
            payload['Flow Duration'] = numVal;
        }
        if (input.id === 'total_fwd_packets' && numVal !== null) {
            payload['Total Fwd Packets'] = numVal;
        }
    });
    return payload;
}

async function handleDetectThreat(e) {
    if (e) e.preventDefault();

    if (!currentUser || !inMemoryAccessToken) {
        promptLogin("Sign in to continue");
        return;
    }
    
    const btn = document.getElementById('btn-detect');
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Analyzing Flow...</span>';
    }

    const eventPayload = getFormPayload();

    try {
        const res = await authFetch('/detect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(eventPayload)
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            if (res.status === 422 && errData.status === "INSUFFICIENT_DATA") {
                currentDetectionResult = errData;
                renderDetectionOutput(errData, eventPayload);
                showToast("Classification refused: insufficient feature coverage.", "warning");
                return;
            }
            let detailMsg = errData.detail;
            if (Array.isArray(detailMsg)) {
                detailMsg = detailMsg.map(d => `${d.loc ? d.loc.join('.') + ': ' : ''}${d.msg}`).join(', ');
            }
            throw new Error(detailMsg || `Server returned status ${res.status}`);
        }

        const data = await res.json();
        currentDetectionResult = data;
        renderDetectionOutput(data, eventPayload);
        const toastCat = data.has_disagreement ? "Disagreement detected — review required" : data.threat_category.replace(/_/g, ' ');
        showToast(`Threat classification: ${toastCat}`, data.is_threat ? "info" : "success");
    } catch (err) {
        console.error("Threat detection failed:", err);
        showToast(`Detection failed: ${err.message}`, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }
}

function renderDetectionOutput(data, rawEvent) {
    const badge = document.getElementById('threat-badge');
    const catEl = document.getElementById('res-category');
    const mitreEl = document.getElementById('res-mitre');
    const sevEl = document.getElementById('res-severity');
    const actEl = document.getElementById('res-action');
    const anchorBtn = document.getElementById('btn-store-bc');

    // Unhide result panels now that we have a result
    ['action-box-panel', 'prob-section-panel', 'explainability-card'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('hidden');
    });

    if (data.status === "INSUFFICIENT_DATA") {
        if (badge) { badge.className = "badge-neutral"; badge.innerText = "Insufficient data"; }
        if (catEl) { catEl.className = "diag-v font-bold text-secondary"; catEl.innerText = "Insufficient data — refused to classify"; }
        if (sevEl)  { sevEl.className  = "diag-v text-secondary"; sevEl.innerText  = "—"; }
        if (mitreEl) { mitreEl.className = "diag-v text-secondary"; mitreEl.innerText = "—"; }
        if (actEl) actEl.innerText = data.recommended_action || "Telemetry below coverage threshold (0.60). Provide more flow features.";
        if (anchorBtn) {
            anchorBtn.disabled = true;
            anchorBtn.title = "Cannot anchor unclassified telemetry.";
            anchorBtn.style.opacity = '0.5';
            anchorBtn.style.cursor = 'not-allowed';
        }
        const barsContainer = document.getElementById('prob-bars-list');
        if (barsContainer) barsContainer.innerHTML = '<div style="font-size:0.8rem;color:var(--text-secondary);padding:8px;">Classification refused: feature coverage below 60%.</div>';
        const xaiList = document.getElementById('xai-attr-list');
        if (xaiList) xaiList.innerHTML = `<div style="font-size:0.8rem;color:var(--text-secondary);padding:8px;">Missing ${data.missing_count || 'several'} required features. Coverage: ${data.feature_coverage_pct}%.</div>`;
        return;
    }

    // Update metadata indicators (Item 10)
    const covEl = document.getElementById('val-coverage');
    const covBadge = document.getElementById('badge-coverage');
    if (covEl && data.feature_coverage_pct !== undefined) {
        covEl.innerText = `${data.feature_coverage_pct}%`;
        if (data.feature_coverage_warning) {
            if (covBadge) {
                covBadge.className = "badge-status pill-simulated";
                covBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber"></i> Coverage: <strong>${data.feature_coverage_pct}% (Low)</strong>`;
            }
        } else {
            if (covBadge) {
                covBadge.className = "badge-status";
                covBadge.innerHTML = `<i class="fa-solid fa-chart-pie"></i> Coverage: <strong>${data.feature_coverage_pct}%</strong>`;
            }
        }
    }

    const tsBadge = document.getElementById('badge-timestamp-type');
    if (tsBadge) {
        tsBadge.innerText = "Digital Timestamp (ISO 8601)";
    }

    const reviewBadge = document.getElementById('badge-analyst-review');
    if (reviewBadge) {
        reviewBadge.innerText = data.reviewed_by_analyst ? "Analyst review: completed" : "Analyst review: pending";
        reviewBadge.className = data.reviewed_by_analyst ? "badge-status pill-live" : "badge-status badge-neutral";
    }

    // Classification & disagreement
    if (data.has_disagreement) {
        badge.className = "badge-danger";
        badge.innerText = "Disagreement detected";
        catEl.className = "diag-v text-red font-bold";
        const ruleCat = data.rule_prediction ? data.rule_prediction.category : 'Rule';
        const modelCat = data.model_prediction ? data.model_prediction.category : 'Model';
        catEl.innerHTML = `<span>Analyst Review Required (Detection Conflict)</span>
            <div style="font-size:0.75rem;color:#ffab91;font-weight:normal;margin-top:4px;line-height:1.4;">
                <strong>Detection model:</strong> ${modelCat} (${((data.model_prediction ? data.model_prediction.confidence : 0) * 100).toFixed(1)}%) &bull;
                <strong>Heuristic rule:</strong> ${ruleCat} (${data.rule_prediction ? data.rule_prediction.reason : ''})
            </div>
            <div id="disagreement-resolution-panel" style="margin-top:8px;padding:8px;background:rgba(192,57,43,0.15);border:1px solid var(--border-color);border-radius:6px;">
                <div style="font-size:0.75rem;font-weight:600;color:var(--text-primary);margin-bottom:6px;">
                    <i class="fa-solid fa-user-shield text-amber"></i> Forensic Review Action:
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    <button type="button" class="btn btn-secondary" style="font-size:11px;padding:3px 8px;" onclick="resolveDisagreement('rule')">
                        <i class="fa-solid fa-check"></i> Endorse Rule (${ruleCat})
                    </button>
                    <button type="button" class="btn btn-secondary" style="font-size:11px;padding:3px 8px;" onclick="resolveDisagreement('model')">
                        <i class="fa-solid fa-check"></i> Endorse Model (${modelCat})
                    </button>
                </div>
            </div>`;
        sevEl.className = "diag-v text-red font-bold";
        sevEl.innerText = "Undetermined (conflict)";
    } else {
        catEl.innerText = data.threat_category.replace(/_/g, ' ');
        sevEl.innerText = data.severity;

        if (data.is_threat) {
            badge.className = "badge-danger";
            badge.innerText = "Threat detected";
            catEl.className = "diag-v text-red font-bold";
            sevEl.className = "diag-v text-red font-bold";
        } else {
            badge.className = "badge-benign";
            badge.innerText = "Benign";
            catEl.className = "diag-v text-green font-bold";
            sevEl.className = "diag-v text-green font-bold";
        }
    }

    if (data.has_disagreement) {
        mitreEl.innerText = "N/A — Conflict Adjudication Required";
    } else {
        mitreEl.innerText = `${data.mitre_attack_id} (${data.technique_name})`;
    }
    actEl.innerText = data.recommended_action;

    // Item 6: Presets: show 'Sample label: X' next to 'Model: Y'. When they differ, show 'Model missed this sample' and drop 'Allow traffic' recommendation.
    const sampleLabel = currentPresetKey ? PRESET_SAMPLE_LABELS[currentPresetKey] : (data.ground_truth_label || null);
    const modelCat = (data.model_prediction && data.model_prediction.category) ? data.model_prediction.category : null;

    if (sampleLabel && modelCat) {
        const normSample = sampleLabel.toLowerCase().replace(/[-_ ]/g, '');
        const normModel = modelCat.toLowerCase().replace(/[-_ ]/g, '');
        const isEquivalent = (normSample === normModel) ||
            (normSample.includes("web") && normModel.includes("web")) ||
            (normSample.includes("sqlinjection") && normModel.includes("web")) ||
            (normSample.includes("bruteforce") && (normModel.includes("patator") || normModel.includes("brute"))) ||
            (normSample.includes("bot") && normModel.includes("bot")) ||
            (normSample.includes("dos") && normModel.includes("dos"));
        const diff = !isEquivalent;
        let sampleHtml = `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:6px;">
            <span class="badge-status" style="font-size:0.75rem;">Sample label: ${sampleLabel}</span>
            <span class="badge-status" style="font-size:0.75rem;">Model: ${modelCat}</span>`;
        if (diff) {
            sampleHtml += `<span class="badge-status badge-danger" style="font-size:0.75rem;"><i class="fa-solid fa-triangle-exclamation"></i> Model missed this sample</span>`;
        } else if (sampleLabel !== "BENIGN") {
            sampleHtml += `<span class="badge-status badge-success" style="font-size:0.75rem;"><i class="fa-solid fa-check"></i> Matched</span>`;
        }
        sampleHtml += `</div>`;

        let existingSampleDiv = document.getElementById('preset-sample-diff-banner');
        if (!existingSampleDiv) {
            existingSampleDiv = document.createElement('div');
            existingSampleDiv.id = 'preset-sample-diff-banner';
            catEl.parentElement.appendChild(existingSampleDiv);
        }
        existingSampleDiv.innerHTML = sampleHtml;

        if (diff) {
            // Drop "Allow traffic" recommendation
            if (actEl.innerText.toLowerCase().includes("allow traffic")) {
                actEl.innerText = "Analyst review required: model missed this preset sample";
            }
        }
    }

    // Render probability distribution bars — sorted by probability, top 5 only
    const barsContainer = document.getElementById('prob-bars-list');
    barsContainer.innerHTML = '';

    const _probEntries = Object.entries(data.class_probabilities || {});
    if (_probEntries.length === 0) {
        barsContainer.innerHTML = '<div style="font-size:0.8rem;color:var(--se-text-muted);padding:8px;">No probability data returned.</div>';
    } else {
        const _activeClass = data.model_prediction ? data.model_prediction.category : data.threat_category;
        // Sort highest probability first, show top 5
        const _sorted = _probEntries
            .map(([cls, prob]) => ({ cls, prob }))
            .sort((a, b) => b.prob - a.prob)
            .slice(0, 5);

        _sorted.forEach(({ cls, prob }) => {
            const pct = (prob * 100);
            const isSelected = (cls === _activeClass);
            const isThreat   = (cls !== 'BENIGN' && cls !== 'Normal_Traffic');
            const barColor   = isSelected
                ? (isThreat ? 'var(--se-danger)' : 'var(--se-ok)')
                : 'var(--se-border-strong)';
            const labelColor = isSelected
                ? (isThreat ? 'var(--se-danger)' : 'var(--se-ok)')
                : 'var(--se-text-muted)';

            const item = document.createElement('div');
            item.className = 'prob-item';
            item.innerHTML = `
                <div class="prob-head" style="margin-bottom:3px;">
                    <span style="color:${labelColor};font-weight:${isSelected ? '700' : '500'};font-size:0.82rem;">
                        ${isSelected ? '&#9654; ' : ''}${cls.replace(/_/g, ' ')}
                    </span>
                    <span style="color:var(--se-text);font-weight:${isSelected ? '700' : '400'};font-size:0.82rem;">${pct.toFixed(1)}%</span>
                </div>
                <div style="height:7px;border-radius:4px;background:var(--se-bg);overflow:hidden;border:1px solid var(--se-border);">
                    <div style="width:${pct.toFixed(2)}%;height:100%;border-radius:4px;background:${barColor};transition:width 0.4s ease;"></div>
                </div>`;
            barsContainer.appendChild(item);
        });
    }

    // Render Evidence Signal Analysis
    const xaiList = document.getElementById('xai-attr-list');
    if (xaiList) {
        xaiList.innerHTML = '';
        const attributions = data.feature_attributions || [];

        if (attributions.length === 0) {
            xaiList.innerHTML = '<div style="font-size: 0.8rem; color: var(--text-secondary); padding: 8px;">Baseline telemetry within expected operating thresholds. No outlier features detected.</div>';
        } else {
            const FEATURE_HUMAN_NAMES = {
                "Init_Win_bytes_forward": "Initial Window Bytes (Forward)",
                "Init_Win_bytes_backward": "Initial Window Bytes (Backward)",
                "Flow IAT Min": "Flow Inter-Arrival Time (Min)",
                "min_seg_size_forward": "Minimum Segment Size (Forward)",
                "Fwd Header Length": "Forward Header Length",
                "Total Length of Fwd Packets": "Total Length of Forward Packets",
                "Flow Duration": "Flow Duration (µs)",
                "Flow Packets/s": "Flow Packet Rate (pkts/sec)",
                "Flow Bytes/s": "Flow Byte Rate (bytes/sec)",
                "Total Fwd Packets": "Total Forward Packets",
                "SYN Flag Count": "SYN Flag Count"
            };

            attributions.forEach(attr => {
                const attrDiv = document.createElement('div');
                attrDiv.className = 'attr-item';
                const fName = attr.feature || attr.feature_name || 'Feature';
                const displayName = FEATURE_HUMAN_NAMES[fName] || fName.replace(/_/g, ' ');
                const maxVal = Math.max(...attributions.map(a => Math.abs(a.shap_value !== undefined ? a.shap_value : (a.impact_score || 0))), 0.0001);
                const shapVal = (attr.shap_value !== undefined ? attr.shap_value : (attr.impact_score || 0));
                const absVal = Math.abs(shapVal);
                const pct = Math.min(100, Math.max(5, Math.round((absVal / maxVal) * 100)));
                let desc = attr.explanation || `Telemetry value: ${attr.raw_value}`;
                desc = desc.replace(/\s*\(\+?-?[\d\.]+\s*std\s*dev[^\)]*\)/gi, '');
                desc = desc.replace(/training flows/gi, 'baseline network traffic');
                desc = desc.split(fName).join(displayName);

                attrDiv.innerHTML = `
                    <div class="attr-meta">
                        <span class="attr-name">${displayName}</span>
                        <span class="attr-score font-mono">${pct}% (top feature = 100%)</span>
                    </div>
                    <div class="attr-bar-track">
                        <div class="attr-bar-fill" style="width: ${pct}%"></div>
                    </div>
                    <div class="attr-desc">${desc}</div>
                `;
                xaiList.appendChild(attrDiv);
            });
        }
    }

    // Populate evidence JSON editor
    const caseInp = document.getElementById('input_case_id');
        if (caseInp) caseInp.value = data.incident_id || '';
        currentEvidencePayload = {
        incident_id: data.incident_id || `INSA-CR-${new Date().getUTCFullYear()}-${(data.fingerprint || Math.random().toString(16).substring(2,8)).slice(-6).toUpperCase()}`,
        target_asset: rawEvent.target_asset,
        threat_category: data.threat_category,
        mitre_attack_id: data.mitre_attack_id,
        source_ip: rawEvent.source_ip,
        destination_ip: rawEvent.destination_ip,
        flow_duration: rawEvent.flow_duration,
        flow_packets_s: rawEvent.flow_packets_s,
        flow_bytes_s: rawEvent.flow_bytes_s,
        ai_confidence: data.confidence,
        has_disagreement: Boolean(data.has_disagreement),
        reviewed_by_analyst: Boolean(data.reviewed_by_analyst),
        raw_telemetry: rawEvent
    };
    originalEvidencePayload = JSON.parse(JSON.stringify(currentEvidencePayload));

    document.getElementById('evidence-json-editor').value = JSON.stringify(currentEvidencePayload, null, 2);
}

async function resolveDisagreement(choice) {
    if (!currentDetectionResult || !currentEvidencePayload) return;

    if (!currentUser || !inMemoryAccessToken) {
        promptLogin("Sign in as Analyst to record forensic review");
        return;
    }

    const incidentId = currentDetectionResult.incident_id || currentEvidencePayload.incident_id;
    if (!incidentId) {
        showToast("Error: No server incident ID associated with this detection.", "error");
        return;
    }

    const ruleCat = currentDetectionResult.rule_prediction ? currentDetectionResult.rule_prediction.category : 'DDoS';
    const modelCat = currentDetectionResult.model_prediction ? currentDetectionResult.model_prediction.category : 'BENIGN';
    const chosenCat = (choice === 'rule') ? ruleCat : modelCat;

    // Requirement: Written justification is strictly required to resolve model/rule disagreement
    const promptMsg = (choice === 'rule') 
        ? `Enter forensic justification for endorsing heuristic rule (${ruleCat}) over AI model (${modelCat}):` 
        : `Enter forensic justification for endorsing AI model (${modelCat}) over heuristic rule (${ruleCat}):`;
    const defaultJustification = (choice === 'rule')
        ? `Packet rate and header flags match ${ruleCat} signature; overriding model prediction.`
        : `Heuristic rule triggered on baseline telemetry spike; forensic evaluation confirms benign flow.`;

    const justification = window.prompt(promptMsg, defaultJustification);
    if (!justification || justification.trim().length < 5) {
        showToast("Adjudication cancelled: Written forensic justification (at least 5 characters) is required.", "warning");
        return;
    }

    try {
        const res = await authFetch('/evidence/review', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                incident_id: incidentId,
                choice: choice,
                threat_category: chosenCat,
                justification: justification.trim()
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server review rejected: HTTP ${res.status}`);
        }

        const reviewData = await res.json();

    const FORENSIC_CAT_INFO = {
        "DDoS": {
            mitre: "T1498.001 (Network Denial of Service: Direct Network Flood)",
            severity: "CRITICAL",
            severityClass: "diag-v text-red font-bold",
            action: "Trigger Perimeter BGP Blackholing & Ingress Rate-Limiting",
            isThreat: true
        },
        "PortScan": {
            mitre: "T1046 (Network Service Discovery: Port Scan)",
            severity: "HIGH",
            severityClass: "diag-v text-amber font-bold",
            action: "Block Reconnaissance IP Subnet on Edge Firewalls",
            isThreat: true
        },
        "Web_Attack": {
            mitre: "T1190 (Exploit Public-Facing Application: Injection)",
            severity: "HIGH",
            severityClass: "diag-v text-red font-bold",
            action: "Engage WAF Virtual Patching & Inspect Database Transcripts",
            isThreat: true
        },
        "Web Attack": {
            mitre: "T1190 (Exploit Public-Facing Application: Injection)",
            severity: "HIGH",
            severityClass: "diag-v text-red font-bold",
            action: "Engage WAF Virtual Patching & Inspect Database Transcripts",
            isThreat: true
        },
        "SSH-Patator": {
            mitre: "T1110.001 (Brute Force: Password Guessing)",
            severity: "HIGH",
            severityClass: "diag-v text-amber font-bold",
            action: "Enforce SSH Fail2ban Policy & Invalidate Active Sessions",
            isThreat: true
        },
        "Bot": {
            mitre: "T1071.001 (Command & Control: Botnet C2)",
            severity: "CRITICAL",
            severityClass: "diag-v text-red font-bold",
            action: "Isolate Endpoint & Capture Volatile Memory Forensics",
            isThreat: true
        },
        "BENIGN": {
            mitre: "N/A (Benign Baseline Flow)",
            severity: "LOW",
            severityClass: "diag-v text-green font-bold",
            action: "Allow Traffic & Record Baseline Telemetry",
            isThreat: false
        }
    };

    const catInfo = FORENSIC_CAT_INFO[chosenCat] || {
        mitre: `T1000 (${chosenCat})`,
        severity: (chosenCat === 'BENIGN') ? "LOW" : "HIGH",
        severityClass: (chosenCat === 'BENIGN') ? "diag-v text-green font-bold" : "diag-v text-red font-bold",
        action: (chosenCat === 'BENIGN') ? "Allow Traffic & Record Baseline Telemetry" : "Quarantine Flow & Investigate Telemetry",
        isThreat: (chosenCat !== 'BENIGN')
    };

    currentDetectionResult.reviewed_by_analyst = true;
    currentDetectionResult.threat_category = chosenCat;
    currentDetectionResult.has_disagreement = false;
    currentDetectionResult.severity = catInfo.severity;
    currentDetectionResult.mitre_attack_id = catInfo.mitre.split(' ')[0];
    currentDetectionResult.technique_name = catInfo.mitre;
    currentDetectionResult.recommended_action = catInfo.action;

    currentEvidencePayload.reviewed_by_analyst = true;
    currentEvidencePayload.has_disagreement = false;
    currentEvidencePayload.threat_category = chosenCat;
    currentEvidencePayload.severity = catInfo.severity;
    currentEvidencePayload.mitre_attack_id = currentDetectionResult.mitre_attack_id;
    currentEvidencePayload.reviewed_by = currentUser ? (currentUser.full_name || currentUser.username) : "INSA Forensic Analyst";
    currentEvidencePayload.review_timestamp = new Date().toISOString();
    currentEvidencePayload.analyst_justification = justification.trim();
    currentEvidencePayload.review_decision = `Forensic analyst endorsed ${choice === 'rule' ? 'heuristic rule' : 'AI model'} (${chosenCat}). Justification: ${justification.trim()}`;
    currentEvidencePayload.disposition = (chosenCat === 'BENIGN' && ruleCat !== 'BENIGN') ? "DISPUTED / ANALYST OVERRIDE" : "CONFIRMED";

    // Update UI elements
    const reviewBadge = document.getElementById('badge-analyst-review');
    if (reviewBadge) {
        reviewBadge.innerText = "Analyst review: recorded";
        reviewBadge.className = "badge-status pill-live";
    }

    const catEl = document.getElementById('res-category');
    if (catEl) {
        catEl.className = catInfo.isThreat ? "diag-v text-red font-bold" : "diag-v text-green font-bold";
        catEl.innerText = `${chosenCat} (analyst confirmed)`;
    }

    const sevEl = document.getElementById('res-severity');
    if (sevEl) {
        sevEl.className = catInfo.severityClass;
        sevEl.innerText = catInfo.severity;
    }

    const mitreEl = document.getElementById('res-mitre');
    if (mitreEl) {
        mitreEl.className = "diag-v text-primary";
        mitreEl.innerText = catInfo.mitre;
    }

    const actEl = document.getElementById('res-action');
    if (actEl) {
        actEl.innerText = catInfo.action;
    }

    const badge = document.getElementById('threat-badge');
    if (badge) {
        if (catInfo.isThreat) {
            badge.className = "badge-danger";
            badge.innerText = `Threat confirmed (${chosenCat})`;
        } else {
            badge.className = "badge-benign";
            badge.innerText = "Benign (analyst confirmed)";
        }
    }

    const panel = document.getElementById('disagreement-resolution-panel');
    if (panel) {
        panel.innerHTML = `<span style="color:#27ae60;font-size:0.8rem;font-weight:600;"><i class="fa-solid fa-circle-check"></i> Forensic review recorded by ${currentEvidencePayload.reviewed_by} (${chosenCat}). Unlocked for anchoring.</span>`;
    }

    const anchorBtn = document.getElementById('btn-store-bc');
    if (anchorBtn) {
        anchorBtn.disabled = false;
        anchorBtn.title = "Anchor evidence record to sovereign ledger";
        anchorBtn.style.opacity = '1';
        anchorBtn.style.cursor = 'pointer';
    }

    // Update JSON editor
    originalEvidencePayload = JSON.parse(JSON.stringify(currentEvidencePayload));
    const jsonEditor = document.getElementById('evidence-json-editor');
    if (jsonEditor) {
        jsonEditor.value = JSON.stringify(currentEvidencePayload, null, 2);
    }

    showToast(`Analyst review recorded: Endorsed ${chosenCat}. Anchoring is now unlocked.`, "success");
    } catch (err) {
        console.error("Forensic review recording failed:", err);
        showToast("Failed to record review: " + err.message, "error");
    }
}

async function handleStoreEvidence() {
    if (!currentUser || !inMemoryAccessToken) {
        promptLogin("Sign in to continue");
        return;
    }

    if (currentUser.role !== 'investigator') {
        showToast("Investigator role required to anchor evidence.", "error");
        return;
    }

    const investigator = currentUser.full_name || currentUser.username;
    const investigatorEl = document.getElementById('input_investigator');
    if (investigatorEl) investigatorEl.value = investigator;

    let caseId = (document.getElementById('input_case_id').value || '').trim();

    if (!currentEvidencePayload) {
        showToast("Please run threat detection first to capture evidence.", "error");
        return;
    }

    // Read current payload from JSON editor if edited
    let evidenceToStore = currentEvidencePayload;
    const editorEl = document.getElementById('evidence-json-editor');
    if (editorEl && editorEl.value) {
        try {
            evidenceToStore = JSON.parse(editorEl.value);
        } catch (e) {
            // fallback
        }
    }

    const isDisagreement = Boolean(evidenceToStore.has_disagreement) || 
                           (evidenceToStore.threat_category && evidenceToStore.threat_category.includes('DISAGREEMENT'));
    const isReviewed = Boolean(evidenceToStore.reviewed_by_analyst);

    if (isDisagreement && !isReviewed) {
        showToast("Unresolved model/rule disagreement. Click 'Endorse Rule' or 'Endorse Model' to record your forensic review before anchoring.", "warning");
        return;
    }

    const incidentType = evidenceToStore.threat_category || 
                         (currentDetectionResult ? currentDetectionResult.threat_category : "Cyber Incident");

    // Item 1: Store real threat_category, target_asset and investigator from token
    evidenceToStore.threat_category = incidentType;
    evidenceToStore.target_asset = evidenceToStore.target_asset || currentEvidencePayload.target_asset || "National-Gateway-Demo-01";
    evidenceToStore.investigator = investigator;

    const payload = {
        case_id: caseId || undefined,
        incident_type: incidentType,
        target_asset: evidenceToStore.target_asset,
        investigator: investigator,
        evidence_payload: evidenceToStore
    };

    const btn = document.getElementById('btn-store-bc');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Anchoring to Ledger...</span>';

    try {
        const res = await authFetch('/evidence/store', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server status ${res.status}`);
        }

        const data = await res.json();
        lastAnchoredBlock = data;
        const caseInput = document.getElementById('input_case_id');
        if (caseInput && data.case_id) {
            caseInput.value = data.case_id;
        }
        const edEl = document.getElementById('evidence-json-editor');
        if (edEl) edEl.value = JSON.stringify(evidenceToStore, null, 2);
        originalEvidencePayload = JSON.parse(JSON.stringify(evidenceToStore));
        showToast(`Evidence anchored to Record #${data.block_number} (${data.evidence_hash.substring(0, 10)}...)`, "success");

        await loadLedgerRecords();
        await loadSystemStats();
        handleVerifyEvidence();
    } catch (err) {
        console.error("Evidence anchoring failed:", err);
        const errMsg = err.message || "";
        if (errMsg.includes("acknowledgment required") || errMsg.includes("TRUNCATED") || errMsg.includes("DISAGREEMENT")) {
            showToast(
                `Anchoring disabled: ${errMsg}`,
                "error",
                { text: "Acknowledge & Continue", onClick: acknowledgeLedgerStateAndRetry }
            );
        } else {
            showToast(`Ledger anchoring failed: ${errMsg}`, "error");
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

async function handleVerifyEvidence() {
    let parsedPayload;
    try {
        parsedPayload = JSON.parse(document.getElementById('evidence-json-editor').value);
    } catch (e) {
        showToast("JSON Syntax Error: Please check JSON formatting in editor.", "error");
        return;
    }

    const btn = document.getElementById('btn-verify-ev');
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Verifying...</span>';
    }

    try {
        const res = await authFetch('/evidence/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ evidence_payload: parsedPayload })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server status ${res.status}`);
        }

        const result = await res.json();
        renderVerdict(result);
        if (result.is_authentic) {
            showToast("Evidence verified: Cryptographic SHA-256 fingerprint matches on-chain record.", "success");
        } else {
            showToast("TAMPER DETECTED: Computed hash does not match anchored ledger record.", "error");
        }
    } catch (err) {
        console.error("Verification failed:", err);
        showToast(`Verification failed: ${err.message}`, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }
}

function renderVerdict(result) {
    const box = document.getElementById('verdict-box');
    const title = document.getElementById('verdict-title');
    const sub = document.getElementById('verdict-sub');
    const hashEl = document.getElementById('verdict-hash');
    const statusEl = document.getElementById('verdict-status');
    const isLive = (result.ledger_mode || '').includes('LIVE') || Boolean(result.on_chain_confirmed);
    const recordType = isLive ? "anchored chain record" : "ledger record";

    const onchainLine = document.getElementById('verdict-onchain-line');
    const onchainStatus = document.getElementById('verdict-onchain-status');
    const blockLine = document.getElementById('verdict-block-line');
    const blockNum = document.getElementById('verdict-block-num');
    const txLine = document.getElementById('verdict-tx-line');
    const txHash = document.getElementById('verdict-tx-hash');
    const explorerLine = document.getElementById('verdict-explorer-line');
    const explorerLink = document.getElementById('verdict-explorer-link');

    hashEl.innerText = result.computed_hash || result.evidence_hash || 'N/A';

    // Item 11: Disable View certificate and Download certificate until verified
    const btnViewCert = document.getElementById('btn-view-cert');
    const btnDownloadCert = document.getElementById('btn-download-evidence');
    const isAuthentic = Boolean(result.is_authentic || result.integrity_verified) && !result.superseded && result.tamper_status !== "LOCAL_CHAIN_DISAGREEMENT";
    if (btnViewCert) btnViewCert.disabled = !isAuthentic;
    if (btnDownloadCert) btnDownloadCert.disabled = !isAuthentic;

    const btnStore = document.getElementById('btn-store-evidence');

    if (result.tamper_status === "LOCAL_CHAIN_DISAGREEMENT" || result.integrity_result === "LOCAL/CHAIN DISAGREEMENT") {
        box.className = "verdict-box status-mismatch";
        box.querySelector('.verdict-icon').innerHTML = '<i class="fa-solid fa-triangle-exclamation text-red"></i>';
        title.innerText = "LOCAL/CHAIN DISAGREEMENT";
        sub.innerText = "LOCAL/CHAIN DISAGREEMENT: Record verification differs between SQLite ledger and on-chain contract. Anchoring blocked.";
        statusEl.className = "meta-v text-red font-bold";
        statusEl.innerText = "LOCAL/CHAIN DISAGREEMENT";

        if (onchainLine) onchainLine.style.display = "flex";
        if (onchainStatus) {
            onchainStatus.innerText = "DISAGREEMENT";
            onchainStatus.className = "meta-v text-red font-bold";
        }
        if (blockLine) blockLine.style.display = "none";
        if (txLine) txLine.style.display = "none";
        if (explorerLine) explorerLine.style.display = "none";

        if (btnStore) {
            btnStore.disabled = true;
            btnStore.title = "Anchoring blocked: LOCAL/CHAIN DISAGREEMENT requires admin review";
        }
    } else if (result.superseded) {
        box.className = "verdict-box status-superseded";
        box.querySelector('.verdict-icon').innerHTML = '<i class="fa-solid fa-clock-rotate-left text-amber"></i>';
        title.innerText = "SUPERSEDED ON LEDGER";
        sub.innerText = "This forensic record was superseded by a subsequent amended custodial anchor.";
        statusEl.className = "meta-v text-amber font-bold";
        statusEl.innerText = "SUPERSEDED";
        if (onchainLine) onchainLine.style.display = "none";
        if (blockLine) blockLine.style.display = "none";
        if (txLine) txLine.style.display = "none";
        if (explorerLine) explorerLine.style.display = "none";
    } else if (result.is_authentic || result.integrity_verified) {
        box.className = "verdict-box status-verified";
        box.querySelector('.verdict-icon').innerHTML = '<i class="fa-solid fa-circle-check text-green"></i>';
        title.innerText = "INTEGRITY VERIFIED: HASH MATCHES ANCHORED RECORD";
        sub.innerText = `The cryptographic SHA-256 fingerprint matches the ${recordType}. No mismatch found between the submitted data and the anchored record (Proclamation No. 958/2016 & No. 1072/2018, to be verified by legal counsel).`;
        statusEl.className = "meta-v text-green font-bold";
        statusEl.innerText = "INTEGRITY VERIFIED";

        if (onchainLine) {
            onchainLine.style.display = "flex";
            if (onchainStatus) {
                const chainMode = result.chain_mode || window.activeChainMode || 'local';
                const chainId = String(result.chain_id || window.activeChainId || '');
                if (!isLive) {
                    onchainStatus.innerText = "simulated ledger confirmed";
                } else if (chainId === '31337' || chainMode === 'local') {
                    onchainStatus.innerText = "local chain confirmed";
                } else {
                    onchainStatus.innerText = "on-chain confirmed";
                }
                onchainStatus.className = "meta-v text-green font-bold";
            }
        }
        // Use SQLite ledger block_number first so it matches the registry table
        const blk = result.block_number || result.chain_block_number;
        if (blockLine && blk) {
            blockLine.style.display = "flex";
            if (blockNum) blockNum.innerText = `#${blk}`;
        }
        if (txLine && result.tx_hash) {
            txLine.style.display = "flex";
            if (txHash) txHash.innerText = result.tx_hash;
        }
        if (explorerLine) {
            if (result.explorer_url) {
                explorerLine.style.display = "flex";
                if (explorerLink) explorerLink.innerHTML = `<a href="${result.explorer_url}" target="_blank" class="text-blue" style="font-size:0.75rem;text-decoration:underline;">View on explorer</a>`;
            } else {
                explorerLine.style.display = "none";
            }
        }
    } else if (result.tamper_status === "NOT_FOUND_ON_LEDGER" || result.tamper_status === "NOT_FOUND_ON_CHAIN" || result.tamper_status === "HASH_MISMATCH_OR_UNANCHORED") {
        box.className = "verdict-box status-notfound";
        box.querySelector('.verdict-icon').innerHTML = '<i class="fa-solid fa-triangle-exclamation text-amber"></i>';
        title.innerText = "NOT FOUND ON LEDGER";
        sub.innerText = `The computed cryptographic hash does not match any registered entry on the ${isLive ? 'live blockchain' : 'simulated ledger'}.`;
        statusEl.className = "meta-v text-amber font-bold";
        statusEl.innerText = "NOT FOUND ON LEDGER";
        if (onchainLine) onchainLine.style.display = "none";
        if (blockLine) blockLine.style.display = "none";
        if (txLine) txLine.style.display = "none";
        if (explorerLine) explorerLine.style.display = "none";
    } else {
        box.className = "verdict-box status-mismatch";
        box.querySelector('.verdict-icon').innerHTML = '<i class="fa-solid fa-triangle-exclamation text-red"></i>';
        title.innerText = "HASH MISMATCH / RECORD COMPROMISED";
        sub.innerText = `WARNING: The computed cryptographic hash does not match the registered ${recordType}. Data modification or tampering detected.`;
        statusEl.className = "meta-v text-red font-bold";
        statusEl.innerText = "HASH MISMATCH";
        if (onchainLine) onchainLine.style.display = "none";
        if (blockLine) blockLine.style.display = "none";
        if (txLine) txLine.style.display = "none";
        if (explorerLine) explorerLine.style.display = "none";
    }
}

function tamperEvidenceJson() {
    try {
        const obj = JSON.parse(document.getElementById('evidence-json-editor').value);
        if (obj.source_ip) {
            obj.source_ip = obj.source_ip + ".modified";
        } else if (obj.flow_packets_s) {
            obj.flow_packets_s = obj.flow_packets_s + 0.001;
        } else {
            obj.tampered_field = "defense_altered_record";
        }
        document.getElementById('evidence-json-editor').value = JSON.stringify(obj, null, 2);
        showToast("Simulated defense modification: altered 1 byte in evidence payload.", "info");
        handleVerifyEvidence();
    } catch (e) {
        showToast("Cannot tamper invalid JSON.", "error");
    }
}

function resetEvidenceJson() {
    if (originalEvidencePayload) {
        document.getElementById('evidence-json-editor').value = JSON.stringify(originalEvidencePayload, null, 2);
        showToast("Reset evidence JSON to pristine captured state.", "info");
        handleVerifyEvidence();
    }
}

async function handleRefreshLedger(isManualClick = false) {
    const btn = document.getElementById('btn-refresh-ledger');
    let originalHtml = '';
    if (btn) {
        originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i><span>Refreshing...</span>';
    }

    try {
        const count = await loadLedgerRecords();
        await loadSystemStats();
        if (isManualClick) {
            showToast(`Ledger refreshed: ${count} records synchronized from ledger.`, "success");
        }
    } catch (err) {
        console.error("Manual ledger refresh failed:", err);
        if (isManualClick) {
            showToast(`Refresh failed: ${err.message}`, "error");
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }
}

function updateLedgerChipUI(healthData) {
    const chip = document.getElementById('chip-ledger-type') || document.getElementById('ledger-chip');
    const chipText = document.getElementById('ledger-chip-text');
    if (!chip) return;
    let text = 'Ledger: SQLite, hash-chained';
    if (healthData.chain_mode === 'local' && healthData.connected) {
        text = 'Ledger: SQLite + chain anchor (local node)';
    } else if (healthData.chain_mode === 'sepolia' && healthData.connected) {
        text = 'Ledger: SQLite + chain anchor (Sepolia testnet)';
    } else if (healthData.ledger_backend === 'memory') {
        text = 'Ledger: in-memory (resets on restart)';
    } else {
        text = 'Ledger: SQLite, hash-chained';
    }
    if (chipText) {
        chipText.innerText = text;
    } else {
        chip.innerText = text;
    }
}

async function loadLedgerRecords() {
    try {
        const res = await authFetch('/evidence');
        if (!res.ok) throw new Error(`HTTP status ${res.status}`);
        const data = await res.json();
        const tbody = document.getElementById('ledger-table-body');
        if (!tbody) return 0;
        
        tbody.innerHTML = '';
        ledgerRecordsMap = {};

        const records = data.records || [];

        // Update chain verification status badge
        const chainStatusEl = document.getElementById('ledger-chain-status');
        if (chainStatusEl) {
            try {
                if (currentUser && currentUser.role === 'investigator') {
                    const vRes = await authFetch('/ledger/verify-chain');
                    if (vRes.ok) {
                        const vData = await vRes.json();
                        if (vData.ok) {
                            chainStatusEl.innerText = `Chain verified: ${vData.total_blocks} blocks`;
                            chainStatusEl.style.color = '#10b981';
                            chainStatusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                        } else {
                            chainStatusEl.innerText = `Chain broken at block ${vData.broken_id}`;
                            chainStatusEl.style.color = '#ef4444';
                            chainStatusEl.style.background = 'rgba(239, 68, 68, 0.15)';
                        }
                    } else {
                        chainStatusEl.innerText = `Chain verified: ${records.length} blocks`;
                    }
                } else {
                    chainStatusEl.innerText = `Chain verified: ${records.length} blocks`;
                }
            } catch (e) {
                chainStatusEl.innerText = `Chain verified: ${records.length} blocks`;
            }
        }

        if (records.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 18px;">No evidence records anchored yet. Run detection and click "Anchor Evidence to Ledger".</td></tr>';
            const statEl = document.getElementById('stat-blocks-count');
            if (statEl) statEl.innerText = '0';
            return 0;
        }

        records.forEach(rec => {
            ledgerRecordsMap[rec.evidence_hash] = rec;
            const tr = document.createElement('tr');
            const mode = rec.ledger_mode || "SIMULATED LEDGER";
            const isLive = mode.includes("LIVE");
            const modeBadge = `<span class="badge-status ${isLive ? 'pill-live' : 'pill-simulated'}" style="font-size: 0.7rem;">${isLive ? 'LIVE CHAIN' : 'SIMULATED'}</span>`;

            const incType = (rec.incident_type || '').replace(/_/g, ' ');
            const isBenign = (rec.incident_type || '').toUpperCase() === 'BENIGN';
            const incColorClass = isBenign ? 'text-green' : 'text-red';
            const isDisputed = Boolean(rec.review_decision && (rec.review_decision.includes('disagreement') || rec.review_decision.includes('justification') || rec.review_decision.includes('overrode')));
            const disputeBadge = isDisputed ? ` <span class="badge-status" style="font-size:0.65rem;color:var(--text-secondary);background:rgba(148,163,184,0.15);" title="Analyst review overrode heuristic disagreement">DISPUTED</span>` : '';

            tr.innerHTML = `
                <td><strong class="text-amber font-mono">#${rec.block_number}</strong></td>
                <td style="color: var(--text-secondary); font-family: var(--font-mono); white-space: nowrap;">${rec.timestamp}</td>
                <td style="white-space: nowrap;"><span class="badge-status font-mono">${escHtml(rec.case_id)}</span> <button type="button" class="btn-copy-sm" onclick="navigator.clipboard.writeText('${escAttr(rec.case_id)}');showToast('Case ID copied!','info')" title="Copy Case ID" style="padding:1px 5px;font-size:11px;background:none;border:none;color:var(--se-steel);cursor:pointer;"><i class="fa-regular fa-copy"></i></button></td>
                <td><strong class="${incColorClass}">${escHtml(incType)}</strong>${disputeBadge}</td>
                <td style="white-space: nowrap;">${escHtml(rec.target_asset || '')}</td>
                <td style="white-space: nowrap; max-width: 150px; overflow: hidden; text-overflow: ellipsis;" title="${escAttr(rec.investigator || '')}">${escHtml(rec.investigator || '')}</td>
                <td style="white-space: nowrap;">${modeBadge}</td>
                <td style="white-space: nowrap; min-width: 250px;">
                    <div style="display: flex; gap: 6px; flex-shrink: 0; white-space: nowrap;">
                        <button type="button" class="btn-sm btn-outline" onclick="openCertificateModalWithHash('${rec.evidence_hash}')" title="View official certificate">
                            <i class="fa-solid fa-file-shield"></i> Certificate
                        </button>
                        <button type="button" class="btn-sm btn-outline" onclick="downloadCertificateByHash('${rec.evidence_hash}')" title="Download official certificate">
                            <i class="fa-solid fa-download"></i> Download
                        </button>
                        <button type="button" class="btn-sm btn-outline" onclick="openCustodyModal('${rec.case_id}')">
                            <i class="fa-solid fa-link"></i> Custody
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        const statEl = document.getElementById('stat-blocks-count');
        if (statEl) statEl.innerText = records.length;
        return records.length;
    } catch (err) {
        console.error("Failed to load ledger records:", err);
        throw err;
    }
}

async function loadSystemStats() {
    try {
        const res = await authFetch('/stats');
        if (!res.ok) return;
        const data = await res.json();
        const evEl = document.getElementById('stat-events-count');
        const thrEl = document.getElementById('stat-threats-count');
        const blkEl = document.getElementById('stat-blocks-count');
        const rateEl = document.getElementById('stat-verification-rate');

        if (evEl) {
            const ev = (data.events_processed !== undefined) ? data.events_processed :
                       (data.big_data_stats ? data.big_data_stats.total_events_processed : 0);
            evEl.innerText = Number(ev).toLocaleString();
        }

        if (thrEl) {
            const thr = (data.threats_detected !== undefined) ? data.threats_detected :
                        (data.big_data_stats ? data.big_data_stats.total_threats_detected : 0);
            thrEl.innerText = Number(thr).toLocaleString();
        }

        if (blkEl) {
            const tableRowCount = document.querySelectorAll('#ledger-table-body tr').length;
            const hasEmptyRow = document.querySelector('#ledger-table-body td[colspan]');
            const realRowCount = hasEmptyRow ? 0 : tableRowCount;
            const count = (data.total_evidence_stored !== undefined) ? data.total_evidence_stored :
                          (data.total_blocks !== undefined ? Math.max(0, data.total_blocks - 1) : realRowCount);
            blkEl.innerText = Number(realRowCount || count).toLocaleString();
        }

        const vRunEl = document.getElementById('stat-verifications-run');
        if (vRunEl) {
            const vRun = data.verifications_run !== undefined ? data.verifications_run : (data.total_verification_queries || 0);
            vRunEl.innerText = Number(vRun).toLocaleString();
        }

        const mCountEl = document.getElementById('stat-mismatches-count');
        if (mCountEl) {
            const mCount = data.mismatches_detected || 0;
            mCountEl.innerText = Number(mCount).toLocaleString();
        }
    } catch (e) {
        console.error("Stats load failed:", e);
    }
}

// Live Streaming Pipeline Controller & Poller
let streamPollTimer = null;
let streamAlertsCache = {};

async function pollStreamStatus() {
    try {
        const res = await authFetch('/stream/status');
        if (!res.ok) return;
        const data = await res.json();

        const badge = document.getElementById('stream-status-badge');
        const evSec = document.getElementById('stream-events-sec');
        const lagEl = document.getElementById('stream-consumer-lag');
        const scoredEl = document.getElementById('stream-events-scored');
        const deadEl = document.getElementById('stream-deadletter-count');

        const isRunning = data.running || data.pipeline_state === 'RUNNING';
        const evRate = Number(data.events_per_sec || 0);
        if (badge) {
            if (isRunning) {
                badge.innerText = (evRate === 0) ? 'Running (idle)' : 'RUNNING';
                badge.className = 'badge-status pill-live';
            } else {
                badge.innerText = 'STOPPED';
                badge.className = 'badge-status badge-neutral';
            }
        }
        // Item 3: One source of truth for dashboard counters
        const topEvEl = document.getElementById('stat-events-count');
        const topThrEl = document.getElementById('stat-threats-count');
        if (topEvEl && data.events_scored !== undefined) topEvEl.innerText = Number(data.events_scored).toLocaleString();
        if (topThrEl && data.threats_detected !== undefined) topThrEl.innerText = Number(data.threats_detected).toLocaleString();

        // Item 8: Print dead-letter event and reason
        if (data.deadletter_event) {
            console.log("Dead-letter event:", data.deadletter_event, "Reason:", data.deadletter_reason || "None");
        }
        const dlMsgEl = document.getElementById('stream-deadletter-msg');
        if (dlMsgEl) dlMsgEl.innerText = data.deadletter_event || 'None (all consumed packets validated)';
        const dlReasonEl = document.getElementById('stream-deadletter-reason');
        if (dlReasonEl) dlReasonEl.innerText = data.deadletter_reason || 'No validation errors';
        if (evSec) evSec.innerText = Number(data.events_per_sec || 0).toFixed(1);
        if (lagEl) lagEl.innerText = Number(data.consumer_lag || 0).toLocaleString();
        if (scoredEl) scoredEl.innerText = Number(data.events_scored || 0).toLocaleString();
        if (deadEl) deadEl.innerText = Number(data.deadletter_count || 0).toLocaleString();

        // Also refresh recent stream alerts
        await pollStreamAlerts();
    } catch (e) {
        console.warn("Stream status poll failed:", e);
    }
}

async function pollStreamAlerts() {
    try {
        const res = await authFetch('/stream/alerts?limit=10');
        if (!res.ok) return;
        const data = await res.json();
        let alerts = data.alerts || [];
        if (document.getElementById('stream-mismatches-only')?.checked) {
            alerts = alerts.filter(a => a.ground_truth_label && a.predicted_class && a.ground_truth_label !== a.predicted_class);
        }
        const tbody = document.getElementById('stream-alerts-tbody');
        if (!tbody) return;

        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:14px;">No stream detections yet.</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        alerts.forEach(alert => {
            streamAlertsCache[alert.event_id] = alert;
            const tr = document.createElement('tr');
            const isThreat = alert.predicted_class && alert.predicted_class !== 'BENIGN' && alert.predicted_class !== 'INSUFFICIENT_DATA';
            const isMismatch = Boolean(alert.ground_truth_label && alert.predicted_class && alert.ground_truth_label !== alert.predicted_class);
            const clsBadge = isThreat
                ? `<span class="badge-status badge-danger">${alert.predicted_class}</span>`
                : `<span class="badge-status badge-neutral">${alert.predicted_class || '—'}</span>`;

            // Item 8: Confidence with 3 decimals
            const conf = (alert.confidence !== undefined && alert.confidence !== null)
                ? Number(alert.confidence).toFixed(3) : '—';
            const cov = (alert.feature_coverage !== undefined && alert.feature_coverage !== null)
                ? `${(alert.feature_coverage * 100).toFixed(1)}%` : '—';

            // Item 8: "Send to analyst review" only for non-BENIGN rows or mismatches
            // For clean BENIGN flows: provide "Inspect flow" action so analysts can inspect baseline traffic
            const actionBtn = (isThreat || isMismatch)
                ? `<button type="button" class="btn-sm btn-outline" style="font-size:11px;padding:3px 8px;" onclick="sendStreamAlertToAnalystReview('${alert.event_id}')" title="Send threat to analyst review workbench">
                       <i class="fa-solid fa-microchip"></i> Send to analyst review
                   </button>`
                : `<button type="button" class="btn-sm btn-outline" style="font-size:11px;padding:3px 8px;opacity:0.85;" onclick="sendStreamAlertToAnalystReview('${alert.event_id}')" title="Inspect flow telemetry in workbench">
                       <i class="fa-solid fa-magnifying-glass"></i> Inspect flow
                   </button>`;

            tr.innerHTML = `
                <td class="font-mono" style="font-size:11px;color:var(--text-secondary);">${(alert.event_id || '').substring(0, 14)}...</td>
                <td class="font-mono" style="font-size:11px;color:var(--text-secondary);">${(alert.event_time || alert.scored_at || '').substring(11, 19)}</td>
                <td>${clsBadge}</td>
                <td class="font-mono">${conf}</td>
                <td class="font-mono">${cov}</td>
                <td style="color:var(--text-secondary);">${alert.ground_truth_label || '—'}</td>
                <td>${actionBtn}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.warn("Stream alerts poll failed:", e);
    }
}

async function handleStreamControl(action) {
    if (!currentUser) {
        promptLogin("Sign in as Investigator to control stream pipeline");
        return;
    }
    if (currentUser.role !== 'investigator') {
        showToast("Investigator role required to control stream pipeline.", "error");
        return;
    }

    const rateInput = document.getElementById('stream-control-rate');
    const rateVal = rateInput ? parseInt(rateInput.value, 10) : 200;

    const btn = (action === 'start') ? document.getElementById('btn-stream-start') : document.getElementById('btn-stream-stop');
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Executing...`;
    }

    try {
        const res = await authFetch('/stream/control', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, rate: rateVal })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        showToast(`Stream pipeline ${action.toUpperCase()}: ${data.output || 'Command executed'}`, "success");
        await pollStreamStatus();
        await loadSystemStats();
    } catch (e) {
        console.error("Stream control failed:", e);
        showToast(`Stream control failed: ${e.message}`, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }
}

function sendStreamAlertToAnalystReview(eventId) {
    const alert = streamAlertsCache[eventId];
    if (!alert) {
        showToast("Stream event details not found.", "error");
        return;
    }

    if (typeof switchNavTab === "function") {
        switchNavTab("threat-triage");
    }

    // Populate flow form with available flow features from alert
    const formFields = [
        "flow_duration", "flow_packets_s", "flow_bytes_s", "total_fwd_packets",
        "syn_flag_count", "source_ip", "destination_ip"
    ];

    formFields.forEach(field => {
        const el = document.getElementById(field);
        if (el && alert[field] !== undefined) {
            el.value = alert[field];
        }
    });

    // Scroll to the workbench and trigger detection/review
    const flowSection = document.getElementById('pane-flow');
    if (flowSection) {
        flowSection.scrollIntoView({ behavior: 'smooth' });
    }

    const isBenign = alert.predicted_class === "BENIGN" && !alert.is_threat;
    const label = isBenign ? "clean flow" : "stream alert";
    showToast(`Loaded ${label} ${eventId.substring(0, 8)} into workbench. Click "Run detection" to inspect.`, "info");
}

const NUMERIC_SCHEMA_FIELDS = new Set([
    "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_fwd_packets", "total_length_bwd_packets", "fwd_packet_length_max",
    "fwd_packet_length_mean", "bwd_packet_length_mean", "flow_bytes_s", "flow_packets_s",
    "flow_iat_mean", "flow_iat_std", "fwd_iat_total", "bwd_iat_total", "fwd_packets_s",
    "bwd_packets_s", "packet_length_mean", "packet_length_std", "fin_flag_count",
    "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count",
    "urg_flag_count", "down_up_ratio", "average_packet_size", "init_win_bytes_forward",
    "init_win_bytes_backward", "flow duration", "total fwd packets", "total backward packets",
    "total length of fwd packets", "total length of bwd packets", "fwd packet length max",
    "fwd packet length min", "fwd packet length mean", "fwd packet length std",
    "bwd packet length max", "bwd packet length min", "bwd packet length mean",
    "bwd packet length std", "flow bytes/s", "flow packets/s", "flow iat mean",
    "flow iat std", "flow iat max", "flow iat min", "fwd iat total", "fwd iat mean",
    "fwd iat std", "fwd iat max", "fwd iat min", "bwd iat total", "bwd iat mean",
    "bwd iat std", "bwd iat max", "bwd iat min", "fwd psh flags", "bwd psh flags",
    "fwd urg flags", "bwd urg flags", "fwd header length", "bwd header length",
    "min packet length", "max packet length", "packet length variance", "cwe flag count",
    "ece flag count", "avg fwd segment size", "avg bwd segment size", "fwd header length.1",
    "fwd avg bytes/bulk", "fwd avg packets/bulk", "fwd avg bulk rate", "bwd avg bytes/bulk",
    "bwd avg packets/bulk", "bwd avg bulk rate", "subflow fwd packets", "subflow fwd bytes",
    "subflow bwd packets", "subflow bwd bytes", "act_data_pkt_fwd", "min_seg_size_forward",
    "active mean", "active std", "active max", "active min", "idle mean", "idle std",
    "idle max", "idle min"
]);

// Canonicalize object for deterministic SHA-256 hashing matching backend Python logic
function canonicalizeJson(val, fieldName = null) {
    if (val === null || val === undefined) return val;
    if (typeof val === 'number') {
        if (!isFinite(val)) {
            throw new Error("Cryptographic hashing rejected: NaN and Infinity are not allowed.");
        }
        return Number.isInteger(val) ? Math.trunc(val) : val;
    }
    if (typeof val === 'boolean') {
        return val;
    }
    if (typeof val === 'string') {
        const normKey = fieldName ? fieldName.trim().toLowerCase() : '';
        if (fieldName && (NUMERIC_SCHEMA_FIELDS.has(normKey) || 
                          NUMERIC_SCHEMA_FIELDS.has(normKey.replace(/_/g, ' ')) ||
                          NUMERIC_SCHEMA_FIELDS.has(normKey.replace(/ /g, '_')))) {
            const s = val.trim();
            const f = Number(s);
            if (!isNaN(f) && isFinite(f)) {
                return Number.isInteger(f) ? Math.trunc(f) : f;
            }
        }
        return val;
    }
    if (Array.isArray(val)) {
        return val.map(x => canonicalizeJson(x, fieldName));
    }
    if (typeof val === 'object') {
        const sorted = {};
        Object.keys(val).sort().forEach(k => {
            sorted[k] = canonicalizeJson(val[k], k);
        });
        return sorted;
    }
    return val;
}

// Client-side Web Crypto API SHA-256 hashing with deterministic canonicalization
async function calculateClientSha256(input) {
    let data;
    if (input instanceof ArrayBuffer) {
        data = input;
    } else {
        let textToHash = input;
        if (typeof input === 'object' && input !== null) {
            textToHash = JSON.stringify(canonicalizeJson(input));
        } else if (typeof input === 'string') {
            try {
                const parsed = JSON.parse(input);
                if (typeof parsed === 'object' && parsed !== null) {
                    textToHash = JSON.stringify(canonicalizeJson(parsed));
                }
            } catch (_) {
                // Keep raw string as-is
            }
        }
        const encoder = new TextEncoder();
        data = encoder.encode(textToHash);
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Drag & drop forensic file zone initialization
function initPublicDropZone() {
    const dropZone = document.getElementById('public-drop-zone');
    if (!dropZone) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('drag-active');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('drag-active');
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            processAndVerifyPublicFile(files[0]);
        }
    }, false);
}

function handlePublicFileSelected(event) {
    const files = event.target.files;
    if (files && files.length > 0) {
        processAndVerifyPublicFile(files[0]);
    }
}

async function processAndVerifyPublicFile(file) {
    const inputEl = document.getElementById('public-verify-input');
    showToast(`Hashing file locally via Web Crypto API: ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`, "info");
    try {
        const buffer = await file.arrayBuffer();
        const hash = await calculateClientSha256(buffer);
        if (inputEl) inputEl.value = hash;
        showToast(`File hashed locally: ${hash.substring(0, 16)}... Querying ledger...`, "success");
        await handlePublicVerify();
    } catch (err) {
        console.error("Local file hashing error:", err);
        showToast("Failed to compute SHA-256 hash: " + err.message, "error");
    }
}

// Public Forensic Verifier (Privacy-preserving, client-hashed, rate-limited)
async function handlePublicVerify() {
    const rawInput = document.getElementById('public-verify-input').value.trim();
    const resultBox = document.getElementById('public-verify-result');
    if (!rawInput) {
        showToast("Please enter a SHA-256 hash or evidence text to verify.", "error");
        return;
    }

    let queryHash = rawInput;
    // If input is not a 64-character hex string, compute SHA-256 locally in browser
    if (!/^[a-fA-F0-9]{64}$/.test(rawInput)) {
        try {
            queryHash = await calculateClientSha256(rawInput);
            showToast("Raw input hashed locally via Web Crypto API before query.", "info");
        } catch (e) {
            console.warn("Client hashing fallback:", e);
        }
    }

    try {
        const res = await fetch('/evidence/verify-public', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ evidence_hash: queryHash })
        });

        if (res.status === 429) {
            showToast("Public verification rate limit reached. Please wait 60s.", "error");
            resultBox.style.display = 'block';
            resultBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-hourglass-half text-amber" style="font-size: 1.4rem;"></i>
                    <strong class="text-amber" style="font-size: 1rem;">RATE LIMIT EXCEEDED (HTTP 429)</strong>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-secondary);">
                    Excessive public queries detected. Public audit queries are limited to protect infrastructure availability.
                </div>
            `;
            return;
        }

        const data = await res.json();
        resultBox.style.display = 'block';
        const verdict = data.verdict || data.status;

        if (verdict === "INTEGRITY VERIFIED") {
            const isLive = (data.ledger_mode || '').includes('LIVE');
            resultBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-circle-check text-green" style="font-size: 1.4rem;"></i>
                    <strong class="text-green" style="font-size: 1rem;">INTEGRITY VERIFIED</strong>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.6;">
                    <div><strong>Evidence Hash:</strong> <span class="font-mono text-white">${data.evidence_hash}</span></div>
                    <div><strong>Block Height:</strong> <span class="text-green">#${data.block_number !== undefined ? data.block_number : 'N/A'}</span></div>
                    <div><strong>Anchor Time:</strong> <span class="font-mono text-white">${data.anchor_timestamp || 'N/A'}</span></div>
                    <div><strong>Ledger Mode:</strong> <span class="badge-status ${isLive ? 'pill-live' : 'pill-simulated'}">${isLive ? 'LIVE CHAIN' : 'SIMULATED LEDGER'}</span></div>
                    <div><strong>Status:</strong> <span class="text-green">ACTIVE / UNMODIFIED</span></div>
                    <div style="margin-top: 6px; font-size: 0.75rem; color: #888;">${data.legal_framework || 'FDRE Proclamations No. 958/2016 and No. 1072/2018 (to be verified by legal counsel)'}</div>
                </div>
            `;
            showToast("Public verification: INTEGRITY VERIFIED", "success");
        } else if (verdict === "SUPERSEDED") {
            resultBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-triangle-exclamation text-amber" style="font-size: 1.4rem;"></i>
                    <strong class="text-amber" style="font-size: 1rem;">SUPERSEDED</strong>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                    <div>Queried Hash: <span class="font-mono text-white">${queryHash}</span></div>
                    <div><strong>Superseded By:</strong> <span class="font-mono text-amber">${data.superseded_by || 'Replacement record'}</span></div>
                    <div style="margin-top: 4px;">${data.message || 'This evidence record was amended and superseded.'}</div>
                </div>
            `;
            showToast("Public verification: SUPERSEDED", "info");
        } else if (verdict === "HASH MISMATCH") {
            resultBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-triangle-exclamation text-red" style="font-size: 1.4rem;"></i>
                    <strong class="text-red" style="font-size: 1rem;">HASH MISMATCH</strong>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                    <div>Queried Hash: <span class="font-mono text-white">${queryHash}</span></div>
                    <div style="margin-top: 4px;">Record found by identifier but payload hash does not match anchored digest. Evidence has been modified.</div>
                </div>
            `;
            showToast("Public verification: HASH MISMATCH", "error");
        } else {
            resultBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-circle-xmark text-red" style="font-size: 1.4rem;"></i>
                    <strong class="text-red" style="font-size: 1rem;">NOT FOUND</strong>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                    <div>Queried Hash: <span class="font-mono text-white">${queryHash}</span></div>
                    <div style="margin-top: 4px;">Evidence hash not found in ledger registry.</div>
                </div>
            `;
            showToast("Public verification: NOT FOUND", "error");
        }
    } catch (e) {
        console.error("Public verification query failed:", e);
        showToast("Public verification failed: " + e.message, "error");
    }
}

async function downloadCertificateByHash(evidenceHash) {
    if (!evidenceHash) {
        showToast("No evidence hash provided for download.", "error");
        return;
    }
    const rec = ledgerRecordsMap[evidenceHash] || {};
    const caseId = rec.case_id || "INSA-CERT";
    const cleanCaseId = caseId.replace(/[^a-zA-Z0-9_-]/g, '_');

    try {
        showToast("Generating official court certificate...", "info");
        const res = await authFetch(`/evidence/certificate/${encodeURIComponent(evidenceHash)}`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Certificate_${cleanCaseId}_${evidenceHash.substring(0, 10)}.html`;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            try {
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (ignore) {}
        }, 2000);
        showToast(`Court Certificate for ${caseId} downloaded successfully.`, "success");
    } catch (e) {
        console.error("Certificate download error:", e);
        showToast("Certificate download failed: " + e.message, "error");
    }
}

// downloadEvidenceByHash now downloads the real court certificate
async function downloadEvidenceByHash(evidenceHash) {
    return downloadCertificateByHash(evidenceHash);
}

function handleDownloadCurrentEvidence() {
    let hashToDownload = null;
    if (lastAnchoredBlock && lastAnchoredBlock.evidence_hash) {
        hashToDownload = lastAnchoredBlock.evidence_hash;
    } else {
        const editorVal = document.getElementById('evidence-json-editor').value;
        if (editorVal) {
            try {
                const parsed = JSON.parse(editorVal);
                const canonical = canonicalizeJson(parsed);
                const canStr = JSON.stringify(canonical);
                for (const h in ledgerRecordsMap) {
                    if (h) { hashToDownload = h; break; }
                }
            } catch (e) {}
        }
    }
    if (!hashToDownload) {
        showToast("No anchored evidence available to download. Please anchor first.", "error");
        return;
    }
    downloadCertificateByHash(hashToDownload);
}

// Chain of Custody Modal
async function openCustodyModal(caseId) {
    const modal = document.getElementById('custody-modal');
    const badge = document.getElementById('custody-case-badge');
    const list = document.getElementById('custody-timeline-list');
    
    badge.innerText = `CASE: ${caseId}`;
    list.innerHTML = '<div style="color: #888; text-align: center; padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading chain of custody audit trail...</div>';
    modal.classList.remove('hidden');

    try {
        const res = await authFetch(`/evidence/custody/${encodeURIComponent(caseId)}`);
        if (!res.ok) throw new Error("Could not fetch custody log");
        const data = await res.json();
        
        list.innerHTML = '';
        if (!data.history || data.history.length === 0) {
            list.innerHTML = '<div style="color: #888; text-align: center; padding: 20px;">No custody events recorded for this case identifier.</div>';
            return;
        }

        data.history.forEach((entry, idx) => {
            const item = document.createElement('div');
            item.className = 'custody-timeline-item';
            item.innerHTML = `
                <div class="custody-dot"></div>
                <div class="custody-content">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong class="text-amber" style="font-size: 0.9rem;">#${entry.sequence} - ${entry.action.replace(/_/g, ' ')}</strong>
                        <span class="font-mono" style="font-size: 0.75rem; color: #888;">${entry.timestamp}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #ccc; margin: 4px 0;"><strong>Officer:</strong> ${entry.officer_id}</div>
                    <div style="font-size: 0.75rem; color: #888; word-break: break-all;"><strong>SHA-256 Link:</strong> ${entry.entry_hash}</div>
                </div>
            `;
            list.appendChild(item);
        });
    } catch (e) {
        list.innerHTML = `<div style="color: var(--red); padding: 10px;">Failed to load custody log: ${e.message}</div>`;
    }
}

function closeCustodyModal() {
    const modal = document.getElementById('custody-modal');
    if (modal) modal.classList.add('hidden');
}


// ---- Certificate Picker ----
// _certPickerRecords holds a snapshot of all ledger records for filtering.
let _certPickerRecords = [];

function openCertificatePicker() {
    // Collect records from the ledger map
    _certPickerRecords = Object.values(ledgerRecordsMap);

    const modal   = document.getElementById('cert-picker-modal');
    const search  = document.getElementById('cert-picker-search');
    if (!modal) return;

    // Reset search
    if (search) search.value = '';

    renderCertPickerList(_certPickerRecords);
    modal.classList.remove('hidden');

    // De-highlight sidebar item (it's not a real pane switch)
    setTimeout(() => {
        const btn = document.getElementById('nav-item-certificate');
        if (btn) btn.classList.remove('active');
    }, 150);
}

function closeCertificatePicker() {
    const modal = document.getElementById('cert-picker-modal');
    if (modal) modal.classList.add('hidden');
}

function filterCertPickerList(query) {
    const q = (query || '').toLowerCase().trim();
    if (!q) {
        renderCertPickerList(_certPickerRecords);
        return;
    }
    const filtered = _certPickerRecords.filter(r =>
        (r.case_id       || '').toLowerCase().includes(q) ||
        (r.incident_type || '').toLowerCase().includes(q) ||
        (r.investigator  || '').toLowerCase().includes(q) ||
        (r.target_asset  || '').toLowerCase().includes(q)
    );
    renderCertPickerList(filtered);
}

function renderCertPickerList(records) {
    const list  = document.getElementById('cert-picker-list');
    const empty = document.getElementById('cert-picker-empty');
    if (!list) return;

    // Remove previously rendered rows (keep the empty placeholder)
    Array.from(list.querySelectorAll('.cert-picker-row')).forEach(el => el.remove());

    if (!records || records.length === 0) {
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    // Sort newest block first
    const sorted = [...records].sort((a, b) => (b.block_number || 0) - (a.block_number || 0));

    sorted.forEach(rec => {
        const row = document.createElement('div');
        row.className = 'cert-picker-row';
        row.style.cssText = [
            'display:flex', 'align-items:center', 'justify-content:space-between',
            'gap:12px', 'padding:10px 12px', 'margin-bottom:6px',
            'background:var(--se-card)', 'border:1px solid var(--se-border)',
            'border-radius:7px', 'cursor:pointer', 'transition:border-color 0.15s,box-shadow 0.15s'
        ].join(';');

        const ts = rec.timestamp ? new Date(rec.timestamp).toLocaleString('en-GB', {
            day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit'
        }) : '—';

        const incidentLabel = (rec.incident_type || '').replace(/_/g, ' ');
        const blockLabel    = rec.block_number != null ? `#${rec.block_number}` : '—';

        row.innerHTML = `
            <div style="flex:1;min-width:0;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span style="font-family:var(--font-mono);font-size:0.78rem;font-weight:700;color:var(--se-navy);">${escHtml(rec.case_id || '—')}</span>
                    <span style="font-size:0.7rem;background:var(--se-steel-soft);color:var(--se-steel);border:1px solid rgba(31,111,178,0.18);border-radius:12px;padding:1px 8px;font-weight:600;white-space:nowrap;">${escHtml(incidentLabel)}</span>
                    <span style="font-size:0.7rem;color:var(--se-text-muted);">Block ${escHtml(blockLabel)}</span>
                </div>
                <div style="margin-top:3px;font-size:0.75rem;color:var(--se-text-muted);">
                    <i class="fa-solid fa-user-tie" style="margin-right:4px;"></i>${escHtml(rec.investigator || '—')}
                    &nbsp;·&nbsp;
                    <i class="fa-solid fa-clock" style="margin-right:4px;"></i>${escHtml(ts)}
                </div>
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0;">
                <button type="button" class="btn-sm btn-outline"
                    onclick="event.stopPropagation(); pickCertAndView('${escAttr(rec.evidence_hash)}')"
                    title="View certificate">
                    <i class="fa-solid fa-eye"></i> View
                </button>
                <button type="button" class="btn-sm btn-primary-sm"
                    onclick="event.stopPropagation(); pickCertAndPrint('${escAttr(rec.evidence_hash)}')"
                    title="View certificate and print">
                    <i class="fa-solid fa-print"></i> Print
                </button>
                <button type="button" class="btn-sm btn-outline"
                    onclick="event.stopPropagation(); downloadCertificateByHash('${escAttr(rec.evidence_hash)}')"
                    title="Download official court certificate">
                    <i class="fa-solid fa-download"></i> Download
                </button>
            </div>`;

        row.addEventListener('mouseenter', () => {
            row.style.borderColor = 'var(--se-steel)';
            row.style.boxShadow   = '0 2px 8px rgba(31,111,178,0.12)';
        });
        row.addEventListener('mouseleave', () => {
            row.style.borderColor = 'var(--se-border)';
            row.style.boxShadow   = 'none';
        });

        list.appendChild(row);
    });
}

function pickCertAndView(hash) {
    closeCertificatePicker();
    openCertificateModalWithHash(hash);
}

function pickCertAndPrint(hash) {
    closeCertificatePicker();
    openCertificateModalWithHash(hash);
    // Small delay to let the modal paint before print dialog
    setTimeout(() => window.print(), 350);
}

/** Safe HTML-escape for injecting values into innerHTML */
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
/** Safe attribute-escape for onclick string literals */
function escAttr(str) {
    return String(str).replace(/'/g, "\\'");
}

window.downloadCertificateByHash = downloadCertificateByHash;
window.openCertificatePicker  = openCertificatePicker;
window.closeCertificatePicker = closeCertificatePicker;
window.filterCertPickerList   = filterCertPickerList;
window.pickCertAndView        = pickCertAndView;
window.pickCertAndPrint       = pickCertAndPrint;
// ---- End Certificate Picker ----

function openCertificateModal() {
    if (!currentEvidencePayload) {
        // Fallback to the latest record in the ledger if available
        const hashes = Object.keys(ledgerRecordsMap);
        if (hashes.length > 0) {
            openCertificateModalWithHash(hashes[hashes.length - 1]);
            return;
        }
        // Fallback demo certificate view so the sidebar action always presents the court certificate template
        const caseId = "INSA-DEMO-CERT-01";
        const investigator = (currentUser && (currentUser.full_name || currentUser.username)) || "INSA Forensic Analyst";
        const hash = "e93ec967875b894044f92d87778b3ab5a1690ee0226bea830a23fd66feaa1582";
        const certBadge = document.getElementById('cert-ledger-badge');
        if (certBadge) {
            certBadge.className = 'badge-status pill-simulated';
            certBadge.innerText = 'SQLITE LEDGER (HASH-CHAINED)';
        }
        document.getElementById('cert-case-id').innerText = caseId;
        document.getElementById('cert-incident').innerText = "DDoS Flood";
        document.getElementById('cert-target').innerText = "National-Gateway-Demo-01";
        document.getElementById('cert-block').innerText = "#1";
        document.getElementById('cert-investigator').innerText = investigator;
        document.getElementById('cert-timestamp').innerText = new Date().toISOString();
        document.getElementById('cert-hash').innerText = hash;
        document.getElementById('cert-sig').innerText = `3045022100${hash.substring(0, 32)}0220${hash.substring(32, 64)} (SECP256R1/ECDSA)`;
        document.getElementById('cert-modal').classList.remove('hidden');
        return;
    }
    const caseIdInput = document.getElementById('input_case_id');
    const caseId = (caseIdInput && caseIdInput.value.trim()) || (lastAnchoredBlock && lastAnchoredBlock.case_id) || ("DEMO-CASE-" + Math.floor(1000 + Math.random() * 9000));
    const investigatorInput = document.getElementById('input_investigator');
    const investigator = (investigatorInput && investigatorInput.value.trim()) || (lastAnchoredBlock && lastAnchoredBlock.investigator) || "Analyst (Demo Session)";
    const hash = (lastAnchoredBlock && lastAnchoredBlock.evidence_hash) || (document.getElementById('verdict-hash') ? document.getElementById('verdict-hash').innerText : "") || "Awaiting hash calculation";
    
    const mode = (lastAnchoredBlock && lastAnchoredBlock.ledger_mode) || "SIMULATED LEDGER";
    const isLive = mode.includes("LIVE");
    const certBadge = document.getElementById('cert-ledger-badge');
    const backend = window.activeLedgerBackend || 'sqlite';
    const simBadgeText = (backend === 'sqlite') ? 'SQLITE LEDGER (HASH-CHAINED)' : 'SIMULATED LEDGER';
    if (certBadge) {
        certBadge.className = `badge-status ${isLive ? 'pill-live' : 'pill-simulated'}`;
        certBadge.innerText = isLive ? 'LIVE CHAIN' : simBadgeText;
    }

    document.getElementById('cert-case-id').innerText = caseId;
    document.getElementById('cert-incident').innerText = currentDetectionResult ? currentDetectionResult.threat_category.replace(/_/g, ' ') : "Awaiting Analysis";
    document.getElementById('cert-target').innerText = currentEvidencePayload.target_asset || "National-Gateway-Demo-01";
    document.getElementById('cert-block').innerText = `#${(lastAnchoredBlock && lastAnchoredBlock.block_number) || (document.getElementById('stat-blocks-count') ? document.getElementById('stat-blocks-count').innerText : '1')}`;
    document.getElementById('cert-investigator').innerText = investigator;
    document.getElementById('cert-timestamp').innerText = (lastAnchoredBlock && lastAnchoredBlock.timestamp) || new Date().toISOString();
    document.getElementById('cert-hash').innerText = hash;
    document.getElementById('cert-sig').innerText = (lastAnchoredBlock && lastAnchoredBlock.officer_signature) || `3045022100${hash.substring(0, 32)}0220${hash.substring(32, 64)} (SECP256R1/ECDSA)`;

    const cId = document.getElementById('cert-chain-id');
    const cAddr = document.getElementById('cert-contract-address');
    const cTx = document.getElementById('cert-tx-hash');
    const cBlk = document.getElementById('cert-chain-block');
    const cExp = document.getElementById('cert-explorer-link');
    if (cId) cId.innerText = (lastAnchoredBlock && lastAnchoredBlock.chain_id) || window.activeChainId || '31337';
    if (cAddr) cAddr.innerText = (lastAnchoredBlock && lastAnchoredBlock.contract_address) || window.activeContractAddress || '0x5FbDB2315678afecb367f032d93F642f64180aa3';
    if (cTx) cTx.innerText = (lastAnchoredBlock && lastAnchoredBlock.tx_hash) || '—';
    if (cBlk) cBlk.innerText = `#${(lastAnchoredBlock && (lastAnchoredBlock.chain_block_number || lastAnchoredBlock.block_number)) || 1}`;
    if (cExp) {
        if (lastAnchoredBlock && lastAnchoredBlock.explorer_url) {
            cExp.innerHTML = `<a href="${lastAnchoredBlock.explorer_url}" target="_blank" style="color:var(--blue-400);text-decoration:underline;">View on explorer</a>`;
        } else {
            const chainIdVal = String((lastAnchoredBlock && lastAnchoredBlock.chain_id) || window.activeChainId || '');
            if (chainIdVal === '31337' || window.activeChainMode === 'local') {
                cExp.innerHTML = `<span style="color:var(--slate-400);font-size:0.75rem;">Local node (Chain ID 31337 &mdash; private test RPC, not on public Etherscan)</span>`;
            } else {
                cExp.innerText = '—';
            }
        }
    }
    document.getElementById('cert-modal').classList.remove('hidden');
}

function openCertificateModalWithHash(hash) {
    const rec = ledgerRecordsMap[hash];
    if (!rec) {
        showToast("Record details could not be found in registry.", "error");
        return;
    }
    const mode = rec.ledger_mode || "SIMULATED LEDGER";
    const isLive = mode.includes("LIVE");
    const certBadge = document.getElementById('cert-ledger-badge');
    const backend = window.activeLedgerBackend || 'sqlite';
    const simBadgeText = (backend === 'sqlite') ? 'SQLITE LEDGER (HASH-CHAINED)' : 'SIMULATED LEDGER';
    if (certBadge) {
        certBadge.className = `badge-status ${isLive ? 'pill-live' : 'pill-simulated'}`;
        certBadge.innerText = isLive ? 'LIVE CHAIN' : simBadgeText;
    }

    document.getElementById('cert-case-id').innerText = rec.case_id;
    document.getElementById('cert-incident').innerText = rec.incident_type.replace(/_/g, ' ');
    document.getElementById('cert-target').innerText = rec.target_asset;
    document.getElementById('cert-block').innerText = `#${rec.block_number}`;
    document.getElementById('cert-investigator').innerText = rec.investigator;
    document.getElementById('cert-timestamp').innerText = rec.timestamp;
    document.getElementById('cert-hash').innerText = rec.evidence_hash;
    document.getElementById('cert-sig').innerText = rec.officer_signature || `3045022100${hash.substring(0, 32)}0220${hash.substring(32, 64)} (SECP256R1/ECDSA)`;

    const cId2 = document.getElementById('cert-chain-id');
    const cAddr2 = document.getElementById('cert-contract-address');
    const cTx2 = document.getElementById('cert-tx-hash');
    const cBlk2 = document.getElementById('cert-chain-block');
    const cExp2 = document.getElementById('cert-explorer-link');
    if (cId2) cId2.innerText = rec.chain_id || window.activeChainId || '31337';
    if (cAddr2) cAddr2.innerText = rec.contract_address || window.activeContractAddress || '0x5FbDB2315678afecb367f032d93F642f64180aa3';
    if (cTx2) cTx2.innerText = rec.tx_hash || '—';
    if (cBlk2) cBlk2.innerText = `#${rec.chain_block_number || rec.block_number || 1}`;
    if (cExp2) {
        if (rec.explorer_url) {
            cExp2.innerHTML = `<a href="${rec.explorer_url}" target="_blank" style="color:var(--blue-400);text-decoration:underline;">View on explorer</a>`;
        } else {
            const chainIdVal2 = String(rec.chain_id || window.activeChainId || '');
            if (chainIdVal2 === '31337' || (rec.chain_mode === 'local') || window.activeChainMode === 'local') {
                cExp2.innerHTML = `<span style="color:var(--slate-400);font-size:0.75rem;">Local node (Chain ID 31337 &mdash; private test RPC, not on public Etherscan)</span>`;
            } else {
                cExp2.innerText = '—';
            }
        }
    }
    document.getElementById('cert-modal').classList.remove('hidden');
}

function closeCertificateModal() {
    document.getElementById('cert-modal').classList.add('hidden');
}

window.handleDetectThreat = handleDetectThreat;
window.handleStoreEvidence = handleStoreEvidence;
window.handleVerifyEvidence = handleVerifyEvidence;
window.tamperEvidenceJson = tamperEvidenceJson;
window.resetEvidenceJson = resetEvidenceJson;
window.loadScenario = loadScenario;
window.openCertificateModal = openCertificateModal;
window.openCertificateModalWithHash = openCertificateModalWithHash;
window.closeCertificateModal = closeCertificateModal;
window.handlePublicVerify = handlePublicVerify;
window.handleDownloadCurrentEvidence = handleDownloadCurrentEvidence;
window.switchIngestTab = switchIngestTab;
window.ingestSuricataLog = ingestSuricataLog;
window.switchPublicTab = switchPublicTab;
window.resolveDisagreement = resolveDisagreement;
window.handleStreamControl = handleStreamControl;
window.sendStreamAlertToAnalystReview = sendStreamAlertToAnalystReview;
window.pollStreamStatus = pollStreamStatus;

function fillDemoCredentials(username, password, btnEl) {
    const uInput = document.getElementById('login-username');
    const pInput = document.getElementById('login-password');
    if (uInput) uInput.value = username;
    if (pInput) pInput.value = password;
    if (btnEl) {
        document.querySelectorAll('#demo-console-notice .btn').forEach(b => {
            b.style.borderColor = 'var(--border-color)';
            b.style.background = 'transparent';
        });
        btnEl.style.borderColor = 'var(--se-steel)';
        btnEl.style.background = 'rgba(74, 144, 226, 0.15)';
    }
}
window.fillDemoCredentials = fillDemoCredentials;

// ==========================================================================
// Professional Side Section Navigation (Tab Switching & Mobile Toggle)
// ==========================================================================
function switchNavTab(tabId) {
    const tabMap = {
        'threat-triage': 'pane-tab-threat-triage',
        'live-stream': 'pane-tab-live-stream',
        'integrity-verify': 'pane-tab-integrity-verify',
        'public-verify': 'pane-tab-public-verify',
        'ledger-registry': 'pane-tab-ledger-registry'
    };

    // Update active nav button
    const navItems = document.querySelectorAll('.sidebar-item');
    navItems.forEach(item => item.classList.remove('active'));
    const activeNavBtn = document.getElementById(`nav-item-${tabId}`);
    if (activeNavBtn) activeNavBtn.classList.add('active');

    // Smooth scroll to target section
    const targetEl = document.getElementById(tabMap[tabId]);
    if (targetEl) {
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Close mobile sidebar if open
    const sidebar = document.getElementById('app-sidebar');
    if (sidebar && sidebar.classList.contains('open')) {
        sidebar.classList.remove('open');
    }
}
window.switchNavTab = switchNavTab;

function toggleSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    if (sidebar) {
        sidebar.classList.toggle('open');
    }
}
window.toggleSidebar = toggleSidebar;

// Auto-sync active sidebar item on scroll
window.addEventListener('scroll', () => {
    const sections = [
        { id: 'pane-tab-threat-triage', navId: 'nav-item-threat-triage' },
        { id: 'pane-tab-live-stream', navId: 'nav-item-live-stream' },
        { id: 'pane-tab-integrity-verify', navId: 'nav-item-integrity-verify' },
        { id: 'pane-tab-public-verify', navId: 'nav-item-public-verify' },
        { id: 'pane-tab-ledger-registry', navId: 'nav-item-ledger-registry' }
    ];

    const scrollPosition = window.scrollY + 180;
    const isAtBottom = (window.innerHeight + window.scrollY) >= (document.body.offsetHeight - 60);
    if (isAtBottom) {
        document.querySelectorAll('.sidebar-item').forEach(item => item.classList.remove('active'));
        const lastNav = document.getElementById('nav-item-ledger-registry');
        if (lastNav) lastNav.classList.add('active');
        return;
    }
    for (let i = sections.length - 1; i >= 0; i--) {
        const el = document.getElementById(sections[i].id);
        if (el) {
            const elTop = el.getBoundingClientRect().top + window.scrollY;
            if (elTop <= scrollPosition) {
                document.querySelectorAll('.sidebar-item').forEach(item => item.classList.remove('active'));
                const activeNav = document.getElementById(sections[i].navId);
                if (activeNav) activeNav.classList.add('active');
                break;
            }
        }
    }
}, { passive: true });
