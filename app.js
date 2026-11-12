
// ========================================
// MY EXPENSE TRACKER - INCOME + EXPENSES
// ========================================

const STORAGE_KEY = "myExpenseTracker_transactions";
const BUDGET_KEY = "myExpenseTracker_budgets";
const SECURE_STORAGE_KEY = "myExpenseTracker_encrypted_v1";
const SECURITY_SETTINGS_KEY = "myExpenseTracker_security_settings_v1";

// Financial data stays in memory only after the user unlocks the app.
let transactions = [];
let budgets = {};
let categoryBudgets = {};
let recurringRules = [];
let saveQueue = Promise.resolve();
let encryptionKey = null;
let securitySettings = null;
let inactivityTimer = null;
let lastActivity = Date.now();
let patternSequence = [];
let pendingPattern = null;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
    let binary = "";
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary);
}

function base64ToBytes(value) {
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

async function deriveEncryptionKey(secret, salt) {
    const material = await crypto.subtle.importKey(
        "raw", encoder.encode(secret), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptPayload(payload, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(payload))
    );
    return { format: "MET-ENCRYPTED-1", iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptPayload(envelope, key) {
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
        key,
        base64ToBytes(envelope.data)
    );
    return JSON.parse(decoder.decode(plaintext));
}

async function saveData() {
    if (!encryptionKey) throw new Error("The app is locked. Unlock before saving.");
    // Snapshot the complete encrypted payload immediately, then serialize writes.
    // This prevents overlapping async saves from replacing newer rules with an older snapshot.
    const keyForSave = encryptionKey;
    const payloadSnapshot = JSON.parse(JSON.stringify({
        transactions, budgets, categoryBudgets, recurringRules
    }));
    const write = async () => {
        if (!encryptionKey || encryptionKey !== keyForSave) throw new Error("The app was locked before the save completed. Unlock and try again.");
        const existing = JSON.parse(localStorage.getItem(SECURE_STORAGE_KEY) || "null");
        if (!existing?.salt) throw new Error("Encryption metadata is missing. Do not clear browser data.");
        const envelope = await encryptPayload(payloadSnapshot, keyForSave);
        localStorage.setItem(SECURE_STORAGE_KEY, JSON.stringify({ ...envelope, salt: existing.salt }));
        // Verify that the stored envelope can be decrypted and contains the expected rule list.
        const verified = await decryptPayload(JSON.parse(localStorage.getItem(SECURE_STORAGE_KEY)), keyForSave);
        if (!Array.isArray(verified.recurringRules) || verified.recurringRules.length !== payloadSnapshot.recurringRules.length) {
            throw new Error("Save verification failed. Your latest recurring rules were not confirmed.");
        }
    };
    const pending = saveQueue.then(write, write);
    saveQueue = pending.catch(() => {});
    return pending;
}

function normalizeTransactions(items) {
    return items.map(item => ({ ...item, type: item.type || "expense" }));
}

function securityOverlay() {
    let overlay = document.getElementById("securityOverlay");
    if (overlay) return overlay;
    overlay = document.createElement("div");
    overlay.id = "securityOverlay";
    overlay.className = "security-overlay";
    overlay.innerHTML = `
      <section class="security-panel" aria-live="polite">
        <div class="security-mark">₹</div>
        <p class="security-eyebrow">MY EXPENSE TRACKER</p>
        <h1 id="securityTitle">Secure your records</h1>
        <p id="securityMessage" class="security-message">Choose how you want to protect your financial records.</p>
        <div id="securitySetupFields">
          <label for="lockMethod">Lock type</label>
          <select id="lockMethod"><option value="pin">PIN</option><option value="pattern">Pattern</option><option value="password">Password</option></select>
          <label for="lockTiming">Automatically lock</label>
          <select id="lockTiming">
            <option value="0">Every time the app is reopened</option>
            <option value="1">After 1 minute of inactivity</option>
            <option value="5">After 5 minutes of inactivity</option>
            <option value="10">After 10 minutes of inactivity</option>
            <option value="30">After 30 minutes of inactivity</option>
            <option value="never">Never automatically</option>
          </select>
          <div id="credentialFields"></div>
        </div>
        <div id="securityUnlockFields" hidden>
          <div id="unlockCredential"></div>
        </div>
        <p id="patternHint" class="security-hint" hidden>Connect at least 4 dots in sequence. Select the same sequence again to confirm.</p>
        <div id="securityError" class="security-error" role="alert"></div>
        <button id="securityPrimary" class="security-primary" type="button">Protect my records</button>
        <button id="securityCancel" class="security-cancel" type="button" hidden>Cancel</button>
        <p class="security-footnote">Your records are encrypted on this device using AES-GCM. If you forget your credential, it cannot be reset to recover encrypted data. Keep a secure backup.</p>
      </section>`;
    document.body.appendChild(overlay);
    return overlay;
}

function makePatternPad(target, onChange) {
    let sequence = [];
    let drawing = false;
    target.innerHTML = '<div class="pattern-pad" aria-label="Draw an unlock pattern">' +
        Array.from({length:9}, (_,i) => `<button type="button" class="pattern-dot" data-dot="${i+1}" aria-label="Pattern dot ${i+1}"></button>`).join('') +
        '</div><p class="pattern-readout" aria-live="polite">Draw a pattern by connecting dots</p><button type="button" class="pattern-clear">Clear pattern</button>';
    const pad = target.querySelector('.pattern-pad');
    const readout = target.querySelector('.pattern-readout');
    const update = () => {
        readout.textContent = sequence.length ? `Selected: ${sequence.join(' – ')}` : 'Draw a pattern by connecting dots';
        onChange(sequence.join('-'));
    };
    const addDot = element => {
        const dot = Number(element?.closest?.('[data-dot]')?.dataset.dot);
        if (dot && !sequence.includes(dot)) {
            sequence.push(dot);
            pad.querySelector(`[data-dot="${dot}"]`)?.classList.add('selected');
            update();
        }
    };
    pad.addEventListener('pointerdown', event => {
        const dot = event.target.closest('[data-dot]');
        if (!dot) return;
        event.preventDefault();
        sequence = [];
        pad.querySelectorAll('.pattern-dot').forEach(button => button.classList.remove('selected'));
        drawing = true;
        addDot(dot);
        pad.setPointerCapture?.(event.pointerId);
    });
    pad.addEventListener('pointermove', event => {
        if (!drawing) return;
        addDot(document.elementFromPoint(event.clientX, event.clientY));
    });
    const finish = () => { drawing = false; };
    pad.addEventListener('pointerup', finish);
    pad.addEventListener('pointercancel', finish);
    // Keyboard/tap accessibility: focus a dot and press Enter/Space to add it.
    pad.querySelectorAll('[data-dot]').forEach(button => button.addEventListener('click', () => {
        if (drawing) return;
        addDot(button);
    }));
    target.querySelector('.pattern-clear').addEventListener('click', () => {
        sequence = [];
        pad.querySelectorAll('.pattern-dot').forEach(button => button.classList.remove('selected'));
        update();
    });
}

function getCredentialValue(method, host) {
    if (method === 'pattern') return host.dataset.pattern || '';
    return host.querySelector('input')?.value || '';
}

function renderCredentialField(container, method, label, patternCallback) {
    container.innerHTML = '';
    if (method === 'pattern') {
        const wrapper = document.createElement('div');
        container.appendChild(wrapper);
        makePatternPad(wrapper, patternCallback);
        return;
    }
    const input = document.createElement('input');
    input.type = method === 'password' ? 'password' : 'password';
    input.inputMode = method === 'pin' ? 'numeric' : 'text';
    input.autocomplete = 'new-password';
    input.placeholder = method === 'pin' ? 'Enter a 6-digit PIN' : method === 'password' ? 'At least 12 characters recommended' : 'Enter PIN';
    input.maxLength = method === 'pin' ? 12 : 128;
    input.setAttribute('aria-label', label);
    container.appendChild(input);
}

function showSecurityError(message) {
    const node = document.getElementById('securityError');
    if (node) node.textContent = message || '';
}

function validateCredential(method, value) {
    if (method === 'pin') return /^\d{6,12}$/.test(value) ? '' : 'Use a PIN containing 6 to 12 digits.';
    if (method === 'pattern') return value.split('-').length >= 4 ? '' : 'Your pattern must connect at least 4 different dots.';
    return value.length >= 10 ? '' : 'Use a password with at least 10 characters.';
}

async function setupSecurity(isChange = false) {
    const overlay = securityOverlay();
    document.getElementById('securityTitle').textContent = isChange ? 'Change security settings' : 'Secure your records';
    document.getElementById('securityMessage').textContent = 'Choose your lock type and when the app should lock.';
    const setup = document.getElementById('securitySetupFields');
    const unlock = document.getElementById('securityUnlockFields');
    setup.hidden = false; unlock.hidden = true;
    const methodSelect = document.getElementById('lockMethod');
    const timingSelect = document.getElementById('lockTiming');
    if (isChange && securitySettings) {
        methodSelect.value = securitySettings.method;
        timingSelect.value = String(securitySettings.timing);
    }
    const fields = document.getElementById('credentialFields');
    const hint = document.getElementById('patternHint');
    const button = document.getElementById('securityPrimary');
    const cancelButton = document.getElementById('securityCancel');
    cancelButton.hidden = !isChange;
    cancelButton.onclick = () => overlay.remove();
    const render = () => {
        patternSequence = [];
        const method = methodSelect.value;
        hint.hidden = method !== 'pattern';
        fields.innerHTML = '<label>Create your ' + (method === 'pin' ? 'PIN' : method) + '</label><div id="credentialOne"></div><label>Confirm your ' + (method === 'pin' ? 'PIN' : method) + '</label><div id="credentialTwo"></div>';
        renderCredentialField(fields.querySelector('#credentialOne'), method, 'Create credential', value => { fields.querySelector('#credentialOne').dataset.pattern = value; });
        renderCredentialField(fields.querySelector('#credentialTwo'), method, 'Confirm credential', value => { fields.querySelector('#credentialTwo').dataset.pattern = value; });
    };
    methodSelect.addEventListener('change', render);
    render();
    button.textContent = isChange ? 'Save security settings' : 'Protect my records';
    button.onclick = async () => {
        try {
            const method = methodSelect.value;
            const firstHost = fields.querySelector('#credentialOne');
            const secondHost = fields.querySelector('#credentialTwo');
            const first = method === 'pattern' ? firstHost.dataset.pattern || '' : getCredentialValue(method, firstHost);
            const second = method === 'pattern' ? secondHost.dataset.pattern || '' : getCredentialValue(method, secondHost);
            const validation = validateCredential(method, first);
            if (validation) throw new Error(validation);
            if (first !== second) throw new Error('The two credentials do not match. Please try again.');
            // When changing the lock credential, preserve every existing encrypted data collection.
            // Only first-time setup migrates the legacy plaintext transaction/budget keys.
            const legacyTransactions = isChange ? transactions : JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
            const legacyBudgets = isChange ? budgets : JSON.parse(localStorage.getItem(BUDGET_KEY) || '{}');
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const key = await deriveEncryptionKey(first, salt);
            const initialData = {
                transactions: normalizeTransactions(legacyTransactions),
                budgets: legacyBudgets,
                categoryBudgets: isChange ? (categoryBudgets || {}) : {},
                recurringRules: isChange ? (Array.isArray(recurringRules) ? recurringRules : []) : []
            };
            const envelope = await encryptPayload(initialData, key);
            // Verify the encrypted payload before replacing or removing old records.
            await decryptPayload(envelope, key);
            localStorage.setItem(SECURE_STORAGE_KEY, JSON.stringify({ ...envelope, salt: bytesToBase64(salt) }));
            const settings = { method, timing: timingSelect.value, version: 1 };
            localStorage.setItem(SECURITY_SETTINGS_KEY, JSON.stringify(settings));
            encryptionKey = key; securitySettings = settings;
            transactions = initialData.transactions; budgets = initialData.budgets; categoryBudgets = initialData.categoryBudgets; recurringRules = initialData.recurringRules;
            localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(BUDGET_KEY);
            overlay.remove();
            renderApp(); startSecurityMonitoring();
        } catch (error) { showSecurityError(error.message || 'Could not secure your records.'); }
    };
}

async function unlockSecurity() {
    const overlay = securityOverlay();
    const settings = JSON.parse(localStorage.getItem(SECURITY_SETTINGS_KEY) || 'null');
    const envelope = JSON.parse(localStorage.getItem(SECURE_STORAGE_KEY) || 'null');
    if (!settings || !envelope) throw new Error('Security data is incomplete. Restore from a backup or contact support.');
    securitySettings = settings;
    document.getElementById('securityTitle').textContent = 'Unlock your records';
    document.getElementById('securityMessage').textContent = 'Enter your ' + settings.method + ' to access your financial records.';
    document.getElementById('securitySetupFields').hidden = true;
    const unlock = document.getElementById('securityUnlockFields'); unlock.hidden = false;
    const host = document.getElementById('unlockCredential');
    host.innerHTML = '';
    if (settings.method === 'pattern') {
        patternSequence = [];
        makePatternPad(host, value => { host.dataset.pattern = value; });
        document.getElementById('patternHint').hidden = false;
    } else {
        const input = document.createElement('input');
        input.type = 'password'; input.autocomplete = 'current-password';
        input.inputMode = settings.method === 'pin' ? 'numeric' : 'text';
        input.placeholder = settings.method === 'pin' ? 'Enter your PIN' : 'Enter your password';
        host.appendChild(input); document.getElementById('patternHint').hidden = true;
    }
    const button = document.getElementById('securityPrimary'); button.textContent = 'Unlock';
    const ATTEMPTS_KEY = "myExpenseTracker_failed_unlocks_v1";
    const LOCK_UNTIL_KEY = "myExpenseTracker_unlock_lock_until_v1";
    const updateCooldown = () => {
        const until = Number(localStorage.getItem(LOCK_UNTIL_KEY) || 0);
        const remaining = Math.ceil((until - Date.now()) / 1000);
        button.disabled = remaining > 0;
        button.textContent = remaining > 0 ? `Try again in ${remaining}s` : 'Unlock';
        if (remaining > 0) setTimeout(updateCooldown, 250);
    };
    updateCooldown();
    button.onclick = async () => {
        if (Number(localStorage.getItem(LOCK_UNTIL_KEY) || 0) > Date.now()) { updateCooldown(); return; }
        try {
            const secret = settings.method === 'pattern' ? host.dataset.pattern || '' : host.querySelector('input').value;
            if (!secret) throw new Error('Enter your unlock credential.');
            const key = await deriveEncryptionKey(secret, base64ToBytes(envelope.salt));
            const data = await decryptPayload(envelope, key);
            if (!Array.isArray(data.transactions) || !data.budgets || typeof data.budgets !== 'object') throw new Error('Encrypted data format is invalid.');
            encryptionKey = key; transactions = normalizeTransactions(data.transactions); budgets = data.budgets; categoryBudgets = data.categoryBudgets && typeof data.categoryBudgets === "object" ? data.categoryBudgets : {}; recurringRules = Array.isArray(data.recurringRules) ? data.recurringRules.filter(rule => rule && rule.id && rule.startDate && ["weekly", "monthly", "yearly"].includes(rule.frequency)) : [];
            localStorage.removeItem(ATTEMPTS_KEY); localStorage.removeItem(LOCK_UNTIL_KEY);
            await processRecurringTransactions();
            overlay.remove(); renderApp(); startSecurityMonitoring();
        } catch (error) {
            const attempts = Number(localStorage.getItem(ATTEMPTS_KEY) || 0) + 1;
            if (attempts >= 3) {
                localStorage.setItem(ATTEMPTS_KEY, "0");
                localStorage.setItem(LOCK_UNTIL_KEY, String(Date.now() + 30000));
                showSecurityError('Too many incorrect attempts. Please wait 30 seconds.');
                updateCooldown();
            } else {
                localStorage.setItem(ATTEMPTS_KEY, String(attempts));
                showSecurityError(`Incorrect credential. ${3 - attempts} attempt(s) remaining before a 30-second lock.`);
            }
        }
    };
}

function lockApp() {
    if (!encryptionKey || !securitySettings) return;
    encryptionKey = null; transactions = []; budgets = {}; categoryBudgets = {}; recurringRules = [];
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    window.__metActivityReset = null;
    unlockSecurity().catch(error => alert(error.message));
}

function startSecurityMonitoring() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    const reset = () => {
        if (!encryptionKey || !securitySettings) return;
        lastActivity = Date.now();
        if (inactivityTimer) clearTimeout(inactivityTimer);
        const minutes = securitySettings.timing;
        if (minutes === 'never' || minutes === '0' || minutes === 0) return;
        const timeout = Number(minutes) * 60 * 1000;
        if (Number.isFinite(timeout) && timeout > 0) inactivityTimer = setTimeout(lockApp, timeout);
    };
    window.__metActivityReset = reset;
    if (!window.__metActivityListeners) {
        ['pointerdown', 'keydown', 'touchstart', 'click'].forEach(eventName =>
            document.addEventListener(eventName, () => window.__metActivityReset?.(), { passive: true })
        );
        document.addEventListener('visibilitychange', () => {
            if (!encryptionKey || !securitySettings) return;
            const timing = securitySettings.timing;
            if (document.hidden && (timing === '0' || timing === 0)) {
                lockApp();
                return;
            }
            if (!document.hidden && timing !== 'never' && timing !== '0' && timing !== 0) {
                const limit = Number(timing) * 60 * 1000;
                if (Date.now() - lastActivity >= limit) lockApp();
                else window.__metActivityReset?.();
            }
        });
        window.addEventListener('pagehide', () => {
            if (securitySettings?.timing === '0' && encryptionKey) lockApp();
        });
        window.__metActivityListeners = true;
    }
    reset();
}

const securitySettingsButton = document.getElementById("securitySettingsBtn");
if (securitySettingsButton) {
    securitySettingsButton.addEventListener("click", () => {
        if (!encryptionKey) return;
        setupSecurity(true).catch(error => showSecurityError(error.message));
    });
}

async function initializeSecureApp() {
    if (!window.crypto?.subtle) {
        alert('This browser does not support the encryption required by My Expense Tracker. Please use the HTTPS published app or a modern browser.');
        return;
    }
    if (localStorage.getItem(SECURE_STORAGE_KEY)) await unlockSecurity();
    else await setupSecurity();
}

const totalIncome = document.getElementById("totalIncome");
const totalExpenses = document.getElementById("totalExpenses");
const monthlySavings = document.getElementById("monthlySavings");
const monthlyBudget = document.getElementById("monthlyBudget");
const remainingBudget = document.getElementById("remainingBudget");

const transactionList = document.getElementById("transactionList");
const currentMonth = document.getElementById("currentMonth");
const budgetInput = document.getElementById("budgetInput");

const addExpenseBtn = document.getElementById("addExpenseBtn");
const saveBudgetBtn = document.getElementById("saveBudgetBtn");

const today = new Date();

function getLocalDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");

    return `${year}-${month}-${day}`;
}

let selectedMonthKey = getLocalDate(today).slice(0, 7);

const CURRENCY_KEY = "myExpenseTracker_currency_v1";
const CURRENCY_OPTIONS = ["INR","USD","EUR","GBP","AED","SAR","SGD","AUD","CAD","JPY","CHF","CNY","NZD","ZAR","MYR","THB","IDR","PHP","BDT","PKR","LKR"];
let selectedCurrency = localStorage.getItem(CURRENCY_KEY) || "INR";
function money(amount) {
    try { return new Intl.NumberFormat(undefined, { style: "currency", currency: selectedCurrency, maximumFractionDigits: 2 }).format(Number(amount) || 0); }
    catch { return `${selectedCurrency} ${(Number(amount) || 0).toLocaleString()}`; }
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}



// ========================================
// CURRENT MONTH
// ========================================

currentMonth.textContent = today.toLocaleDateString(
    "en-IN",
    { month: "long", year: "numeric" }
);

// ========================================
// TRANSACTION CATEGORIES
// ========================================

const categories = {
    expense: [
        "Food & Groceries",
        "Transport",
        "Vehicle Maintenance",
        "Fuel",
        "Shopping",
        "Bills & Utilities",
        "Rent",
        "Medical",
        "Entertainment",
        "Education",
        "Others"
    ],

    income: [
        "Salary",
        "Business Income",
        "Freelance Income",
        "Interest",
        "Investment Returns",
        "Other Income"
    ]
};

// ========================================
// CREATE TRANSACTION FORM
// ========================================

const modal = document.createElement("dialog");
modal.id = "expenseModal";

modal.innerHTML = `
    <form id="expenseForm">

        <h2 id="modalTitle">Add Transaction</h2>

        <label>Transaction Type</label>
        <select id="transactionType" required>
            <option value="expense">Expense</option>
            <option value="income">Income</option>
        </select>

        <label>Description</label>
        <input
            type="text"
            id="description"
            placeholder="Example: Monthly salary"
            maxlength="80"
            required
        >

        <label>Amount (₹)</label>
        <input
            type="number"
            id="amount"
            placeholder="Enter amount"
            min="0.01"
            max="100000000"
            step="0.01"
            required
        >

        <label>Category</label>
        <select id="category" required></select>

        <label>Payment Method</label>
        <select id="payment" required>
            <option value="UPI">UPI</option>
            <option value="Cash">Cash</option>
            <option value="Debit Card">Debit Card</option>
            <option value="Credit Card">Credit Card</option>
            <option value="Bank Transfer">Bank Transfer</option>
            <option value="Other">Other</option>
        </select>

        <label>Date</label>
        <input type="date" id="expenseDate" required>

        <div class="modal-actions">
            <button type="button" id="cancelBtn" class="cancel-btn">
                Cancel
            </button>

            <button type="submit" id="submitExpenseBtn">
                Save Transaction
            </button>
        </div>

    </form>
`;

document.body.appendChild(modal);

// ========================================
// MODAL DESIGN
// ========================================

const modalStyle = document.createElement("style");

modalStyle.textContent = `
    #expenseModal {
        width: min(90%, 420px);
        max-height: 90vh;
        overflow-y: auto;
        border: none;
        border-radius: 18px;
        padding: 25px;
        margin: auto;
        box-shadow: 0 10px 40px rgba(0,0,0,0.25);
    }

    #expenseModal::backdrop {
        background: rgba(0,0,0,0.55);
    }

    #expenseForm {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    #expenseForm h2 {
        margin-bottom: 12px;
        font-size: 22px;
    }

    #expenseForm label {
        font-size: 13px;
        font-weight: 600;
        margin-top: 5px;
    }

    #expenseForm input,
    #expenseForm select {
        width: 100%;
        padding: 12px;
        border: 1px solid #DCE3EA;
        border-radius: 9px;
        font-size: 15px;
        background: white;
        color: #172B40;
    }

    .modal-actions {
        display: flex;
        gap: 10px;
        margin-top: 15px;
    }

    .modal-actions button {
        flex: 1;
        padding: 13px;
    }

    .cancel-btn {
        background: #E9EEF3;
        color: #172B40;
    }

    .transaction-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        padding: 15px 10px;
        background: #F7F9FC;
        border-radius: 12px;
    }

    .transaction-info {
        flex: 1;
        min-width: 0;
    }

    .transaction-info strong {
        display: block;
        font-size: 14px;
        overflow-wrap: anywhere;
    }

    .transaction-info small {
        display: block;
        color: #718096;
        font-size: 11px;
        margin-top: 5px;
    }

    .transaction-amount {
        font-weight: 700;
        font-size: 13px;
        white-space: nowrap;
    }

    .income-amount {
        color: #16834A;
    }

    .expense-amount {
        color: #C34A4A;
    }

    .transaction-actions {
        display: flex;
        gap: 5px;
    }

    .transaction-actions button {
        padding: 7px;
        font-size: 11px;
        background: #E3EAF1;
        color: #172B40;
    }

    .summary-details {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 15px;
    }

    .budget-details {
        margin-top: 22px;
    }

    .budget-progress {
        height: 8px;
        background: #E5EAF0;
        border-radius: 10px;
        overflow: hidden;
        margin-top: 15px;
    }

    .budget-progress div {
        height: 100%;
        background: #55B88A;
        transition: width 0.3s;
    }

    @media (max-width: 380px) {
        .transaction-item {
            flex-wrap: wrap;
        }
    }
`;

document.head.appendChild(modalStyle);

// ========================================
// UPDATE CATEGORY OPTIONS
// ========================================

const typeInput = document.getElementById("transactionType");
const categoryInput = document.getElementById("category");

function updateCategories(selectedCategory = "") {

    const type = typeInput.value;

    categoryInput.innerHTML = categories[type]
        .map(category => `
            <option value="${escapeHTML(category)}">
                ${escapeHTML(category)}
            </option>
        `)
        .join("");

    if (categories[type].includes(selectedCategory)) {
        categoryInput.value = selectedCategory;
    }
}

typeInput.addEventListener("change", () => {
    updateCategories();
});

// ========================================
// ADD AND EDIT TRANSACTIONS
// ========================================

let editingId = null;

function openTransactionForm(transaction = null) {

    editingId = transaction ? transaction.id : null;

    document.getElementById("modalTitle").textContent =
        transaction ? "Edit Transaction" : "Add Transaction";

    document.getElementById("submitExpenseBtn").textContent =
        transaction ? "Update Transaction" : "Save Transaction";

    typeInput.value = transaction?.type || "expense";

    updateCategories(transaction?.category || "");

    document.getElementById("description").value =
        transaction?.description || "";

    document.getElementById("amount").value =
        transaction?.amount || "";

    document.getElementById("payment").value =
        transaction?.payment || "UPI";

    document.getElementById("expenseDate").value =
        transaction?.date || getLocalDate(today);

    modal.showModal();
}

addExpenseBtn.addEventListener("click", () => {
    openTransactionForm();
});

document.getElementById("cancelBtn").addEventListener("click", () => {
    modal.close();
});

modal.addEventListener("click", event => {
    if (event.target === modal) {
        modal.close();
    }
});

// ========================================
// SAVE TRANSACTION
// ========================================

document.getElementById("expenseForm").addEventListener(
    "submit",
    async event => {

        event.preventDefault();

        const type = typeInput.value;
        const description = document.getElementById("description").value.trim();
        const amount = Number(document.getElementById("amount").value);
        const category = categoryInput.value;
        const payment = document.getElementById("payment").value;
        const date = document.getElementById("expenseDate").value;

        if (
            !description ||
            !Number.isFinite(amount) ||
            amount <= 0 ||
            amount > 100000000 ||
            !date ||
            date > getLocalDate(today) ||
            !["income", "expense"].includes(type)
        ) {
            alert("Please enter valid transaction details.");
            return;
        }

        const transactionData = {
            type,
            description,
            amount,
            category,
            payment,
            date
        };

        if (editingId !== null) {

            const index = transactions.findIndex(
                item => String(item.id) === String(editingId)
            );

            if (index !== -1) {
                transactions[index] = {
                    ...transactions[index],
                    ...transactionData
                };
            }

        } else {

            transactions.push({
                id: Date.now() + Math.random(),
                ...transactionData
            });
        }

        await saveData();
        renderApp();
        modal.close();
    }
);

// ========================================
// DISPLAY TRANSACTIONS
// ========================================

function renderTransactions() {

    const monthlyTransactions = transactions
        .filter(item => item.date?.slice(0, 7) === selectedMonthKey)
        .sort((a, b) => b.date.localeCompare(a.date));

    if (monthlyTransactions.length === 0) {
        transactionList.innerHTML = `
            <p class="empty-message">
                No transactions yet. Add your first transaction!
            </p>
        `;
        return;
    }

    transactionList.innerHTML = monthlyTransactions.map(item => {

        const isIncome = item.type === "income";

        return `
            <div class="transaction-item">

                <div class="transaction-info">
                    <strong>${escapeHTML(item.description)}</strong>

                    <small>
                        ${isIncome ? "Income" : "Expense"} ·
                        ${escapeHTML(item.category)} ·
                        ${escapeHTML(item.payment)} ·
                        ${escapeHTML(item.date)}
                    </small>
                </div>

                <div class="transaction-amount ${
                    isIncome ? "income-amount" : "expense-amount"
                }">
                    ${isIncome ? "+" : "−"}${money(item.amount)}
                </div>

                <div class="transaction-actions">
                    <button data-edit="${item.id}">Edit</button>
                    <button data-delete="${item.id}">Delete</button>
                </div>

            </div>
        `;
    }).join("");
}

// ========================================
// EDIT AND DELETE
// ========================================

transactionList.addEventListener("click", async event => {

    const editId = event.target.dataset.edit;
    const deleteId = event.target.dataset.delete;

    if (editId !== undefined) {

        const transaction = transactions.find(
            item => String(item.id) === editId
        );

        if (transaction) {
            openTransactionForm(transaction);
        }
    }

    if (deleteId !== undefined) {

        if (!confirm("Are you sure you want to delete this transaction?")) {
            return;
        }

        transactions = transactions.filter(
            item => String(item.id) !== deleteId
        );

        await saveData();
        renderApp();
    }
});

// ========================================
// MONTHLY BUDGET
// ========================================

saveBudgetBtn.addEventListener("click", async () => {

    const amount = Number(budgetInput.value);

    if (
        !Number.isFinite(amount) ||
        amount < 0 ||
        amount > 100000000
    ) {
        alert("Please enter a valid monthly budget.");
        return;
    }

    budgets[selectedMonthKey] = amount;

    await saveData();
    renderApp();

    budgetInput.value = "";

    alert("Monthly budget saved successfully!");
});

// ========================================
// UPDATE DASHBOARD
// ========================================

function renderDashboard() {

    const monthlyTransactions = transactions.filter(
        item => item.date?.slice(0, 7) === selectedMonthKey
    );

    const income = monthlyTransactions
        .filter(item => item.type === "income")
        .reduce((sum, item) => sum + Number(item.amount), 0);

    const expenses = monthlyTransactions
        .filter(item => item.type !== "income")
        .reduce((sum, item) => sum + Number(item.amount), 0);

    const savings = income - expenses;

    const budget = Number(budgets[selectedMonthKey] || 0);
    const remaining = budget - expenses;

    totalIncome.textContent = money(income);
    totalExpenses.textContent = money(expenses);
    monthlySavings.textContent = money(savings);

    monthlyBudget.textContent = money(budget);

const budgetStatusLabel = document.getElementById("budgetStatusLabel");

if (remaining < 0) {
    budgetStatusLabel.textContent = "Budget Exceeded";
    remainingBudget.textContent = money(Math.abs(remaining));
    remainingBudget.style.color = "#FF7777";
} else {
    budgetStatusLabel.textContent = "Budget Remaining";
    remainingBudget.textContent = money(remaining);
    remainingBudget.style.color = "#FFFFFF";
}

    monthlySavings.style.color =
        savings < 0 ? "#FFB4B4" : "#FFFFFF";

    remainingBudget.style.color =
        remaining < 0 ? "#FFB4B4" : "#FFFFFF";

    let progress = document.getElementById("budgetProgress");

    if (!progress) {
        progress = document.createElement("div");
        progress.id = "budgetProgress";
        progress.className = "budget-progress";

        document.querySelector(".summary-card").appendChild(progress);
    }

    const percentage = budget > 0
        ? Math.min((expenses / budget) * 100, 100)
        : 0;

    const progressColor = remaining < 0 ? "#FF7777" : "#55B88A";

progress.innerHTML = `
    <div style="width:${percentage}%; background:${progressColor}"></div>
`;
}

// ========================================
// REFRESH APPLICATION
// ========================================


function getChartSeries() {
    const monthItems = transactions.filter(item => item.date?.slice(0, 7) === selectedMonthKey);
    const dataMode = document.getElementById("chartDataSelect")?.value || "income-expense";
    if (dataMode === "categories") {
        const totals = {};
        monthItems.filter(item => item.type !== "income").forEach(item => {
            const key = item.category || "Others";
            totals[key] = (totals[key] || 0) + Number(item.amount || 0);
        });
        return Object.entries(totals).sort((a,b) => b[1]-a[1]).map(([label,value]) => ({label,value}));
    }
    if (dataMode === "daily") {
        const days = {};
        monthItems.filter(item => item.type !== "income").forEach(item => {
            const day = Number(item.date.slice(8,10));
            days[day] = (days[day] || 0) + Number(item.amount || 0);
        });
        return Array.from({length:31}, (_,i) => ({label:String(i+1),value:days[i+1] || 0})).filter((item,i) => {
            const [year,month] = selectedMonthKey.split("-").map(Number);
            return i < new Date(year,month,0).getDate();
        });
    }
    const income = monthItems.filter(item => item.type === "income").reduce((sum,item)=>sum+Number(item.amount||0),0);
    const expenses = monthItems.filter(item => item.type !== "income").reduce((sum,item)=>sum+Number(item.amount||0),0);
    return [{label:"Income",value:income},{label:"Expenses",value:expenses}];
}

function renderInteractiveGraph() {
    const host = document.getElementById("incomeExpenseChart");
    if (!host) return;
    const series = getChartSeries();
    const type = document.getElementById("chartTypeSelect")?.value || "bar";
    const mode = document.getElementById("chartDataSelect")?.value || "income-expense";
    const titles = {"income-expense":"Income vs Expenses",categories:"Expenses by Category",daily:"Daily Spending Trend"};
    document.getElementById("selectedGraphTitle").textContent = `${titles[mode]} · ${({bar:"Bar Chart",line:"Line Chart",donut:"Donut Chart",area:"Area Chart",column:"Column Chart"})[type]}`;
    document.getElementById("graphPeriodLabel").textContent = selectedMonthKey;
    if (!series.length || series.every(item => item.value === 0)) {
        host.innerHTML = `<p class="chart-empty">No data available for this selection yet. Add transactions to see your graph.</p>`;
        return;
    }
    const width=760, height=300, left=52, right=22, top=20, bottom=52;
    const plotW=width-left-right, plotH=height-top-bottom;
    const max=Math.max(...series.map(x=>x.value),1)*1.15;
    const colors=["#1677e8","#f05b67","#8b5cf6","#18a66a","#f59e0b","#06a6a6","#64748b","#ec4899"];
    const y = v => top + plotH - (v/max)*plotH;
    const x = i => left + (series.length===1 ? plotW/2 : i*plotW/(series.length-1));
    let svg=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${titles[mode]} ${type}" xmlns="http://www.w3.org/2000/svg">`;
    for(let i=0;i<=4;i++){const gy=top+i*plotH/4;svg+=`<line x1="${left}" y1="${gy}" x2="${width-right}" y2="${gy}" stroke="var(--chart-grid)" stroke-dasharray="4 5"/><text x="${left-10}" y="${gy+4}" text-anchor="end" fill="var(--muted)" font-size="11">${Math.round(max*(1-i/4)).toLocaleString()}</text>`;}
    if(type==="donut"){
        const total=series.reduce((a,b)=>a+b.value,0);let offset=0;const circumference=2*Math.PI*82;
        series.forEach((item,i)=>{const dash=item.value/total*circumference;svg+=`<circle cx="${width/2}" cy="${height/2-4}" r="82" fill="none" stroke="${colors[i%colors.length]}" stroke-width="34" stroke-dasharray="${dash} ${circumference-dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${width/2} ${height/2-4})"/>`;offset+=dash;});
        svg+=`<text x="${width/2}" y="${height/2-2}" text-anchor="middle" fill="var(--text)" font-size="17" font-weight="700">${money(series.reduce((a,b)=>a+b.value,0))}</text><text x="${width/2}" y="${height/2+20}" text-anchor="middle" fill="var(--muted)" font-size="12">Total</text>`;
    } else if(type==="line" || type==="area"){
        const points=series.map((item,i)=>`${x(i)},${y(item.value)}`).join(" ");
        if(type==="area"){svg+=`<polygon points="${left},${top+plotH} ${points} ${width-right},${top+plotH}" fill="#1677e8" opacity=".14"/>`;}
        svg+=`<polyline points="${points}" fill="none" stroke="#1677e8" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>`;
        series.forEach((item,i)=>svg+=`<circle cx="${x(i)}" cy="${y(item.value)}" r="5" fill="#1677e8" stroke="var(--surface)" stroke-width="2"/>`);
    } else {
        const slot=plotW/series.length;series.forEach((item,i)=>{const bw=Math.min(type==="column"?slot*.48:26,52);const bh=(item.value/max)*plotH;const bx=type==="column"?left+i*slot+(slot-bw)/2:left+10;const by=y(item.value);svg+=`<rect x="${bx}" y="${by}" width="${type==="column"?bw:Math.max(18,plotW*.72/series.length)}" height="${bh}" rx="7" fill="${colors[i%colors.length]}"/>`;});
    }
    if(type!=="donut") series.forEach((item,i)=>{const lx=series.length>18?x(i):left+(i+.5)*plotW/series.length;svg+=`<text x="${lx}" y="${height-20}" text-anchor="middle" fill="var(--muted)" font-size="${series.length>18?9:11}">${escapeHTML(item.label.length>12?item.label.slice(0,11)+"…":item.label)}</text>`;});
    svg+='</svg>';
    const legend=series.map((item,i)=>`<span class="graph-legend-item"><i style="background:${colors[i%colors.length]}"></i>${escapeHTML(item.label)} <b>${money(item.value)}</b></span>`).join("");
    host.innerHTML=svg+`<div class="graph-legend">${legend}</div>`;
}

function renderCharts() {
    renderInteractiveGraph();
    renderCategoryBudgetReport();
    const monthlyTransactions = transactions.filter(item => item.date?.slice(0, 7) === selectedMonthKey);
    const categoryTotals = {};
    monthlyTransactions.filter(item => item.type !== "income").forEach(item => {categoryTotals[item.category || "Others"]=(categoryTotals[item.category || "Others"]||0)+Number(item.amount||0);});
    const total=Object.values(categoryTotals).reduce((a,b)=>a+b,0);
    const categoryChart=document.getElementById("categoryChart");
    const sorted=Object.entries(categoryTotals).sort((a,b)=>b[1]-a[1]);
    categoryChart.innerHTML=sorted.length?sorted.map(([name,amount],i)=>`<div class="chart-row"><div class="chart-label"><span>${escapeHTML(name)}</span><strong>${money(amount)}</strong></div><div class="chart-track"><div class="chart-fill category-fill" style="width:${total?amount/total*100:0}%;background:${["#1677e8","#f59e0b","#8b5cf6","#18a66a","#f05b67"][i%5]}"></div></div><small>${total?(amount/total*100).toFixed(1):"0.0"}% of expenses</small></div>`).join(""):`<p class="chart-empty">No expense data available yet.</p>`;
    const income=monthlyTransactions.filter(item=>item.type==="income").reduce((a,b)=>a+Number(b.amount||0),0);
    const expenses=monthlyTransactions.filter(item=>item.type!=="income").reduce((a,b)=>a+Number(b.amount||0),0);
    const summary=document.getElementById("monthlyAnalysisSummary");
    if(summary) summary.innerHTML=`<div class="monthly-analysis-grid"><div><span>Income</span><strong>${money(income)}</strong></div><div><span>Expenses</span><strong>${money(expenses)}</strong></div><div><span>Net Savings</span><strong>${money(income-expenses)}</strong></div></div>`;
}

function installReportTabs(){
    const root=document.querySelector(".reports-section");if(!root||root.dataset.tabsReady)return;root.dataset.tabsReady="1";
    root.querySelectorAll("[data-report-tab]").forEach(button=>button.addEventListener("click",()=>{
        const tab=button.dataset.reportTab;
        root.querySelectorAll("[data-report-tab]").forEach(b=>b.classList.toggle("active",b===button));
        root.querySelectorAll("[data-report-pane]").forEach(p=>p.hidden=p.dataset.reportPane!==tab);
        if(tab==="charts")renderCharts();if(tab==="yearly")renderYearlyReport();
    }));
    ["chartTypeSelect","chartDataSelect","refreshChartBtn"].forEach(id=>document.getElementById(id)?.addEventListener("change",renderCharts));
    document.getElementById("refreshChartBtn")?.addEventListener("click",renderCharts);
}

function renderYearlyReport() {

    const yearSelect = document.getElementById("reportYear");
    const year = Number(yearSelect.value);

    if (!year) return;

    const yearTransactions = transactions.filter(
        item => item.date?.slice(0, 4) === String(year)
    );

    const income = yearTransactions
        .filter(item => item.type === "income")
        .reduce((sum, item) => sum + Number(item.amount), 0);

    const expenses = yearTransactions
        .filter(item => item.type !== "income")
        .reduce((sum, item) => sum + Number(item.amount), 0);

    document.getElementById("yearIncome").textContent = money(income);

    document.getElementById("yearExpenses").textContent = money(expenses);

    document.getElementById("yearSavings").textContent =
        money(income - expenses);

    // Calculate expenses month by month
    const monthlyData = Array.from({ length: 12 }, (_, index) => ({
        month: new Date(year, index, 1).toLocaleDateString("en-IN", {
            month: "long"
        }),
        income: 0,
        expenses: 0
    }));

    yearTransactions.forEach(item => {

        const monthIndex = Number(item.date.slice(5, 7)) - 1;

        if (monthIndex < 0 || monthIndex > 11) return;

        if (item.type === "income") {
            monthlyData[monthIndex].income += Number(item.amount);
        } else {
            monthlyData[monthIndex].expenses += Number(item.amount);
        }
    });

    // Find highest spending month
    const highest = [...monthlyData]
        .sort((a, b) => b.expenses - a.expenses)[0];

    document.getElementById("highestSpendingMonth").textContent =
        highest && highest.expenses > 0
            ? `${highest.month} (${money(highest.expenses)})`
            : "No expenses";

    // Monthly breakdown
    const breakdown = document.getElementById("yearlyBreakdown");

    const maximum = Math.max(
        ...monthlyData.map(item =>
            Math.max(item.income, item.expenses)
        ),
        1
    );

    breakdown.innerHTML = monthlyData.map(item => {

        const incomeWidth = item.income / maximum * 100;
        const expenseWidth = item.expenses / maximum * 100;

        return `
            <div class="year-month-row">

                <div class="year-month-heading">
                    <span>${item.month}</span>
                    <strong>${money(item.income - item.expenses)}</strong>
                </div>

                <div class="year-month-details">
                    <span>Income: ${money(item.income)}</span>
                    <span>Expense: ${money(item.expenses)}</span>
                </div>

                <div class="year-month-bar">
                    <div class="year-income-bar"
                         style="width:${incomeWidth}%"></div>
                    <div class="year-expense-bar"
                         style="width:${expenseWidth}%"></div>
                </div>

            </div>
        `;
    }).join("");
}

// Populate available years only after encrypted records have been unlocked.
const reportYear = document.getElementById("reportYear");

function populateReportYears() {
    const previousYear = reportYear.value;
    const availableYears = new Set([
        String(today.getFullYear()),
        ...transactions.filter(item => item.date).map(item => item.date.slice(0, 4))
    ]);
    reportYear.innerHTML = [...availableYears]
        .sort((a, b) => Number(b) - Number(a))
        .map(year => `<option value="${year}">${year}</option>`)
        .join("");
    reportYear.value = availableYears.has(previousYear) ? previousYear : String(today.getFullYear());
}

reportYear.addEventListener("change", renderYearlyReport);

function mergeRecurringRules(current, incoming) { const map = new Map((current||[]).map(r=>[String(r.id),r])); (incoming||[]).forEach(r=>{if(r && r.id) map.set(String(r.id),r);}); return [...map.values()]; }

// Recurring dates are generated in local calendar time; occurrence keys make processing idempotent.
function recurringDateFor(rule, index) {
    const start = new Date(`${rule.startDate}T12:00:00`);
    if (rule.frequency === "weekly") start.setDate(start.getDate() + index * 7);
    else if (rule.frequency === "monthly") { const day = start.getDate(); const target = new Date(start.getFullYear(), start.getMonth() + index, 1, 12); target.setDate(Math.min(day, new Date(target.getFullYear(), target.getMonth()+1, 0).getDate())); return getLocalDate(target); }
    else { const month = start.getMonth(), day = start.getDate(); const target = new Date(start.getFullYear()+index, month, 1, 12); target.setDate(Math.min(day, new Date(target.getFullYear(), month+1, 0).getDate())); return getLocalDate(target); }
    return getLocalDate(start);
}
let recurringProcessing = false;
async function processRecurringTransactions() {
    if (recurringProcessing || !encryptionKey || !Array.isArray(recurringRules) || !recurringRules.length) return;
    recurringProcessing = true;
    try {
    const todayKey = getLocalDate(new Date()); const existing = new Set(transactions.map(t => t.occurrenceKey).filter(Boolean)); let changed = false;
    recurringRules.forEach(rule => {
        if (!rule.active || !rule.startDate || !["weekly","monthly","yearly"].includes(rule.frequency)) return;
        for (let i=0; i<1200; i++) {
            const due = recurringDateFor(rule, i); if (due > todayKey || (rule.endDate && due > rule.endDate)) break;
            const occurrenceKey = `${rule.id}:${due}`; if (existing.has(occurrenceKey)) continue;
            transactions.push({ id:`rec-${rule.id}-${due}`, type:rule.type, description:rule.description, amount:Number(rule.amount), category:rule.category, payment:rule.payment, date:due, recurringRuleId:rule.id, occurrenceKey });
            existing.add(occurrenceKey); changed = true;
        }
    });
    if (changed) await saveData();
    } finally { recurringProcessing = false; }
}
function renderCategoryBudgetReport() {
    const host=document.getElementById("categoryBudgetReport"); if(!host)return;
    const limits=categoryBudgets[selectedMonthKey]||{}; const entries=Object.entries(limits);
    if(!entries.length){host.innerHTML='<p class="feature-empty">Set category budgets on the Home page to compare spending here.</p>';return;}
    const monthTx=transactions.filter(t=>t.date?.slice(0,7)===selectedMonthKey&&t.type!=="income");
    host.innerHTML=entries.map(([category,limit])=>{const spent=monthTx.filter(t=>t.category===category).reduce((sum,t)=>sum+Number(t.amount||0),0);const pct=limit?spent/limit*100:0;const status=pct>=100?"Over budget":pct>=80?"80%+ used":pct>=50?"50%+ used":"On track";return `<div class="category-budget-report-row"><div class="feature-item-head"><strong>${escapeHTML(category)}</strong><b>${money(spent)} / ${money(limit)}</b></div><div class="feature-progress"><span style="width:${Math.min(pct,100)}%"></span></div><div class="feature-item-foot"><span>${status}</span><span>${pct>100?`${money(spent-limit)} over`: `${money(limit-spent)} remaining`}</span></div></div>`;}).join("");
}

function renderCategoryBudgets() {
    const host=document.getElementById("categoryBudgetList"); if(!host)return;
    const monthTx=transactions.filter(t=>t.date?.slice(0,7)===selectedMonthKey && t.type!=="income");
    const limits=categoryBudgets[selectedMonthKey]||{}; const entries=Object.entries(limits);
    if(!entries.length){host.innerHTML='<p class="feature-empty">No category budgets set for this month yet.</p>';return;}
    host.innerHTML=entries.map(([category,limit])=>{
      const spent=monthTx.filter(t=>t.category===category).reduce((sum,t)=>sum+Number(t.amount||0),0); const pct=limit>0?spent/limit*100:0;
      const status=pct>=100?"Limit exceeded":pct>=80?"Warning · 80% used":pct>=50?"On track · 50% used":"Within limit"; const width=Math.min(pct,100);
      return `<div class="category-budget-item"><div class="feature-item-head"><strong>${escapeHTML(category)}</strong><b>${money(spent)} / ${money(limit)}</b></div><div class="feature-progress"><span style="width:${width}%"></span></div><div class="feature-item-foot"><span>${status}</span><span>${pct>100?`${money(spent-limit)} over`: `${money(Math.max(0,limit-spent))} left`}</span></div><button type="button" class="feature-remove" data-remove-category-budget="${escapeHTML(category)}">Remove</button></div>`;
    }).join("");
}
function renderRecurringRules() {
    const host = document.getElementById("recurringList");
    if (!host) return;
    const todayKey = getLocalDate(new Date());
    if (!recurringRules.length) {
        host.innerHTML = '<p class="feature-empty">No recurring transactions configured yet.</p>';
        return;
    }
    const completedOccurrences = new Set(transactions.map(item => item.occurrenceKey).filter(Boolean));
    host.innerHTML = recurringRules.map(rule => {
        let next = "No upcoming date";
        let status = rule.active ? "" : "Paused";
        if (rule.active) {
            for (let i = 0; i < 1200; i++) {
                const due = recurringDateFor(rule, i);
                if (rule.endDate && due > rule.endDate) break;
                if (due >= todayKey && !completedOccurrences.has(`${rule.id}:${due}`)) {
                    next = due;
                    break;
                }
            }
            if (next === "No upcoming date") status = "Schedule completed";
        }
        const nextLabel = status || `Next occurrence: ${next}`;
        return `<div class="recurring-item"><div class="feature-item-head"><strong>${escapeHTML(rule.description)}</strong><b>${money(rule.amount)}</b></div><p>${escapeHTML(rule.type)} · ${escapeHTML(rule.category)} · ${escapeHTML(rule.frequency)}</p><p>${nextLabel}${rule.endDate ? ` · Ends ${escapeHTML(rule.endDate)}` : ""}</p><div class="feature-actions"><button type="button" data-recurring-action="toggle" data-id="${escapeHTML(rule.id)}">${rule.active ? "Pause" : "Resume"}</button><button type="button" class="feature-remove" data-recurring-action="delete" data-id="${escapeHTML(rule.id)}">Delete rule</button></div></div>`;
    }).join("");
}

function renderApp() {
    installReportTabs();
    populateReportYears();
    renderDashboard();
    renderTransactions();
    renderCharts();
    renderYearlyReport();
    renderCategoryBudgets();
    renderRecurringRules();

    budgetInput.value = budgets[selectedMonthKey] ?? "";
}

const reportMonth = document.getElementById("reportMonth");

reportMonth.value = selectedMonthKey;

reportMonth.addEventListener("change", () => {

    if (!reportMonth.value) return;

    selectedMonthKey = reportMonth.value;

    currentMonth.textContent = new Date(
        selectedMonthKey + "-01T00:00:00"
    ).toLocaleDateString("en-IN", {
        month: "long",
        year: "numeric"
    });

    renderApp();
});


function exportTransactions() {

    if (!confirm("CSV files are not encrypted and can be opened by anyone with access to the file. Continue exporting?")) return;

    const headers = [
        "Date",
        "Description",
        "Type",
        "Category",
        "Payment Method",
        "Amount"
    ];

    const rows = transactions.map(item => [
        item.date,
        item.description,
        item.type === "income" ? "Income" : "Expense",
        item.category,
        item.payment,
        Number(item.amount).toFixed(2)
    ]);

    const csvEscape = value => {
        let text = String(value ?? "");

        // Prevent spreadsheet formula injection
        if (/^[=+\-@\t\r]/.test(text)) {
            text = "'" + text;
        }

        return '"' + text.replace(/"/g, '""') + '"';
    };

    const csvContent = [
        headers,
        ...rows
    ].map(row => row.map(csvEscape).join(",")).join("\r\n");

    const blob = new Blob(
        ["\uFEFF" + csvContent],
        { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download = "My_Expense_Report.csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}

document.getElementById("exportBtn").addEventListener(
    "click",
    exportTransactions
);

// ========================================
// FULL DATA BACKUP
// ========================================

document.getElementById("backupBtn").addEventListener("click", async () => {
    try {
        if (!encryptionKey) throw new Error("Unlock the app before creating a backup.");
        // Wait for all queued encrypted writes so the downloaded backup includes the latest rules.
        await saveQueue;
        const envelope = JSON.parse(localStorage.getItem(SECURE_STORAGE_KEY));
        const backupData = {
            appName: "My Expense Tracker",
            version: 2,
            backupDate: new Date().toISOString(),
            security: { method: securitySettings.method, salt: envelope.salt },
            encrypted: { format: envelope.format, iv: envelope.iv, data: envelope.data }
        };
        const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url; link.download = "MyExpenseTracker_Encrypted_Backup.json";
        document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
        alert("Encrypted backup downloaded. Keep your unlock credential safe; it is required to restore this backup.");
    } catch (error) { alert("Backup failed: " + error.message); }
});

// ========================================
// RESTORE DATA
// ========================================

const restoreBtn = document.getElementById("restoreBtn");
const restoreFile = document.getElementById("restoreFile");

restoreBtn.addEventListener("click", () => {
    restoreFile.click();
});

restoreFile.addEventListener("change", async () => {

    const file = restoreFile.files[0];

    if (!file) return;

    try {

        if (file.size > 10 * 1024 * 1024) {
            throw new Error("Backup file is too large.");
        }

        const text = await file.text();
        const backup = JSON.parse(text);

        if (backup.appName === "My Expense Tracker" && backup.version === 2 && backup.encrypted && backup.security?.salt) {
            const secret = prompt("Enter the PIN, pattern sequence, or password used when this backup was created. For a pattern, enter dot numbers separated by hyphens (example: 1-2-3-6).");
            if (!secret) return;
            const key = await deriveEncryptionKey(secret, base64ToBytes(backup.security.salt));
            const restoredData = await decryptPayload({ ...backup.encrypted }, key);
            if (!Array.isArray(restoredData.transactions) || !restoredData.budgets || typeof restoredData.budgets !== "object") throw new Error("Encrypted backup contents are invalid.");
            if (!confirm(`Found ${restoredData.transactions.length} transactions. Merge these records with the current records?`)) return;
            const merged = new Map(transactions.map(item => [String(item.id), item]));
            restoredData.transactions.forEach(item => merged.set(String(item.id), { ...item, type: item.type || "expense" }));
            transactions = Array.from(merged.values()); budgets = { ...budgets, ...restoredData.budgets }; categoryBudgets = { ...categoryBudgets, ...(restoredData.categoryBudgets || {}) }; recurringRules = mergeRecurringRules(recurringRules, restoredData.recurringRules || []);
            await saveData(); renderApp(); alert("Encrypted backup restored successfully."); return;
        }

        if (
            backup.appName !== "My Expense Tracker" ||
            !Array.isArray(backup.transactions) ||
            !backup.budgets ||
            typeof backup.budgets !== "object" ||
            Array.isArray(backup.budgets)
        ) {
            throw new Error("Invalid backup file.");
        }

        // Validate transaction records
        const validTransactions = backup.transactions.every(item =>
            item &&
            item.id !== undefined &&
            typeof item.description === "string" &&
            typeof item.date === "string" &&
            /^\d{4}-\d{2}-\d{2}$/.test(item.date) &&
            Number.isFinite(Number(item.amount)) &&
            Number(item.amount) > 0 &&
            Number(item.amount) <= 100000000 &&
            ["income", "expense"].includes(item.type || "expense") &&
            typeof item.category === "string" &&
            typeof item.payment === "string"
        );

        if (!validTransactions) {
            throw new Error("Backup contains invalid transactions.");
        }

        // Validate monthly budgets
        const validBudgets = Object.entries(backup.budgets).every(
            ([month, amount]) =>
                /^\d{4}-(0[1-9]|1[0-2])$/.test(month) &&
                Number.isFinite(Number(amount)) &&
                Number(amount) >= 0 &&
                Number(amount) <= 100000000
        );

        if (!validBudgets) {
            throw new Error("Backup contains invalid budgets.");
        }

        const confirmed = confirm(
            `Found ${backup.transactions.length} transactions. ` +
            "Restore and merge these records with existing data? " +
            "Existing records will not be cleared."
        );

        if (!confirmed) return;

        // Merge by transaction ID instead of deleting existing data
        const merged = new Map(
            transactions.map(item => [String(item.id), item])
        );

        backup.transactions.forEach(item => {
            const restored = {
                ...item,
                type: item.type || "expense"
            };

            merged.set(String(item.id), restored);
        });

        transactions = Array.from(merged.values());

        // Restore monthly budgets
        budgets = { ...budgets, ...backup.budgets };
        categoryBudgets = { ...categoryBudgets, ...(backup.categoryBudgets || {}) };
        recurringRules = mergeRecurringRules(recurringRules, backup.recurringRules || []);

        await saveData();
        renderApp();

        alert("Backup restored successfully!");

    } catch (error) {

        alert("Restore failed: " + error.message);

    } finally {

        restoreFile.value = "";
    }
});


// App navigation, per-device currency and appearance preferences
function installAppNavigation() {
    const main = document.querySelector("main");
    if (!main || document.getElementById("appNavigation")) return;

    const summary = main.querySelector(".summary-card");
    const sections = Array.from(main.querySelectorAll(":scope > section"));
    const transactionsSection = sections.find(el => el.querySelector("#transactionList"));
    const reportsSection = sections.find(el => el.classList.contains("reports-section"));
    const budgetSection = sections.find(el => el.querySelector("#budgetInput"));

    // Keep the original elements and IDs so existing finance/security logic remains intact.
    // Phase 1 tools are mounted inside existing pages so the fixed bottom navigation stays unchanged.
    [summary, budgetSection].forEach(el => { if (el) el.dataset.appPage = "dashboard"; });
    if (transactionsSection) transactionsSection.dataset.appPage = "transactions";
    if (reportsSection) reportsSection.dataset.appPage = "reports";

    if (budgetSection && !document.getElementById("categoryBudgetPanel")) {
      const panel = document.createElement("section");
      panel.id = "categoryBudgetPanel";
      panel.className = "category-budget-panel";
      panel.innerHTML = `
        <div class="feature-heading"><div><span class="eyebrow">SPENDING CONTROL</span><h3>Category-wise monthly budgets</h3><p>Set a separate spending limit for each expense category.</p></div></div>
        <div class="feature-form category-budget-form">
          <label for="categoryBudgetCategory">Expense category</label><select id="categoryBudgetCategory"></select>
          <label for="categoryBudgetAmount">Monthly limit</label><input id="categoryBudgetAmount" type="number" min="0.01" max="100000000" step="0.01" placeholder="Enter category budget">
          <button type="button" id="saveCategoryBudgetBtn">Save category budget</button>
        </div>
        <div id="categoryBudgetList" class="feature-list"></div>`;
      budgetSection.append(panel);
      const catSelect = panel.querySelector("#categoryBudgetCategory");
      catSelect.innerHTML = categories.expense.map(c => `<option value="${escapeHTML(c)}">${escapeHTML(c)}</option>`).join("");
      panel.querySelector("#saveCategoryBudgetBtn").addEventListener("click", async () => {
        const category = catSelect.value;
        const amount = Number(panel.querySelector("#categoryBudgetAmount").value);
        if (!category || !Number.isFinite(amount) || amount <= 0 || amount > 100000000) { alert("Enter a valid category budget greater than zero."); return; }
        categoryBudgets[selectedMonthKey] ||= {};
        categoryBudgets[selectedMonthKey][category] = amount;
        await saveData(); renderApp(); panel.querySelector("#categoryBudgetAmount").value = "";
      });
      panel.addEventListener("click", async event => {
        const category = event.target.closest("[data-remove-category-budget]")?.dataset.removeCategoryBudget;
        if (!category) return;
        if (!confirm(`Remove the ${category} budget for ${selectedMonthKey}?`)) return;
        delete categoryBudgets[selectedMonthKey]?.[category];
        await saveData(); renderApp();
      });
    }

    if (transactionsSection && !document.getElementById("recurringPanel")) {
      const panel = document.createElement("section");
      panel.id = "recurringPanel";
      panel.className = "recurring-panel";
      panel.innerHTML = `
        <div class="feature-heading"><div><span class="eyebrow">AUTOMATION</span><h3>Recurring transactions</h3><p>Automatically add scheduled salary, rent, subscriptions, EMIs and other repeating entries when the app is opened.</p></div></div>
        <form id="recurringForm" class="feature-form">
          <label for="recurringType">Transaction type</label><select id="recurringType"><option value="expense">Expense</option><option value="income">Income</option></select>
          <label for="recurringDescription">Description</label><input id="recurringDescription" maxlength="80" required placeholder="e.g. Monthly rent">
          <label for="recurringAmount">Amount</label><input id="recurringAmount" type="number" min="0.01" max="100000000" step="0.01" required placeholder="Enter amount">
          <label for="recurringCategory">Category</label><select id="recurringCategory" required></select>
          <label for="recurringPayment">Payment method</label><select id="recurringPayment"><option>UPI</option><option>Cash</option><option>Debit Card</option><option>Credit Card</option><option>Bank Transfer</option><option>Other</option></select>
          <label for="recurringFrequency">Frequency</label><select id="recurringFrequency"><option value="weekly">Weekly</option><option value="monthly" selected>Monthly</option><option value="yearly">Yearly</option></select>
          <label for="recurringStart">First occurrence date</label><input id="recurringStart" type="date" required>
          <label for="recurringEnd">End date (optional)</label><input id="recurringEnd" type="date">
          <button type="submit">Save recurring rule</button>
        </form>
        <div class="feature-subheading">Your recurring rules</div><div id="recurringList" class="feature-list"></div>`;
      transactionsSection.append(panel);
      const rType = panel.querySelector("#recurringType"), rCategory = panel.querySelector("#recurringCategory");
      function fillRecurringCategories() { rCategory.innerHTML = categories[rType.value].map(c => `<option value="${escapeHTML(c)}">${escapeHTML(c)}</option>`).join(""); }
      rType.addEventListener("change", fillRecurringCategories); fillRecurringCategories();
      panel.querySelector("#recurringStart").value = getLocalDate(new Date());
      panel.querySelector("#recurringForm").addEventListener("submit", async event => {
        event.preventDefault();
        const startDate = panel.querySelector("#recurringStart").value, endDate = panel.querySelector("#recurringEnd").value;
        const amount = Number(panel.querySelector("#recurringAmount").value);
        if (!startDate || (endDate && endDate < startDate) || !Number.isFinite(amount) || amount <= 0 || amount > 100000000) { alert("Check the amount and schedule dates."); return; }
        recurringRules.push({ id: `rr-${Date.now()}-${Math.random().toString(36).slice(2,8)}`, type:rType.value, description:panel.querySelector("#recurringDescription").value.trim(), amount, category:rCategory.value, payment:panel.querySelector("#recurringPayment").value, frequency:panel.querySelector("#recurringFrequency").value, startDate, endDate:endDate || null, active:true, createdAt:new Date().toISOString() });
        await processRecurringTransactions(); await saveData(); renderApp(); panel.querySelector("#recurringForm").reset(); panel.querySelector("#recurringStart").value = getLocalDate(new Date()); fillRecurringCategories();
      });
      panel.addEventListener("click", async event => {
        const action = event.target.closest("[data-recurring-action]"); if (!action) return;
        const rule = recurringRules.find(r => r.id === action.dataset.id); if (!rule) return;
        if (action.dataset.recurringAction === "toggle") rule.active = !rule.active;
        if (action.dataset.recurringAction === "delete") { if (!confirm("Delete this recurring rule? Already-created transactions will remain.")) return; recurringRules = recurringRules.filter(r => r.id !== rule.id); }
        await saveData(); renderApp();
      });
    }

    const settings = document.createElement("section");
    settings.id = "appSettings";
    settings.className = "section settings-page";
    settings.hidden = true;
    settings.innerHTML = `
      <div class="page-heading"><div><span class="eyebrow">PREFERENCES</span><h2>Settings</h2><p>Personalize and protect your finance tracker.</p></div></div>
      <div class="settings-layout">
        <section class="settings-group"><div class="settings-icon">◐</div><div class="settings-content"><h3>Appearance</h3><p>Choose how My Expense Tracker looks on this device.</p><label for="appearanceSelect">Theme</label><select id="appearanceSelect"><option value="light">Light</option><option value="dark">Dark</option><option value="system">System default</option></select></div></section>
        <section class="settings-group"><div class="settings-icon">◎</div><div class="settings-content"><h3>Currency & Region</h3><p>Choose the currency used to display your amounts.</p><label for="currencySelect">Display currency</label><select id="currencySelect">${CURRENCY_OPTIONS.map(c=>`<option value="${c}">${c}</option>`).join("")}</select><small>Changing currency changes display formatting only. It does not convert existing amounts.</small></div></section>
        <section class="settings-group"><div class="settings-icon">♢</div><div class="settings-content"><h3>Security & Privacy</h3><p>Manage your lock method and automatic-lock preferences.</p><button type="button" id="settingsSecurityBtn">Manage app lock</button></div></section>
        <section class="settings-group"><div class="settings-icon">⇧</div><div class="settings-content"><h3>Data & Backup</h3><p>Export or restore your financial records.</p><button type="button" id="settingsReportsBtn">Open backup & restore</button></div></section>
        <section class="settings-group"><div class="settings-icon">ⓘ</div><div class="settings-content"><h3>About</h3><p>My Expense Tracker · Personal finance manager</p></div></section>
      </div>`;
    main.append(settings);

    const nav = document.createElement("nav");
    nav.id = "appNavigation";
    nav.className = "app-navigation";
    nav.setAttribute("aria-label", "Main navigation");
    nav.innerHTML = `
      <button type="button" data-page="dashboard" class="active"><span class="nav-symbol">⌂</span><span>Home</span></button>
      <button type="button" data-page="transactions"><span class="nav-symbol">⇄</span><span>Activity</span></button>
      <button type="button" data-action="add" class="nav-add" aria-label="Add transaction"><span>＋</span></button>
      <button type="button" data-page="reports"><span class="nav-symbol">▥</span><span>Reports</span></button>
      <button type="button" data-page="settings"><span class="nav-symbol">⚙</span><span>Settings</span></button>`;
    document.body.append(nav);

    const currencySelect = settings.querySelector("#currencySelect");
    currencySelect.value = selectedCurrency;
    currencySelect.addEventListener("change", () => {
      selectedCurrency = currencySelect.value;
      localStorage.setItem(CURRENCY_KEY, selectedCurrency);
      renderApp();
    });

    const THEME_KEY = "myExpenseTracker_theme_v2";
    const appearanceSelect = settings.querySelector("#appearanceSelect");
    const savedTheme = localStorage.getItem(THEME_KEY) || "system";
    appearanceSelect.value = savedTheme;
    function applyTheme(value) {
      const effective = value === "system" ? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light") : value;
      document.documentElement.dataset.theme = effective;
      document.documentElement.dataset.themePreference = value;
    }
    applyTheme(savedTheme);
    appearanceSelect.addEventListener("change", () => {
      localStorage.setItem(THEME_KEY, appearanceSelect.value);
      applyTheme(appearanceSelect.value);
    });
    window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
      if ((localStorage.getItem(THEME_KEY) || "system") === "system") applyTheme("system");
    });

    settings.querySelector("#settingsSecurityBtn").addEventListener("click", () => {
      if (!encryptionKey) return;
      setupSecurity(true).catch(error => showSecurityError(error.message));
    });
    settings.querySelector("#settingsReportsBtn").addEventListener("click", () => {
      showPage("reports");
      reportsSection?.querySelector('[data-report-tab="backup"]')?.click();
    });

    function showPage(page) {
      [summary, transactionsSection, reportsSection, budgetSection, settings].filter(Boolean).forEach(el => {
        el.hidden = el.dataset.appPage ? el.dataset.appPage !== page : page !== "settings";
      });
      nav.querySelectorAll("button[data-page]").forEach(b => b.classList.toggle("active", b.dataset.page === page));
      document.body.dataset.activePage = page;
      if (page === "reports") renderCharts();
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
    nav.addEventListener("click", e => {
      const add = e.target.closest('[data-action="add"]');
      if (add) { addExpenseBtn?.click(); return; }
      const button = e.target.closest("button[data-page]");
      if (button) showPage(button.dataset.page);
    });
    showPage("dashboard");
}

// Start the application
installAppNavigation();
initializeSecureApp().catch(error => {
    console.error("Secure app initialization failed:", error);
    alert("Unable to open secure storage. Do not clear browser data. Restore from your backup or contact support.");
});
