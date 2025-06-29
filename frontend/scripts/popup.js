import { analyzeUrl } from './urlAnalyzer.js';
import { analyzeEmail } from './emailAnalyzer.js';
import { HistoryManager } from './historyManager.js';

const historyManager = new HistoryManager();
let currentUrl = '';

// DOM Elements
const tabs = {
  url: document.getElementById('url-check'),
  email: document.getElementById('email-check'),
  history: document.getElementById('history'),
};

const tabButtons = {
  url: document.getElementById('url-tab-btn'),
  email: document.getElementById('email-tab-btn'),
  history: document.getElementById('history-tab-btn'),
};

// === Initialize Popup ===
document.addEventListener('DOMContentLoaded', async () => {
  await getCurrentTabUrl();
  bindTabEvents();
  bindUrlCheckEvents();
  bindEmailCheckEvents();
  bindHistoryEvents();
  switchTab('url');
});

// === Get Current URL ===
async function getCurrentTabUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    currentUrl = tabs[0]?.url || '';
    document.getElementById('current-url-display').textContent = currentUrl || 'N/A';
  });
}

// === Tab Switch Logic ===
function switchTab(tab) {
  Object.keys(tabs).forEach((key) => {
    tabs[key].classList.toggle('active', key === tab);
    tabButtons[key].classList.toggle('active', key === tab);
  });

  if (tab === 'history') loadHistoryItems('all');
}

function bindTabEvents() {
  Object.entries(tabButtons).forEach(([key, button]) => {
    button.addEventListener('click', () => switchTab(key));
  });
}

// === URL Check Logic ===
function bindUrlCheckEvents() {
  document.getElementById('check-current-url').addEventListener('click', () => {
    if (currentUrl) analyzeAndDisplayUrl(currentUrl);
  });

  document.getElementById('check-url-btn').addEventListener('click', () => {
    const inputUrl = document.getElementById('url-input').value.trim();
    if (inputUrl) analyzeAndDisplayUrl(inputUrl);
  });
}

async function analyzeAndDisplayUrl(url) {
  const resultBox = document.getElementById('url-result');
  const badge = document.getElementById('url-safety-badge');
  const adviceBox = document.getElementById('url-advice');

  resultBox.classList.remove('hidden');
  setBadge(badge, 'Analyzing...', 'badge');

  try {
    const result = await analyzeUrl(url);
    updateUrlUI(result);
    await historyManager.addHistoryItem({
      type: 'url',
      content: url,
      result: result.safetyScore,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(err);
    setBadge(badge, 'Error', 'badge danger');
    adviceBox.innerHTML = `<p>${err.message}</p>`;
  }
}

function updateUrlUI(result) {
  const badge = document.getElementById('url-safety-badge');
  const { safetyScore, domainAge, sslValid, blacklisted, suspiciousPatterns, advice } = result;

  setBadge(
    badge,
    safetyScore >= 80 ? 'Safe' : safetyScore >= 50 ? 'Suspicious' : 'Dangerous',
    `badge ${safetyScore >= 80 ? 'safe' : safetyScore >= 50 ? 'warning' : 'danger'}`
  );

  document.getElementById('domain-age').textContent = domainAge;
  document.getElementById('ssl-status').textContent = sslValid ? 'Valid' : 'Invalid';
  document.getElementById('blacklist-status').textContent = blacklisted ? 'Blacklisted' : 'Not Blacklisted';
  document.getElementById('suspicious-patterns').textContent =
    suspiciousPatterns.length > 0 ? `${suspiciousPatterns.length} found` : 'None';
  document.getElementById('url-advice').innerHTML = `<p>${advice}</p>`;
}

// === Email Check Logic ===
function bindEmailCheckEvents() {
  document.getElementById('check-email-btn').addEventListener('click', async () => {
    const sender = document.getElementById('email-sender').value.trim();
    const subject = document.getElementById('email-subject').value.trim();
    const content = document.getElementById('email-content').value.trim();

    if (!sender || !subject || !content) {
      alert('Please fill all email fields.');
      return;
    }

    const badge = document.getElementById('email-safety-badge');
    const resultBox = document.getElementById('email-result');
    resultBox.classList.remove('hidden');
    setBadge(badge, 'Analyzing...', 'badge');

    try {
      const result = await analyzeEmail(sender, subject, content);
      updateEmailUI(result);
      await historyManager.addHistoryItem({
        type: 'email',
        content: `${sender} - ${subject}`,
        result: result.safetyScore,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error(err);
      setBadge(badge, 'Error', 'badge danger');
      document.getElementById('email-advice').innerHTML = `<p>${err.message}</p>`;
    }
  });
}

function updateEmailUI(result) {
  const badge = document.getElementById('email-safety-badge');
  const { safetyScore, senderVerified, phishingIndicators, urgencyTactics, suspiciousLinks, advice } = result;

  setBadge(
    badge,
    safetyScore >= 80 ? 'Safe' : safetyScore >= 50 ? 'Suspicious' : 'Dangerous',
    `badge ${safetyScore >= 80 ? 'safe' : safetyScore >= 50 ? 'warning' : 'danger'}`
  );

  document.getElementById('sender-verification').textContent = senderVerified ? 'Verified' : 'Unverified';
  document.getElementById('phishing-indicators').textContent = `${phishingIndicators.length} detected`;
  document.getElementById('urgency-tactics').textContent = urgencyTactics ? 'Detected' : 'Not detected';
  document.getElementById('suspicious-links').textContent = `${suspiciousLinks.length} found`;
  document.getElementById('email-advice').innerHTML = `<p>${advice}</p>`;
}

// === History Tab Logic ===
function bindHistoryEvents() {
  ['all', 'url', 'email'].forEach((type) => {
    document.getElementById(`${type}-history`).addEventListener('click', () => {
      highlightFilter(type);
      loadHistoryItems(type);
    });
  });
}

function highlightFilter(type) {
  ['all', 'url', 'email'].forEach((t) =>
    document.getElementById(`${t}-history`).classList.remove('active')
  );
  document.getElementById(`${type}-history`).classList.add('active');
}

async function loadHistoryItems(type = 'all') {
  const list = document.getElementById('history-list');
  const items = await historyManager.getHistoryItems();
  const filtered = type === 'all' ? items : items.filter((i) => i.type === type);

  list.innerHTML = filtered.length === 0
    ? `<p class="empty-state">No ${type} history found.</p>`
    : '';

  filtered.forEach((item) => {
    const itemDiv = document.createElement('div');
    const status = item.result >= 80 ? 'safe' : item.result >= 50 ? 'warning' : 'danger';
    const date = new Date(item.timestamp).toLocaleString();

    itemDiv.className = `history-item ${status}`;
    itemDiv.innerHTML = `
      <div class="history-item-header">
        <span class="history-item-type">${item.type.toUpperCase()}</span>
        <span class="history-item-date">${date}</span>
      </div>
      <div class="history-item-content">${item.content}</div>
    `;
    list.appendChild(itemDiv);
  });
}

// === Helper Function ===
function setBadge(element, text, className) {
  element.textContent = text;
  element.className = className;
}
