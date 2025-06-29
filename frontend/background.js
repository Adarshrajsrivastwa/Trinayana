/**
 * Background Script for FraudShield Extension
 * 
 * This script runs in the background and handles tasks such as:
 * - Monitoring web requests for suspicious patterns
 * - Providing real-time alerts for potentially malicious sites
 * - Managing extension state
 */

import { analyzeUrl } from './scripts/urlAnalyzer.js';
import { HistoryManager } from './scripts/historyManager.js';

// Initialize history manager
const historyManager = new HistoryManager();

// Listen for tab URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only run analysis when the URL has been completely loaded
  if (changeInfo.status === 'complete' && tab.url) {
    performBackgroundUrlCheck(tab.url, tabId);
  }
});

/**
 * Performs a background check on URLs as users browse
 * @param {string} url - The URL to analyze
 * @param {number} tabId - The tab ID where the URL is loaded
 */
async function performBackgroundUrlCheck(url, tabId) {
  try {
    // Skip analysis for non-http URLs, browser internal pages, and extension pages
    if (!url.startsWith('http') || 
        url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') ||
        url.startsWith('about:')) {
      return;
    }
    
    // Analyze URL
    const result = await analyzeUrl(url);
    
    // Only save to history and notify if it's suspicious or dangerous
    if (result.safetyScore < 70) {
      // Save to history
      await historyManager.addHistoryItem({
        type: 'url',
        content: url,
        result: result.safetyScore,
        timestamp: new Date().toISOString()
      });
      
      // If very dangerous, show notification
      if (result.safetyScore < 40) {
        showDangerNotification(url, result, tabId);
      }
    }
  } catch (error) {
    console.error('Error in background URL check:', error);
  }
}

/**
 * Shows a notification for dangerous websites
 * @param {string} url - The dangerous URL
 * @param {Object} result - Analysis result
 * @param {number} tabId - Tab ID where the site is loaded
 */
function showDangerNotification(url, result, tabId) {
  // Create notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'assets/icon128.png',
    title: 'Dangerous Website Detected',
    message: `The site ${new URL(url).hostname} may be unsafe. Safety score: ${result.safetyScore}/100`,
    priority: 2
  });
  
  // Optional: Add a badge to the extension icon for this tab
  chrome.action.setBadgeText({
    text: '!',
    tabId: tabId
  });
  
  chrome.action.setBadgeBackgroundColor({
    color: '#FF0000',
    tabId: tabId
  });
}

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getCurrentUrl') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        sendResponse({ url: tabs[0].url });
      } else {
        sendResponse({ url: null });
      }
    });
    return true; // Required for async sendResponse
  }
});

// Clear any badge when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.action.setBadgeText({
    text: '',
    tabId: tabId
  });
});

console.log('FraudShield background service started');