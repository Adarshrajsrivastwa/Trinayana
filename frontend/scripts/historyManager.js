export class HistoryManager {
  constructor() {
    this.key = 'phishing_history';
  }

  async addHistoryItem(item) {
    if (!this._isChromeAvailable()) return;

    const history = await this.getHistoryItems();
    history.push(item);

    return new Promise((resolve) => {
      chrome.storage.local.set({ [this.key]: history }, resolve);
    });
  }

  async getHistoryItems() {
    if (!this._isChromeAvailable()) return [];

    return new Promise((resolve) => {
      chrome.storage.local.get([this.key], (result) => {
        resolve(result[this.key] || []);
      });
    });
  }

  async clearHistory() {
    if (!this._isChromeAvailable()) return;

    return new Promise((resolve) => {
      chrome.storage.local.remove([this.key], resolve);
    });
  }

  _isChromeAvailable() {
    return typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
  }
}
