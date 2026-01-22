import { CONFIG } from './config.js';

document.getElementById('subscribeBtn').addEventListener('click', () => {
    // This connects the extension's button to your existing /login flow
    chrome.tabs.create({ url: `${CONFIG.API_BASE_URL}/login` });
});