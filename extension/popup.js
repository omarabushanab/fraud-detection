// extension/popup.js
const API_BASE_URL = "https://gus-hypertonic-otto.ngrok-free.dev";

document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('subscribeBtn');
    
    if (btn) {
        btn.addEventListener('click', async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'ngrok-skip-browser-warning': 'true'
                    }
                });

                // Debug: Check if we actually got a JSON response
                const contentType = response.headers.get("content-type");
                if (contentType && contentType.includes("application/json")) {
                    const data = await response.json();
                    if (data.auth_url) {
                        chrome.tabs.create({ url: data.auth_url });
                    }
                } else {
                    // This will log the HTML that's causing the crash
                    const text = await response.text();
                    console.error("Received HTML instead of JSON. Check ngrok warning:", text.substring(0, 100));
                }
            } catch (error) {
                console.error("Connection failed:", error);
            }
        });
    }
});