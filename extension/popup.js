const API_BASE_URL = "https://jonell-ardeid-interpervasively.ngrok-free.dev";

document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('subscribeBtn');
    
    if (btn) {
        btn.addEventListener('click', async () => {
            try {
                // 1. Fetch the JSON from your existing API
                const response = await fetch(`${API_BASE_URL}/login`);
                const data = await response.json();
                
                // 2. Extract the URL string from the JSON object
                if (data.auth_url) {
                    console.log("Redirecting to Google...");
                    chrome.tabs.create({ url: data.auth_url });
                } else {
                    console.error("Invalid response format:", data);
                }
            } catch (error) {
                console.error("Connection failed. Is the backend/ngrok running?", error);
            }
        });
    }
});