// Function to inject a "Warning Banner" at the top of the email
function injectWarning(reason, detail) {
    const emailHeader = document.querySelector('.ha');
    if (!emailHeader || document.getElementById('phish-guard-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'phish-guard-banner';
    banner.style = "background: #fee2e2; border: 2px solid #ef4444; padding: 15px; margin: 10px; border-radius: 8px; color: #991b1b; font-family: sans-serif;";
    
    const message = reason === 'url' 
        ? `⚠️ <strong>High Risk:</strong> This email contains a blacklisted URL: <code style="background:#fca5a5; padding:2px;">${detail}</code>`
        : `⚠️ <strong>AI Analysis:</strong> Our XLM-R model detected suspicious patterns in the text (highlighted in red).`;
    
    banner.innerHTML = message;
    emailHeader.prepend(banner);
}
function injectExplainButton() {
    // console.log("Current hash:", window.location.hash);
    // Only proceed if we are in the malicious folder
    if (!window.location.hash.includes('malicious')) return;

    // Attempt several common Gmail toolbar selectors
    const toolbar = document.querySelector('div[role="main"] .G-atb') || 
                    document.querySelector('.ade') || 
                    document.querySelector('.ha'); // Fallback to email header
    
    if (!toolbar || document.getElementById('ai-explain-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'ai-explain-btn';
    btn.innerText = "Explain Phishing Risk";
    // Inline styling to ensure it stands out
    btn.style = "background: #ef4444; color: white; border: none; padding: 8px 15px; margin: 5px; border-radius: 4px; cursor: pointer; font-weight: bold; position: relative; z-index: 1000;";
    
    btn.onclick = () => {
        console.log("Button clicked: Starting XLM-R Explanation...");
        checkAndHighlight(true); // Forced manual trigger
    };
    
    toolbar.appendChild(btn);
}
let isAnalyzing = false;

async function checkAndHighlight() {
    if (isAnalyzing) return;
    
    // Gmail uses hashes for navigation (e.g., #label/malicious)
    // const isMaliciousFolder = window.location.hash.includes('malicious');
    // if (!isMaliciousFolder) return;

    // Wait for email body to load
    const emailBody = document.querySelector('.a3s.aiL');
    if (!emailBody || emailBody.dataset.explained === "true") return;
    
    isAnalyzing = true;
    console.log("Analyzing malicious email...");
    console.log("Email body text:", emailBody.innerText);
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/analyze-full`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'ngrok-skip-browser-warning': 'true'},
            body: JSON.stringify({ email: emailBody.innerText })
        });
        
        const data = await response.json();
        if (data.label !== "phishing") return;

        injectWarning(data.reason_type, data.malicious_url);

        let html = emailBody.innerHTML;

        if (data.reason_type === "url") {
            const urlRegex = new RegExp(`(${data.malicious_url})`, 'gi');
            html = html.replace(urlRegex, '<mark style="background: #ef4444; color: white; font-weight: bold;">$1 [MALICIOUS]</mark>');
            } else if (data.reason_type === "xlmr") {
                data.triggers.forEach(word => {
                    // Remove SentencePiece artifacts
                    const cleanWord = word.replace(/[Ġ▁]/g, '').trim();
                    if (cleanWord.length < 2) return; 

                    // Use a global, case-insensitive search without word boundaries
                    const regex = new RegExp(`(${cleanWord})`, 'gi');
                    html = html.replace(regex, '<mark style="background: #fecaca; border-bottom: 2px solid #ef4444; color: black;">$1</mark>');
                });
            }
        
        emailBody.innerHTML = html;
        emailBody.dataset.explained = "true";
    } catch (error) {
        console.error("Error during analysis:", error);
    }
    finally {
        isAnalyzing = false;
    }
}
// FIX: Run every time the URL hash changes (Gmail navigation)
// window.addEventListener('hashchange', checkAndHighlight);


// // Run periodically to catch cases where the DOM loads after the hash change
// setInterval(checkAndHighlight, 2000);

setInterval(injectExplainButton, 1000);