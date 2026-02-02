// extension/content.js

// ==========================================
// 1. Extraction Helpers
// ==========================================

function getCleanUserEmail() {
    // Strategy: Extract from window title "Subject - email@address.com - Gmail"
    const title = document.title;
    const match = title.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)\s+-\s+Gmail$/);
    if (match && match[1]) {
        return match[1];
    }
    
    // Fallback: Check for the hidden user email element in standard Gmail DOM
    // This varies by theme/version, but often exists in the account button aria-label
    const accountBtn = document.querySelector('a[aria-label*="("][aria-label*="@"]');
    if (accountBtn) {
        const ariaLabel = accountBtn.getAttribute('aria-label');
        const emailMatch = ariaLabel.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/);
        if (emailMatch) return emailMatch[1];
    }
    
    return null;
}

// extension/content.js

function getActualMessageId() {
    // strict regex for the API format (16 lowercase hex chars)
    const apiIdRegex = /^[a-f0-9]{16}$/;

    // STRATEGY 1: 'data-legacy-message-id' (The Gold Standard)
    // This attribute is explicitly maintained by Gmail to match the API ID.
    const legacyElements = document.querySelectorAll('[data-legacy-message-id]');
    for (const el of legacyElements) {
        const id = el.getAttribute('data-legacy-message-id');
        if (apiIdRegex.test(id)) {
            console.log("✅ Found exact Message ID (Legacy):", id);
            return id;
        }
    }

    // STRATEGY 2: Filtered 'data-message-id'
    // We scan all elements but strictly REJECT anything starting with "msg-a:"
    // This handles cases where the legacy attribute is missing.
    const allMessageElements = document.querySelectorAll('[data-message-id]');
    for (const el of allMessageElements) {
        const id = el.getAttribute('data-message-id');
        
        // Strict Filter: Must be 16 hex chars (e.g., "18e3b4d2f8a1b2c3")
        // Rejects "msg-a:..." and "thread-f:..."
        if (apiIdRegex.test(id)) {
            console.log("✅ Found exact Message ID (DOM):", id);
            return id;
        }
    }

    console.warn("❌ Could not find a valid Message ID. URL ID was ignored to avoid mismatch.");
    return null;
}

// ==========================================
// 2. UI Injection Logic
// ==========================================

function injectWarning(data) {
    const emailHeader = document.querySelector('.ha') || document.querySelector('.h7'); 
    if (!emailHeader || document.getElementById('phish-guard-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'phish-guard-banner';
    banner.style = `
        background: #fef2f2; 
        border: 1px solid #ef4444; 
        padding: 16px; 
        margin: 10px 0; 
        border-radius: 6px; 
        color: #991b1b; 
        font-family: 'Google Sans', Roboto, sans-serif;
        display: flex;
        align-items: center;
        gap: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    `;
    
    let title, description;
    
    switch(data.reason_type) {
        case 'url':
            title = "⚠️ High Risk Link Detected";
            description = `A known malicious URL was found: <code style="background:#fee2e2; padding:2px 4px; border-radius:4px;">${data.malicious_url}</code>`;
            break;
        case 'attachment':
            title = "⚠️ Dangerous Attachment";
            description = `This email contains a malicious file: <strong>${data.filename || "Unknown File"}</strong>. <br>Scanning engine triggers: ${data.triggers.join(', ')}`;
            break;
        case 'llm':
            title = "⚠️ AI Content Warning";
            description = `<strong>AI Analysis:</strong> ${data.reason}`;
            break;
        case 'xlmr':
        default:
            title = "⚠️ Suspicious Patterns Detected";
            description = `Our ML model identified linguistic patterns common in phishing attacks.`;
            break;
    }

    banner.innerHTML = `
        <div style="font-size: 24px;">🛡️</div>
        <div>
            <div style="font-weight: bold; font-size: 14px; margin-bottom: 4px;">${title}</div>
            <div style="font-size: 13px; line-height: 1.4;">${description}</div>
        </div>
    `;
    
    // Insert after the subject line container
    emailHeader.parentNode.insertBefore(banner, emailHeader.nextSibling);
}

function highlightContent(data) {
    const emailBody = document.querySelector('.a3s.aiL');
    if (!emailBody) return;

    let html = emailBody.innerHTML;
    let modified = false;

    // Helper to escape regex characters
    const escapeRegExp = (string) => {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // 1. Highlight Malicious URLs
    if (data.reason_type === "url" && data.malicious_url) {
        // ... (Your existing URL logic is fine)
        const urlRegex = new RegExp(escapeRegExp(data.malicious_url), 'gi');
        html = html.replace(urlRegex, (match) => 
            `<mark style="background: #ef4444; color: white; padding: 0 2px; border-radius: 2px; font-weight: bold;" title="Malicious URL">${match} 🚫</mark>`
        );
        modified = true;
    } 
    // 2. Highlight XLM-R Triggers
    else if (data.reason_type === "xlmr" && data.triggers && data.triggers.length > 0) {
        // Sort by length (longest first) to prevent partial replacements breaking things
        const sortedTriggers = [...data.triggers].sort((a, b) => b.length - a.length);

        sortedTriggers.forEach(word => {
            const cleanWord = word.trim();
            if (cleanWord.length < 3) return;

            // Escape the word to be Regex-safe
            const safeWord = escapeRegExp(cleanWord);

            // Regex: Find word NOT inside an HTML tag
            // Note: This matches the text content of the email
            const regex = new RegExp(`(?<!<[^>]*)${safeWord}`, 'gi');
            
            html = html.replace(regex, (match) => 
                `<mark style="background: #fee2e2; border-bottom: 2px solid #ef4444; color: #7f1d1d;" title="Suspicious Term">${match}</mark>`
            );
            modified = true;
        });
    }
    
    if (modified) {
        emailBody.innerHTML = html;
    }
}
// ==========================================
// 3. Main Logic
// ==========================================

async function fetchExplanation() {
    // 1. Get Context
    const msgId = getActualMessageId();
    const userEmail = getCleanUserEmail();

    if (!msgId) {
        console.log("Could not find Message ID");
        return;
    }
    if (!userEmail) {
        console.log("Could not find User Email");
        return;
    }

    console.log(`Fetching explanation for ${userEmail} / ${msgId}`);

    // 2. Call Backend
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/analyze-full`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'ngrok-skip-browser-warning': 'true'
            },
            body: JSON.stringify({
                 email: "FETCH_FROM_CACHE_ONLY", // We don't need to send body if fetching from cache
                 message_id: msgId,
                 user_email: userEmail
            })
        });
        
        const data = await response.json();
        
        if (data.label === "phishing") {
            injectWarning(data);
            // Only highlight if it's NOT LLM based (LLM is banner only)
            if (data.reason_type !== "llm") {
                highlightContent(data);
            }
        } else {
            console.log("Email is safe or no explanation found.");
        }

    } catch (error) {
        console.error("Error fetching explanation:", error);
    }
}

// ==========================================
// 4. Injection Trigger
// ==========================================

// function injectExplainButton() {
//     // Only show button in "Malicious" folder or if we suspect it
//     if (!window.location.hash.includes('malicious')) return;
    
//     // Look for the action toolbar (Archive, Delete, etc.)
//     const toolbar = document.querySelector('.G-atb') || document.querySelector('.iH');
    
//     if (toolbar && !document.getElementById('ai-explain-btn')) {
//         const btn = document.createElement('div');
//         btn.id = 'ai-explain-btn';
//         btn.role = "button";
//         btn.className = "T-I J-J5-Ji nu T-I-ax7 L3"; // Native Gmail button classes
//         btn.innerHTML = "🤖 Why is this Phishing?";
//         btn.style.backgroundColor = "#d93025";
//         btn.style.color = "#fff";
//         btn.style.backgroundImage = "none";
//         btn.style.marginLeft = "10px";
        
//         btn.onclick = fetchExplanation;
        
//         // Append to the toolbar
//         // Try to find the second group of buttons to place it nicely
//         const container = toolbar.querySelector('.G-Ni') || toolbar;
//         container.appendChild(btn);
//     }
// }

// // Run periodically to handle navigation (Gmail is a SPA)
// setInterval(injectExplainButton, 1000);


// extension/content.js

/**
 * Core Injection Logic
 * Uses the selectors that worked for you, but adds a check to avoid duplicates.
 */
function injectExplainButton() {
    // 1. Only proceed if we are in the malicious folder
    if (!window.location.hash.includes('malicious')) {
        const existingBtn = document.getElementById('ai-explain-btn');
        if (existingBtn) existingBtn.remove();
        return;
    }

    // 2. Attempt the selectors you confirmed were working
    const toolbar = document.querySelector('div[role="main"] .G-atb') || 
                    document.querySelector('.ade') || 
                    document.querySelector('.ha'); 
    
    // 3. Prevent duplicate injection
    if (!toolbar || document.getElementById('ai-explain-btn')) return;

    // 4. Create the button exactly as you styled it
    const btn = document.createElement('button');
    btn.id = 'ai-explain-btn';
    btn.innerText = "Explain Phishing Risk";
    btn.style = `
        background: #ef4444; 
        color: white; 
        border: none; 
        padding: 8px 15px; 
        margin: 5px; 
        border-radius: 4px; 
        cursor: pointer; 
        font-weight: bold; 
        position: relative; 
        z-index: 1000;
        display: inline-flex;
        align-items: center;
    `;
    
    // Attach your working function
    // btn.onclick = () => {
    //     console.log("Button clicked: Starting XLM-R Explanation...");
    //     checkAndHighlight(); // Removed forced manual trigger as it's built into the function
    // };
    // Attach your working function
    btn.onclick = () => {
        console.log("Button clicked: Starting XLM-R Explanation...");
        fetchExplanation(); // FIX: Call the correct function name
    };
    // 5. Append it to the container
    toolbar.appendChild(btn);
    console.log("✅ Button injected into toolbar.");
}

// ==========================================
// Robust Trigger Logic (Replaces setInterval)
// ==========================================

// A. MutationObserver: Fires immediately when Gmail updates the DOM
const observer = new MutationObserver(() => {
    injectExplainButton();
});

// Start observing the main Gmail structure
observer.observe(document.body, {
    childList: true,
    subtree: true
});

// B. Initial Call
injectExplainButton();