import { CONFIG } from './config.js';

async function getExplanations(emailText) {
    const response = await fetch(`${CONFIG.API_BASE_URL}/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: emailText })
    });
    return await response.json();
}

async function checkAndHighlight() {
    // 1. Check if Gmail has applied your "Malicious" label to this email on screen
    const labels = document.querySelectorAll('.at'); 
    const isMalicious = Array.from(labels).some(l => l.innerText.includes('malicious'));

    if (isMalicious) {
        const emailBody = document.querySelector('.a3s.aiL');
        if (!emailBody || emailBody.dataset.explained === "true") return;

        // 2. Send text to your FastAPI /explain endpoint
        const response = await fetch(`${CONFIG.API_BASE_URL}/explain`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ text: emailBody.innerText })
        });
        
        const data = await response.json();
        
        // 3. Highlight triggers
        let html = emailBody.innerHTML;
        data.triggers.forEach(word => {
        // Clean XLM-R specific characters (like the 'Ġ' used by RoBERTa/XLM-R)
        const cleanWord = word.replace('Ġ', '').replace(' ', '');
        if (cleanWord.length < 2) return; // Skip single characters

        const regex = new RegExp(`\\b(${cleanWord})\\b`, 'gi');
        html = html.replace(regex, '<mark style="background: #ffcccb; color: black; border-radius: 4px; padding: 2px;">$1</mark>');
        });
        
        emailBody.innerHTML = html;
        emailBody.dataset.explained = "true"; // Prevent infinite loops
    }
}

// Watch for when the user clicks a different email
setInterval(checkAndHighlight, 2000);