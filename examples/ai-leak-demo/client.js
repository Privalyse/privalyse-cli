const axios = require('axios');

async function sendToAI(userData) {
    const email = userData.email;
    
    // Leak
    await axios.post('https://api.openai.com/v1/completions', {
        prompt: `User email is ${email}`,
        model: 'text-davinci-003'
    });
    
    // Safe? (JS analyzer is regex based, might not catch sanitization perfectly but let's try)
    const safeEmail = sanitize(email);
    await axios.post('https://api.anthropic.com/v1/complete', {
        prompt: `User is ${safeEmail}`,
        model: 'claude-2'
    });
}

function sanitize(str) {
    return "***";
}
