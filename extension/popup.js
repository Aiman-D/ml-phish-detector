// This MUST point to your live, WORKING Render API
const API_ENDPOINT = 'https://ml-phish-detector.onrender.com/predict'; 

document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
            // ... (error handling for no tab)
            return;
        }
        const url = tabs[0].url;
        if (!url || url.startsWith('chrome://')) {
            // ... (error handling for chrome pages)
            return;
        }

        document.getElementById('url-display').textContent = url.substring(0, 70) + (url.length > 70 ? '...' : '');

        // 2. Call the ML Prediction API
        fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) {
                // --- THIS IS THE NEW, BETTER ERROR ---
                // It will now show "API error: 503 Service Unavailable"
                throw new Error(`API error: ${response.status} ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            // ... (all the success logic for displaying results) ...
            const statusDiv = document.getElementById('status');
            const resultDiv = document.getElementById('result');
            const spinner = resultDiv.querySelector('.spinner');
            if (spinner) spinner.remove();

            const mlLabel = data.ml_label || 'N/A';
            const mlConf = data.ml_conf || 0;
            const mlFeatures = data.features_ml || []; 

            statusDiv.textContent = `${mlLabel} (${mlConf}%)`;
            
            if (mlLabel === 'Phishing') {
                statusDiv.className = 'phishing';
            } else if (mlLabel === 'Legitimate') {
                statusDiv.className = 'legitimate';
            } else {
                 statusDiv.className = 'loading';
            }

            if (mlFeatures.length > 0) {
                const featureNames = ['URL Len', 'Host Len', 'Digits', 'Subdomains', 'Has IP', 'Non-Alnum', 'Entropy'];
                let featuresHTML = '<div class="confidence"><b>ML Features Used:</b><ul style="margin: 4px 0; padding-left: 18px; font-size: 0.9em;">';
                featureNames.forEach((name, i) => {
                    let val = (typeof mlFeatures[i] === 'number') ? mlFeatures[i].toFixed(2) : mlFeatures[i];
                    featuresHTML += `<li>${name}: ${val}</li>`;
                });
                featuresHTML += '</ul></div>';
                resultDiv.insertAdjacentHTML('beforeend', featuresHTML);
            }
        })
        .catch(error => {
            console.error('Prediction failed:', error);
            const statusDiv = document.getElementById('status');
            // --- THIS IS THE NEW, BETTER ERROR ---
            // This will display the exact error in the popup
            statusDiv.textContent = `API Failed: ${error.message}`; 
            statusDiv.className = 'loading';
            const spinner = document.getElementById('result').querySelector('.spinner');
            if (spinner) spinner.remove();
        });
    });
});