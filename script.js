// ===== UPDATED SCRIPT.JS FOR RENDER =====
// ... (keep all your existing code, just update the scanFile function)

function scanFile() {
    const fileInput = document.getElementById('fileInput');
    const result = document.getElementById('scanResult');
    
    if (!fileInput.files.length) {
        alert('⚠️ Please select a file first!');
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    // Show loading
    result.style.display = 'block';
    result.className = 'scan-result';
    result.innerHTML = `
        <div style="text-align: center; padding: 20px;">
            <div style="width:40px; height:40px; border:4px solid #f3f3f3; border-top:4px solid #33a351; border-radius:50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
            <p style="margin-top: 10px;">🔄 Scanning with VirusTotal...</p>
            <p style="font-size: 14px; color: #6c757d;">Checking 70+ antivirus engines</p>
        </div>
    `;
    
    // Send to Render backend
    fetch('https://bougg-malware-tool.onrender.com/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            result.innerHTML = `<div style="color:red;">Error: ${data.error}</div>`;
            return;
        }
        
        const stats = data.stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const undetected = stats.undetected || 0;
        const isMalware = data.is_malware || false;
        
        result.className = 'scan-result ' + (isMalware ? 'danger' : 'safe');
        result.innerHTML = `
            <div class="result-icon">${isMalware ? '🚨' : '✅'}</div>
            <h3>${isMalware ? '⚠️ Malware Detected!' : '✅ File is Safe!'}</h3>
            <p>${isMalware ? `${malicious} antivirus engines detected threats` : 'No threats detected'}</p>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin: 15px 0;">
                <div style="background: #dc3545; color: white; padding: 10px; border-radius: 5px;">
                    <div style="font-size: 20px; font-weight: 700;">${malicious}</div>
                    <div style="font-size: 12px;">Malicious</div>
                </div>
                <div style="background: #ffc107; color: #333; padding: 10px; border-radius: 5px;">
                    <div style="font-size: 20px; font-weight: 700;">${suspicious}</div>
                    <div style="font-size: 12px;">Suspicious</div>
                </div>
                <div style="background: #28a745; color: white; padding: 10px; border-radius: 5px;">
                    <div style="font-size: 20px; font-weight: 700;">${undetected}</div>
                    <div style="font-size: 12px;">Undetected</div>
                </div>
            </div>
            
            <div style="font-size: 13px; color: #6c757d; margin: 10px 0;">
                Source: ${data.source || 'VirusTotal'} | ${data.detection_ratio || '0/0'} engines
            </div>
            
            <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
        result.innerHTML = `<div style="color:red;">Error connecting to backend. Please try again.</div>`;
    });
}
