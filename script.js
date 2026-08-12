// ===== HIDE PRELOADER =====
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        var preloader = document.getElementById('preloader');
        if (preloader) {
            preloader.classList.add('hidden');
        }
    }, 1000);
    initNavigation();
    initUploadZone();
});

// ===== NAVIGATION =====
function switchPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    var target = document.getElementById(pageId);
    if (target) target.classList.add('active');
    
    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
    var navLink = document.querySelector('nav a[href="#' + pageId + '"]');
    if (navLink) navLink.classList.add('active');
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function initNavigation() {
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var pageId = this.getAttribute('href').replace('#', '');
            if (pageId) switchPage(pageId);
        });
    });
}

// ===== UPLOAD ZONE =====
function initUploadZone() {
    var zone = document.getElementById('uploadZone');
    var fileInput = document.getElementById('fileInput');
    if (!zone || !fileInput) return;
    
    zone.addEventListener('click', function() {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            var file = this.files[0];
            document.getElementById('fileName').textContent = file.name;
            document.getElementById('fileSize').textContent = (file.size / 1024).toFixed(1) + ' KB';
            document.getElementById('fileInfo').style.display = 'block';
            document.getElementById('uploadZone').style.display = 'none';
            document.getElementById('scanResult').style.display = 'none';
        }
    });
}

var lastScanData = null;

// ===== SCAN FUNCTION =====
function scanFile() {
    var fileInput = document.getElementById('fileInput');
    var result = document.getElementById('scanResult');
    
    if (!fileInput.files.length) {
        alert('⚠️ Please select a file first!');
        return;
    }
    
    var file = fileInput.files[0];
    var formData = new FormData();
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
    
    fetch('/api/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            result.innerHTML = `<div style="color:red;">Error: ${data.error}</div>`;
            return;
        }
        
        lastScanData = data;
        displayResults(data);
    })
    .catch(function(error) {
        console.error('Error:', error);
        result.innerHTML = `<div style="color:red;">Error connecting to backend. Please try again.</div>`;
    });
}

function displayResults(data) {
    var result = document.getElementById('scanResult');
    var stats = data.stats || {};
    var malicious = stats.malicious || 0;
    var suspicious = stats.suspicious || 0;
    var undetected = stats.undetected || 0;
    var isMalware = data.is_malware || false;
    var totalEngines = data.total_engines || 0;
    
    result.className = 'scan-result ' + (isMalware ? 'danger' : 'safe');
    result.innerHTML = `
        <div class="result-icon">${isMalware ? '🚨' : '✅'}</div>
        <h3>${isMalware ? '⚠️ Malware Detected!' : '✅ File is Safe!'}</h3>
        <p>${isMalware ? malicious + ' antivirus engines detected threats' : 'No threats detected'}</p>
        
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
            Source: ${data.source || 'VirusTotal'} | ${malicious}/${totalEngines} engines detected
        </div>
        
        ${isMalware ? `<button class="btn btn-primary" onclick="showDetails()" style="margin: 10px 0;">🔍 View Detected Threats (${malicious})</button>` : ''}
        
        <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
    `;
}

// ===== SHOW DETAILED RESULTS =====
function showDetails() {
    if (!lastScanData) return;
    
    var modal = document.getElementById('detailsModal');
    var content = document.getElementById('detailsContent');
    var details = lastScanData.detailed_results || [];
    
    if (details.length === 0) {
        content.innerHTML = '<p>No detailed results available.</p>';
        modal.style.display = 'block';
        return;
    }
    
    var html = `
        <div style="margin-bottom:20px;">
            <p><strong>File:</strong> ${lastScanData.filename}</p>
            <p><strong>SHA256:</strong> <span style="font-size:12px; word-break:break-all;">${lastScanData.sha256}</span></p>
            <p><strong>Total Detections:</strong> ${lastScanData.stats.malicious}/${lastScanData.total_engines}</p>
        </div>
        <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:14px;">
                <thead>
                    <tr style="background:#33a351; color:white;">
                        <th style="padding:10px; text-align:left;">#</th>
                        <th style="padding:10px; text-align:left;">Antivirus Engine</th>
                        <th style="padding:10px; text-align:left;">Detection Name</th>
                        <th style="padding:10px; text-align:left;">Category</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    details.forEach(function(item, index) {
        var categoryColor = item.category === 'malicious' ? '#dc3545' : '#ffc107';
        var categoryText = item.category === 'malicious' ? '🚨 Malicious' : '⚠️ Suspicious';
        html += `
            <tr style="border-bottom:1px solid #eee;">
                <td style="padding:8px;">${index + 1}</td>
                <td style="padding:8px; font-weight:600;">${item.engine}</td>
                <td style="padding:8px; font-family:monospace; font-size:12px;">${item.result || 'Detected'}</td>
                <td style="padding:8px; color:${categoryColor}; font-weight:600;">${categoryText}</td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
        <p style="margin-top:15px; font-size:12px; color:#6c757d;">Showing ${details.length} threats detected by VirusTotal</p>
    `;
    
    content.innerHTML = html;
    modal.style.display = 'block';
}

function closeDetails() {
    document.getElementById('detailsModal').style.display = 'none';
}

function resetScan() {
    document.getElementById('fileInput').value = '';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'block';
    document.getElementById('scanResult').style.display = 'none';
    lastScanData = null;
}

function clearFile() {
    document.getElementById('fileInput').value = '';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'block';
    document.getElementById('scanResult').style.display = 'none';
    lastScanData = null;
}

console.log('%c🛡️ BOUGG Malware Detection Tool', 'font-size:20px; font-weight:bold; color:#33a351;');
console.log('%c🔒 Loaded successfully!', 'font-size:14px; color:#6c757d;');
