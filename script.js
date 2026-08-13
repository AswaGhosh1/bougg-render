// ===== DOM READY =====
document.addEventListener('DOMContentLoaded', function() {
    // Hide preloader immediately
    var preloader = document.getElementById('preloader');
    if (preloader) {
        preloader.classList.add('hidden');
    }
    
    setTimeout(function() {
        var preloader = document.getElementById('preloader');
        if (preloader) {
            preloader.classList.add('hidden');
        }
    }, 1000);
    
    initNavigation();
    initUploadZone();
    initCounterAnimation();
    
    console.log('🐞 BOUGG Malware Detection Tool Loaded Successfully');
    console.log('Powered by Bougg - 70+ Antivirus Engines');
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
    
    zone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });
    
    zone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
    });
    
    zone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect();
        }
    });
    
    fileInput.addEventListener('change', function() {
        console.log('File input changed');
        handleFileSelect();
    });
    
    zone.addEventListener('click', function() {
        fileInput.click();
    });
    
    // Also handle the "Choose File" label click
    var chooseBtn = document.querySelector('label[for="fileInput"]');
    if (chooseBtn) {
        chooseBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            fileInput.click();
        });
    }
}

function handleFileSelect() {
    var fileInput = document.getElementById('fileInput');
    var fileInfo = document.getElementById('fileInfo');
    var fileName = document.getElementById('fileName');
    var fileSize = document.getElementById('fileSize');
    var uploadZone = document.getElementById('uploadZone');
    var result = document.getElementById('scanResult');
    
    if (!fileInput || !fileInput.files || !fileInput.files.length) {
        console.log('No file selected');
        return;
    }
    
    var file = fileInput.files[0];
    console.log('File selected:', file.name, file.size);
    
    var size = (file.size / 1024 / 1024).toFixed(2);
    var sizeUnit = file.size > 1024 * 1024 ? 'MB' : 'KB';
    var displaySize = file.size > 1024 * 1024 ? size : (file.size / 1024).toFixed(1);
    
    fileName.textContent = file.name;
    fileSize.textContent = displaySize + ' ' + sizeUnit;
    
    // Force show file info and hide upload zone
    fileInfo.style.display = 'block';
    fileInfo.style.visibility = 'visible';
    fileInfo.style.opacity = '1';
    uploadZone.style.display = 'none';
    result.style.display = 'none';
    document.getElementById('fileAnalysis').style.display = 'none';
    
    console.log('File info displayed, scan button should be visible');
}

function clearFile() {
    var fileInput = document.getElementById('fileInput');
    var fileInfo = document.getElementById('fileInfo');
    var uploadZone = document.getElementById('uploadZone');
    var result = document.getElementById('scanResult');
    
    fileInput.value = '';
    fileInfo.style.display = 'none';
    uploadZone.style.display = 'block';
    result.style.display = 'none';
    document.getElementById('fileAnalysis').style.display = 'none';
}

function resetScan() {
    clearFile();
}

var lastScanData = null;

// ===== SCAN FUNCTION =====
function scanFile() {
    var fileInput = document.getElementById('fileInput');
    var result = document.getElementById('scanResult');
    
    if (!fileInput || !fileInput.files || !fileInput.files.length) {
        alert('Please select a file first!');
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
            <p style="margin-top: 10px; font-weight: 600;">Scanning with VirusTotal...</p>
            <p style="font-size: 14px; color: #6c757d;">Checking 70+ antivirus engines</p>
        </div>
    `;
    document.getElementById('fileAnalysis').style.display = 'none';
    
    fetch('/api/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            result.innerHTML = '<div style="color:red; font-weight:600;">Error: ' + data.error + '</div>';
            return;
        }
        
        lastScanData = data;
        displayResults(data);
        displayFileInfo(data.file_info);
    })
    .catch(function(error) {
        console.error('Error:', error);
        result.innerHTML = '<div style="color:red; font-weight:600;">Error connecting to backend. Please try again.</div>';
    });
}

// ===== DISPLAY RESULTS =====
function displayResults(data) {
    var result = document.getElementById('scanResult');
    var vt = data.vt_results || {};
    var stats = vt.stats || {};
    var malicious = stats.malicious || 0;
    var suspicious = stats.suspicious || 0;
    var undetected = stats.undetected || 0;
    var harmless = stats.harmless || 0;
    var isMalware = vt.is_malware || false;
    var total = malicious + suspicious + undetected + harmless;
    
    result.className = 'scan-result ' + (isMalware ? 'danger' : 'safe');
    
    var detailsHtml = '';
    if (isMalware && vt.detailed_results) {
        detailsHtml = `
            <button class="btn btn-primary" onclick="showDetails()" style="margin: 10px 0;">
                View Detected Threats (${malicious})
            </button>
        `;
    }
    
    result.innerHTML = `
        <div class="result-icon">${isMalware ? }</div>
        <h3>${isMalware ? 'Malware Detected!' : 'File is Safe!'}</h3>
        <p>${isMalware ? malicious + ' antivirus engines detected threats' : 'No threats detected by any engine'}</p>
        
        <div class="result-stats">
            <div class="stat-box" style="background: #dc3545; color: white;">
                <div class="number">${malicious}</div>
                <div class="label">Malicious</div>
            </div>
            <div class="stat-box" style="background: #ffc107; color: #333;">
                <div class="number">${suspicious}</div>
                <div class="label">Suspicious</div>
            </div>
            <div class="stat-box" style="background: #28a745; color: white;">
                <div class="number">${undetected}</div>
                <div class="label">Undetected</div>
            </div>
        </div>
        
        <div style="font-size: 13px; color: #6c757d; margin: 10px 0;">
            Source: ${vt.source || 'Bougg database'} | ${malicious}/${total} engines detected
        </div>
        
        ${detailsHtml}
        
        <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
    `;
}

// ===== DISPLAY FILE INFO =====
function displayFileInfo(info) {
    var container = document.getElementById('fileAnalysis');
    if (!container) return;
    
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth' });
    
    var html = `
        <div class="card" style="padding: 30px;">
            <h3 style="color: #33a351; font-size: 22px; font-weight: 700; margin-bottom: 20px;">File Information</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div class="analysis-item"><span class="label">Filename</span><span class="value">${info.filename || 'N/A'}</span></div>
                <div class="analysis-item"><span class="label">File Size</span><span class="value">${info.size_human || 'N/A'}</span></div>
                <div class="analysis-item"><span class="label">File Type</span><span class="value">${info.file_type || 'Unknown'}</span></div>
                <div class="analysis-item"><span class="label">MIME Type</span><span class="value">${info.mime_type || 'Unknown'}</span></div>
                <div class="analysis-item"><span class="label">Extension</span><span class="value">${info.extension || 'None'}</span></div>
                ${info.pe_type ? `<div class="analysis-item"><span class="label">PE Type</span><span class="value">${info.pe_type}</span></div>` : ''}
                ${info.encoding ? `<div class="analysis-item"><span class="label">Encoding</span><span class="value">${info.encoding} (${info.confidence || 0}%)</span></div>` : ''}
                <div class="analysis-item" style="grid-column: 1 / -1;"><span class="label">MD5</span><span class="value" style="font-size: 12px; font-family: monospace;">${info.md5 || 'N/A'}</span></div>
                <div class="analysis-item" style="grid-column: 1 / -1;"><span class="label">SHA1</span><span class="value" style="font-size: 12px; font-family: monospace;">${info.sha1 || 'N/A'}</span></div>
                <div class="analysis-item" style="grid-column: 1 / -1;"><span class="label">SHA256</span><span class="value" style="font-size: 12px; font-family: monospace;">${info.sha256 || 'N/A'}</span></div>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
}

// ===== SHOW DETAILED RESULTS =====
function showDetails() {
    if (!lastScanData) return;
    
    var vt = lastScanData.vt_results || {};
    var details = vt.detailed_results || [];
    var modal = document.getElementById('detailsModal');
    var content = document.getElementById('detailsContent');
    
    if (!modal || !content) return;
    
    if (details.length === 0) {
        content.innerHTML = '<p>No detailed results available.</p>';
        modal.style.display = 'block';
        return;
    }
    
    var html = `
        <div style="margin-bottom: 20px;">
            <p><strong>File:</strong> ${lastScanData.filename}</p>
            <p><strong>SHA256:</strong> <span style="font-size: 12px; word-break: break-all;">${lastScanData.sha256}</span></p>
        </div>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Antivirus Engine</th>
                        <th>Detection Name</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    details.forEach(function(item, index) {
        var categoryColor = item.category === 'malicious' ? '#dc3545' : '#ffc107';
        var categoryText = item.category === 'malicious' ? 'Malicious' : 'Suspicious';
        html += `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${item.engine}</strong></td>
                <td style="font-family: monospace; font-size: 12px;">${item.result || 'Detected'}</td>
                <td style="color: ${categoryColor}; font-weight: 600;">${categoryText}</td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
        <p style="margin-top: 15px; font-size: 12px; color: #6c757d;">Showing ${details.length} threats detected</p>
    `;
    
    content.innerHTML = html;
    modal.style.display = 'block';
}

function closeDetails() {
    var modal = document.getElementById('detailsModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// ===== COUNTER ANIMATION =====
function initCounterAnimation() {
    var counters = document.querySelectorAll('.stat-number');
    
    if (!counters.length) return;
    
    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                var target = parseInt(entry.target.dataset.target);
                animateCounter(entry.target, target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });
    
    counters.forEach(function(counter) {
        observer.observe(counter);
    });
}

function animateCounter(element, target) {
    var current = 0;
    var increment = target / 60;
    
    var timer = setInterval(function() {
        current += increment;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = Math.round(current).toLocaleString() + (target === 99.9 ? '%' : '');
    }, 25);
}

// ===== FEEDBACK FORM =====
function submitFeedback(event) {
    event.preventDefault();
    
    var text = document.getElementById('feedbackText');
    if (!text) return;
    
    var feedbackText = text.value.trim();
    if (!feedbackText) {
        alert('Please enter your feedback.');
        return;
    }
    
    var successMsg = document.getElementById('feedbackSuccess');
    if (successMsg) {
        successMsg.classList.add('show');
    }
    
    setTimeout(function() {
        var form = document.getElementById('feedbackForm');
        if (form) form.reset();
        if (successMsg) successMsg.classList.remove('show');
    }, 3000);
}
