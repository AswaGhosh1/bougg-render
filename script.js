// ===== DOM READY =====
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        var preloader = document.getElementById('preloader');
        if (preloader) {
            preloader.classList.add('hidden');
        }
    }, 1000);
    initNavigation();
    initUploadZone();
    initCounterAnimation();
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
    
    fileInput.addEventListener('change', handleFileSelect);
    zone.addEventListener('click', function() {
        fileInput.click();
    });
}

function handleFileSelect() {
    var fileInput = document.getElementById('fileInput');
    var fileInfo = document.getElementById('fileInfo');
    var fileName = document.getElementById('fileName');
    var fileSize = document.getElementById('fileSize');
    var uploadZone = document.getElementById('uploadZone');
    var result = document.getElementById('scanResult');
    
    if (!fileInput.files.length) return;
    
    var file = fileInput.files[0];
    var size = (file.size / 1024 / 1024).toFixed(2);
    var sizeUnit = file.size > 1024 * 1024 ? 'MB' : 'KB';
    var displaySize = file.size > 1024 * 1024 ? size : (file.size / 1024).toFixed(1);
    
    fileName.textContent = file.name;
    fileSize.textContent = displaySize + ' ' + sizeUnit;
    fileInfo.style.display = 'block';
    uploadZone.style.display = 'none';
    result.style.display = 'none';
    document.getElementById('fileAnalysis').style.display = 'none';
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
    
    if (!fileInput.files.length) {
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
            <p style="margin-top: 10px;">Analyzing file...</p>
            <p style="font-size: 14px; color: #6c757d;">Checking with VirusTotal + performing deep analysis</p>
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
            result.innerHTML = '<div style="color:red;">Error: ' + data.error + '</div>';
            return;
        }
        
        lastScanData = data;
        displayResults(data);
        displayFileAnalysis(data.file_analysis);
    })
    .catch(function(error) {
        console.error('Error:', error);
        result.innerHTML = '<div style="color:red;">Error connecting to backend. Please make sure the server is running.</div>';
    });
}

function displayResults(data) {
    var result = document.getElementById('scanResult');
    var vt = data.vt_results || {};
    var stats = vt.stats || {};
    var malicious = stats.malicious || 0;
    var suspicious = stats.suspicious || 0;
    var undetected = stats.undetected || 0;
    var isMalware = vt.is_malware || false;
    var total = malicious + suspicious + undetected;
    
    result.className = 'scan-result ' + (isMalware ? 'danger' : 'safe');
    result.innerHTML = `
        <div class="result-icon">${isMalware ? 'X' : 'Check'}</div>
        <h3>${isMalware ? 'Malware Detected!' : 'File is Safe!'}</h3>
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
            Source: ${vt.source || 'Bougg Database'} | ${malicious}/${total || 1} engines detected
        </div>
        
        ${isMalware ? `<button class="btn btn-primary" onclick="showDetails()" style="margin: 10px 0;">View Detected Threats (${malicious})</button>` : ''}
        
        <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
    `;
}

function displayFileAnalysis(analysis) {
    var container = document.getElementById('fileAnalysis');
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth' });
    
    var html = '<h3 style="color:#33a351; margin-top:20px;">Deep File Analysis</h3>';
    
    var info = analysis.file_info || {};
    var hashes = analysis.hashes || {};
    html += `
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>File Information</h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 13px;">
                <div><strong>File Type:</strong> ${analysis.file_type || 'Unknown'}</div>
                <div><strong>Size:</strong> ${info.file_size_human || 'N/A'}</div>
                <div><strong>Entropy:</strong> ${analysis.entropy || 'N/A'} ${analysis.entropy > 7.0 ? '(High - possible encryption)' : ''}</div>
                <div><strong>MD5:</strong> <span style="font-size: 11px;">${hashes.md5 || 'N/A'}</span></div>
                <div><strong>SHA1:</strong> <span style="font-size: 11px;">${hashes.sha1 || 'N/A'}</span></div>
                <div><strong>SHA256:</strong> <span style="font-size: 11px;">${hashes.sha256 || 'N/A'}</span></div>
            </div>
        </div>
    `;
    
    if (analysis.is_pe) {
        var pe_info = analysis.pe_info || {};
        html += `
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
                <h4>PE Information</h4>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 13px;">
                    <div><strong>Type:</strong> ${pe_info.pe_type || 'N/A'}</div>
                    <div><strong>Entry Point:</strong> ${pe_info.entry_point || 'N/A'}</div>
                    <div><strong>Image Base:</strong> ${pe_info.image_base || 'N/A'}</div>
                    <div><strong>Sections:</strong> ${pe_info.number_of_sections || 'N/A'}</div>
                    <div><strong>Machine:</strong> ${pe_info.machine || 'N/A'}</div>
                    <div><strong>Timestamp:</strong> ${pe_info.timestamp || 'N/A'}</div>
                </div>
            </div>
        `;
        
        var sections = analysis.pe_sections || [];
        if (sections.length > 0) {
            html += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <h4>Section Analysis</h4>
                    <div style="overflow-x: auto;">
                        <table style="width:100%; border-collapse:collapse; font-size:13px;">
                            <tr style="background:#33a351; color:white;">
                                <th style="padding:8px;">Name</th>
                                <th style="padding:8px;">Entropy</th>
                                <th style="padding:8px;">Size</th>
                                <th style="padding:8px;">Status</th>
                            </tr>
            `;
            sections.forEach(function(s) {
                var status = s.suspicious ? 'Suspicious' : 'Normal';
                var color = s.suspicious ? '#dc3545' : '#28a745';
                html += `
                    <tr style="border-bottom:1px solid #eee;">
                        <td style="padding:8px;"><strong>${s.name}</strong></td>
                        <td style="padding:8px;">${s.entropy}</td>
                        <td style="padding:8px;">${s.size_human}</td>
                        <td style="padding:8px; color:${color};">${status}</td>
                    </tr>
                `;
            });
            html += '</table></div></div>';
        }
        
        var apis = analysis.suspicious_apis || [];
        if (apis.length > 0) {
            html += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <h4>Suspicious APIs Detected</h4>
                    <ul style="list-style:none; padding:0;">
            `;
            apis.forEach(function(api) {
                html += '<li style="padding:5px; border-bottom:1px solid #eee;">[!] <strong>' + api.function + '</strong> [' + api.dll + '] -> ' + api.category + '</li>';
            });
            html += '</ul></div>';
        }
        
        if (analysis.packer_detected) {
            html += `
                <div style="background: #fff3cd; padding: 10px; border-radius: 8px; margin: 10px 0; border: 1px solid #ffc107;">
                    <strong>Packer Detected:</strong> ${analysis.packer_detected}
                </div>
            `;
        }
    }
    
    var risk = analysis.risk_level || 'Low';
    var riskColor = risk === 'Critical' ? '#dc3545' : risk === 'High' ? '#fd7e14' : risk === 'Medium' ? '#ffc107' : '#28a745';
    var riskSymbol = risk === 'Critical' ? '!!' : risk === 'High' ? '!' : risk === 'Medium' ? '?' : 'Ok';
    
    html += `
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>Risk Assessment</h4>
            <div style="padding:15px; border-radius:8px; background:${riskColor}20; border:2px solid ${riskColor};">
                <div style="font-size:24px; font-weight:700; color:${riskColor};">${riskSymbol} ${risk}</div>
                <div style="margin-top:10px;">
                    ${analysis.risk_factors && analysis.risk_factors.length > 0 ? analysis.risk_factors.map(function(f) { return '[!] ' + f; }).join('<br>') : 'No significant risk factors identified'}
                </div>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
}

function showDetails() {
    if (!lastScanData) return;
    
    var vt = lastScanData.vt_results || {};
    var details = vt.detailed_results || [];
    var modal = document.getElementById('detailsModal');
    var content = document.getElementById('detailsContent');
    
    if (details.length === 0) {
        content.innerHTML = '<p>No detailed results available.</p>';
        modal.style.display = 'block';
        return;
    }
    
    var html = `
        <div style="margin-bottom:20px;">
            <p><strong>File:</strong> ${lastScanData.filename}</p>
            <p><strong>SHA256:</strong> <span style="font-size:12px; word-break:break-all;">${lastScanData.sha256}</span></p>
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
        var categoryText = item.category === 'malicious' ? 'Malicious' : 'Suspicious';
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
        <p style="margin-top:15px; font-size:12px; color:#6c757d;">Showing ${details.length} threats detected</p>
    `;
    
    content.innerHTML = html;
    modal.style.display = 'block';
}

function closeDetails() {
    document.getElementById('detailsModal').style.display = 'none';
}

// ===== COUNTER ANIMATION =====
function initCounterAnimation() {
    var counters = document.querySelectorAll('.stat-number');
    
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
    
    var text = document.getElementById('feedbackText').value.trim();
    if (!text) {
        alert('Please enter your feedback.');
        return;
    }
    
    var successMsg = document.getElementById('feedbackSuccess');
    successMsg.classList.add('show');
    
    setTimeout(function() {
        document.getElementById('feedbackForm').reset();
        successMsg.classList.remove('show');
    }, 3000);
}

console.log('BOUGG Malware Detection Tool Loaded Successfully');
console.log('Unlimited scans - Enjoy!');
