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
    checkLoginStatus();
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
    document.querySelectorAll('nav a:not([onclick])').forEach(link => {
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
            document.getElementById('fileAnalysis').style.display = 'none';
            document.getElementById('peAnalysis').style.display = 'none';
        }
    });
}

var lastScanData = null;

// ===== AUTH FUNCTIONS =====
function showLogin() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('authMessage').style.display = 'none';
}

function showRegister() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('authMessage').style.display = 'none';
}

function openLoginModal() {
    document.getElementById('loginModal').style.display = 'block';
    showLogin();
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
}

function closeLoginModal() {
    document.getElementById('loginModal').style.display = 'none';
}

function showAuthMessage(message, isError) {
    var msg = document.getElementById('authMessage');
    msg.textContent = message;
    msg.style.display = 'block';
    msg.style.background = isError ? '#f8d7da' : '#d4edda';
    msg.style.color = isError ? '#721c24' : '#155724';
    msg.style.border = '1px solid ' + (isError ? '#f5c6cb' : '#c3e6cb');
}

function registerUser() {
    var username = document.getElementById('registerUsername').value.trim();
    var email = document.getElementById('registerEmail').value.trim();
    var password = document.getElementById('registerPassword').value;
    
    if (!username || !password) {
        showAuthMessage('Please fill in all required fields', true);
        return;
    }
    
    if (password.length < 6) {
        showAuthMessage('Password must be at least 6 characters', true);
        return;
    }
    
    fetch('/api/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, email, password})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAuthMessage('Registration successful! Please login.', false);
            setTimeout(showLogin, 1500);
        } else {
            showAuthMessage(data.error || 'Registration failed', true);
        }
    })
    .catch(() => showAuthMessage('Server error. Please try again.', true));
}

function loginUser() {
    var username = document.getElementById('loginUsername').value.trim();
    var password = document.getElementById('loginPassword').value;
    
    if (!username || !password) {
        showAuthMessage('Please enter username and password', true);
        return;
    }
    
    fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeLoginModal();
            updateUserUI(data.user);
            checkRemainingSearches();
            // Update login button
            document.getElementById('loginNavBtn').textContent = 'Logout';
            document.getElementById('loginNavBtn').onclick = function() { logoutUser(); return false; };
        } else {
            showAuthMessage(data.error || 'Invalid credentials', true);
        }
    })
    .catch(() => showAuthMessage('Server error. Please try again.', true));
}

function logoutUser() {
    fetch('/api/logout', {method: 'POST'})
    .then(() => {
        document.getElementById('userBar').style.display = 'none';
        document.getElementById('loginNavBtn').textContent = 'Login';
        document.getElementById('loginNavBtn').onclick = function() { openLoginModal(); return false; };
        location.reload();
    });
}

function updateUserUI(user) {
    document.getElementById('userBar').style.display = 'block';
    document.getElementById('usernameDisplay').textContent = user.username + (user.is_admin ? ' (Admin)' : '');
}

function checkRemainingSearches() {
    fetch('/api/remaining-searches')
    .then(response => response.json())
    .then(data => {
        if (data.remaining !== undefined) {
            var display = data.remaining === Infinity ? 'Unlimited searches' : data.remaining + ' searches remaining';
            document.getElementById('searchesRemaining').textContent = display;
        }
    })
    .catch(() => {});
}

function checkLoginStatus() {
    fetch('/api/user')
    .then(response => {
        if (response.status === 401) {
            return null;
        }
        return response.json();
    })
    .then(data => {
        if (data && data.id) {
            updateUserUI(data);
            checkRemainingSearches();
            document.getElementById('loginNavBtn').textContent = 'Logout';
            document.getElementById('loginNavBtn').onclick = function() { logoutUser(); return false; };
        }
    })
    .catch(() => {});
}

// ===== SCAN FUNCTION =====
function scanFile() {
    var fileInput = document.getElementById('fileInput');
    var result = document.getElementById('scanResult');
    
    // Check if user is logged in
    fetch('/api/user')
    .then(response => {
        if (response.status === 401) {
            openLoginModal();
            return Promise.reject('Please login first');
        }
        return response.json();
    })
    .then((userData) => {
        if (!userData || !userData.id) {
            openLoginModal();
            return Promise.reject('Please login first');
        }
        
        if (!fileInput.files.length) {
            alert('Please select a file first!');
            return;
        }
        
        var file = fileInput.files[0];
        var formData = new FormData();
        formData.append('file', file);
        
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
        document.getElementById('peAnalysis').style.display = 'none';
        
        fetch('/api/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                if (data.error.includes('limit')) {
                    alert('Daily search limit reached! Please try again tomorrow.');
                }
                result.innerHTML = `<div style="color:red;">Error: ${data.error}</div>`;
                return;
            }
            
            lastScanData = data;
            displayResults(data);
            displayFileAnalysis(data.file_analysis);
            checkRemainingSearches();
        })
        .catch(function(error) {
            console.error('Error:', error);
            result.innerHTML = `<div style="color:red;">Error connecting to backend. Please try again.</div>`;
        });
    })
    .catch(error => {
        if (error !== 'Please login first') {
            console.error('Auth error:', error);
        }
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
            ${data.remaining_searches !== undefined ? ' | Remaining: ' + data.remaining_searches : ''}
        </div>
        
        ${isMalware ? `<button class="btn btn-primary" onclick="showDetails()" style="margin: 10px 0;">View Detected Threats (${malicious})</button>` : ''}
        
        <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
    `;
}

function displayFileAnalysis(analysis) {
    var container = document.getElementById('fileAnalysis');
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth' });
    
    var html = `<h3 style="color:#33a351; margin-top:20px;">Deep File Analysis</h3>`;
    
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
            html += `</table></div></div>`;
        }
        
        var apis = analysis.suspicious_apis || [];
        if (apis.length > 0) {
            html += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <h4>Suspicious APIs Detected</h4>
                    <ul style="list-style:none; padding:0;">
            `;
            apis.forEach(function(api) {
                html += `<li style="padding:5px; border-bottom:1px solid #eee;">[!] <strong>${api.function}</strong> [${api.dll}] -> ${api.category}</li>`;
            });
            html += `</ul></div>`;
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

function resetScan() {
    document.getElementById('fileInput').value = '';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'block';
    document.getElementById('scanResult').style.display = 'none';
    document.getElementById('fileAnalysis').style.display = 'none';
    document.getElementById('peAnalysis').style.display = 'none';
    lastScanData = null;
}

function clearFile() {
    document.getElementById('fileInput').value = '';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'block';
    document.getElementById('scanResult').style.display = 'none';
    document.getElementById('fileAnalysis').style.display = 'none';
    document.getElementById('peAnalysis').style.display = 'none';
    lastScanData = null;
}

console.log('BOUGG Malware Detection Tool Loaded Successfully');
