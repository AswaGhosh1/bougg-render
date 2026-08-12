// ===== DOM READY =====
document.addEventListener('DOMContentLoaded', function() {
    // Hide preloader
    setTimeout(() => {
        document.getElementById('preloader').classList.add('hidden');
    }, 1000);

    // Initialize
    initNavigation();
    initRatingStars();
    initUploadZone();
    initCounterAnimation();
    initMobileMenu();
});

// ===== NAVIGATION =====
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-links a');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const pageId = this.dataset.page;
            if (pageId) {
                switchPage(pageId);
                // Update URL hash without scrolling
                history.pushState(null, '', '#' + pageId);
            }
        });
    });

    // Handle hash on load
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(hash)) {
        switchPage(hash);
    }
}

function switchPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    // Show target page
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add('active');
    }

    // Update nav links
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.page === pageId) {
            link.classList.add('active');
        }
    });

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ===== MOBILE MENU =====
function initMobileMenu() {
    const toggle = document.getElementById('menuToggle');
    const navLinks = document.getElementById('navLinks');

    if (toggle && navLinks) {
        toggle.addEventListener('click', function() {
            navLinks.classList.toggle('open');
            this.classList.toggle('active');
        });
    }
}

// ===== RATING STARS =====
function initRatingStars() {
    const stars = document.querySelectorAll('.rating-stars span');
    const hiddenInput = document.getElementById('feedbackRating');

    stars.forEach(star => {
        star.addEventListener('click', function() {
            const value = parseInt(this.dataset.value);
            hiddenInput.value = value;

            stars.forEach(s => {
                s.classList.toggle('active', parseInt(s.dataset.value) <= value);
            });
        });

        star.addEventListener('mouseenter', function() {
            const value = parseInt(this.dataset.value);
            stars.forEach(s => {
                s.style.opacity = parseInt(s.dataset.value) <= value ? '1' : '0.3';
            });
        });

        star.addEventListener('mouseleave', function() {
            const current = parseInt(hiddenInput.value);
            stars.forEach(s => {
                s.style.opacity = parseInt(s.dataset.value) <= current ? '1' : '0.3';
            });
        });
    });
}

// ===== UPLOAD ZONE =====
function initUploadZone() {
    const zone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');

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
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const uploadZone = document.getElementById('uploadZone');
    const result = document.getElementById('scanResult');

    if (!fileInput.files.length) return;

    const file = fileInput.files[0];
    const size = (file.size / 1024 / 1024).toFixed(2);
    const sizeUnit = file.size > 1024 * 1024 ? 'MB' : 'KB';
    const displaySize = file.size > 1024 * 1024 ? size : (file.size / 1024).toFixed(1);

    fileName.textContent = file.name;
    fileSize.textContent = `${displaySize} ${sizeUnit}`;
    fileInfo.style.display = 'block';
    uploadZone.style.display = 'none';
    result.style.display = 'none';
}

function clearFile() {
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const uploadZone = document.getElementById('uploadZone');
    const result = document.getElementById('scanResult');

    fileInput.value = '';
    fileInfo.style.display = 'none';
    uploadZone.style.display = 'block';
    result.style.display = 'none';
}

function resetScan() {
    clearFile();
}

// ===== SCAN FUNCTION WITH VIRUSTOTAL =====
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

    // Show loading state
    result.style.display = 'block';
    result.className = 'scan-result';
    result.innerHTML = `
    <div style="text-align: center; padding: 20px;">
    <div style="width:40px; height:40px; border:4px solid #f3f3f3; border-top:4px solid #33a351; border-radius:50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
    <p style="margin-top: 10px;">🔄 Scanning with VirusTotal...</p>
    <p style="font-size: 14px; color: #6c757d;">Checking 70+ antivirus engines</p>
    </div>
    `;

    // Call the VirusTotal backend
    fetch('http://localhost:5000/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            // If backend fails, fallback to local detection
            console.warn('VirusTotal backend error:', data.error);
            performLocalScan(file);
            return;
        }

        // Display VirusTotal results
        displayVirusTotalResults(data, file);
    })
    .catch(error => {
        console.error('VirusTotal connection error:', error);
        // Fallback to local detection
        performLocalScan(file);
    });
}

// ===== VIRUSTOTAL RESULTS DISPLAY =====
function displayVirusTotalResults(data, file) {
    const result = document.getElementById('scanResult');
    const stats = data.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const isMalware = data.is_malware || false;
    const total = malicious + suspicious + undetected;

    // Determine risk level
    let riskLevel = 'Low';
    let riskColor = '#28a745';
    if (malicious > 5) { riskLevel = 'Critical'; riskColor = '#dc3545'; }
    else if (malicious > 2) { riskLevel = 'High'; riskColor = '#fd7e14'; }
    else if (malicious > 0) { riskLevel = 'Medium'; riskColor = '#ffc107'; }

    result.style.display = 'block';
    result.className = 'scan-result ' + (isMalware ? 'danger' : 'safe');

    result.innerHTML = `
    <div class="result-icon">${isMalware ? '🚨' : '✅'}</div>
    <h3>${isMalware ? `⚠️ Malware Detected! (${riskLevel} Risk)` : '✅ File is Safe!'}</h3>
    <p>${isMalware ? `${malicious} antivirus engines detected threats` : 'No threats detected by any engine'}</p>

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
    <strong>Source:</strong> ${data.source || 'VirusTotal'} |
    <strong>Detection:</strong> ${data.detection_ratio || `${malicious}/${total}`} engines
    ${data.scan_date ? `| <strong>Scanned:</strong> ${new Date(data.scan_date).toLocaleString()}` : ''}
    </div>

    <div style="font-size: 12px; color: #6c757d; margin: 5px 0; word-break: break-all; text-align: left; background: #f8f9fa; padding: 10px; border-radius: 5px;">
    <strong>File:</strong> ${data.filename || file.name}<br>
    <strong>Size:</strong> ${(file.size / 1024 / 1024).toFixed(2)} MB<br>
    <strong>MD5:</strong> ${data.hashes?.md5 || 'N/A'}<br>
    <strong>SHA256:</strong> ${data.hashes?.sha256 || 'N/A'}
    </div>

    <button class="btn btn-secondary" onclick="resetScan()" style="margin-top: 15px;">Scan Another File</button>
    `;

    // Update detail fields if they exist
    if (document.getElementById('detailName')) {
        document.getElementById('detailName').textContent = data.filename || file.name;
        document.getElementById('detailSize').textContent = (file.size / 1024 / 1024).toFixed(2) + ' MB';
        document.getElementById('detailType').textContent = data.hashes?.sha256 ? 'PE File' : 'Unknown';
        document.getElementById('detailTime').textContent = new Date().toLocaleTimeString();
    }
}

// ===== LOCAL FALLBACK SCAN (Original Logic) =====
function performLocalScan(file) {
    const result = document.getElementById('scanResult');
    const name = file.name.toLowerCase();
    const ext = name.substring(name.lastIndexOf('.'));
    const size = file.size;

    const badNames = [
        'virus.exe', 'trojan.bat', 'malware.docm', 'ransomware.scr',
        'worm.vbs', 'backdoor.js', 'keylogger.exe', 'spyware.dll',
        'rootkit.sys', 'adware.cpl', 'exploit.jar', 'payload.exe'
    ];

    const badExt = [
        '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.ps1',
        '.jar', '.docm', '.cpl', '.pif', '.com', '.sh', '.pl'
    ];

    let reasons = [];
    let danger = false;

    if (badNames.includes(name)) {
        danger = true;
        reasons.push('Known malware filename detected');
    }

    if (badExt.includes(ext)) {
        danger = true;
        reasons.push('Suspicious file extension');
    }

    if (size < 1024 && size > 0) {
        danger = true;
        reasons.push('Unusually small file size (potential threat)');
    }

    if (name.includes('update') && badExt.includes(ext)) {
        danger = true;
        reasons.push('Suspicious update file');
    }

    if (name.includes('crack') || name.includes('patch')) {
        danger = true;
        reasons.push('Potentially unsafe software');
    }

    result.style.display = 'block';
    result.className = 'scan-result ' + (danger ? 'danger' : 'safe');

    document.getElementById('resultIcon').textContent = danger ? '🚨' : '✅';
    document.getElementById('resultTitle').textContent = danger ? '⚠️ Malware Detected!' : '✅ File is Safe!';
    document.getElementById('resultMessage').textContent = danger
    ? 'Threat detected: ' + reasons.join(', ')
    : 'No threats detected. File appears to be safe.';

    document.getElementById('detailName').textContent = file.name;
    document.getElementById('detailSize').textContent = (size / 1024 / 1024).toFixed(2) + ' MB';
    document.getElementById('detailType').textContent = ext || 'Unknown';
    document.getElementById('detailTime').textContent = new Date().toLocaleTimeString();

    trackScan(danger);
}

function trackScan(danger) {
    console.log('Scan completed:', {
        timestamp: new Date().toISOString(),
                danger: danger,
                fileType: document.getElementById('detailType').textContent
    });
}

// ===== COUNTER ANIMATION =====
function initCounterAnimation() {
    const counters = document.querySelectorAll('.stat-number');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = parseInt(entry.target.dataset.target);
                animateCounter(entry.target, target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
}

function animateCounter(element, target) {
    let current = 0;
    const increment = target / 60;
    const duration = 1500;
    const steps = 60;
    const stepTime = duration / steps;

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = Math.round(current).toLocaleString() + (target === 99.9 ? '%' : '');
    }, stepTime);
}

// ===== FEEDBACK FORM =====
function submitFeedback(event) {
    event.preventDefault();

    const name = document.getElementById('feedbackName').value.trim();
    const email = document.getElementById('feedbackEmail').value.trim();
    const category = document.getElementById('feedbackCategory').value;
    const rating = document.getElementById('feedbackRating').value;
    const text = document.getElementById('feedbackText').value.trim();

    if (!text) {
        alert('⚠️ Please enter your feedback.');
        return;
    }

    // Show success
    const successMsg = document.getElementById('feedbackSuccess');
    successMsg.classList.add('show');

    // Prepare email
    const subject = encodeURIComponent(`BOUGG Feedback - ${category}`);
    const body = encodeURIComponent(
        `Feedback Category: ${category}\n` +
        `Rating: ${'⭐'.repeat(parseInt(rating))}\n` +
        `Name: ${name || 'Anonymous'}\n` +
        `Email: ${email || 'Not provided'}\n\n` +
        `Feedback:\n${text}`
    );

    // Open email
    window.location.href = `mailto:boouggmalwaretool@gmail.com?subject=${subject}&body=${body}`;

    // Reset form after delay
    setTimeout(() => {
        document.getElementById('feedbackForm').reset();
        successMsg.classList.remove('show');
        document.querySelectorAll('.rating-stars span').forEach(s => s.classList.remove('active'));
        document.getElementById('feedbackRating').value = '5';
    }, 3000);
}

// ===== NEWSLETTER =====
function subscribeNewsletter(event) {
    event.preventDefault();
    const input = event.target.querySelector('input');
    const email = input.value.trim();

    if (email) {
        alert(`✅ Thank you for subscribing with ${email}!`);
        input.value = '';
    }
}

// ===== KEYBOARD SHORTCUTS =====
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey || e.metaKey) {
        const pages = ['home', 'scan', 'features', 'feedback', 'about'];
        const num = parseInt(e.key);
        if (num >= 1 && num <= pages.length) {
            e.preventDefault();
            switchPage(pages[num - 1]);
            history.pushState(null, '', '#' + pages[num - 1]);
        }
    }
});

// ===== CONSOLE WELCOME =====
console.log('%c🛡️ BOUGG Malware Detection Tool', 'font-size:24px; font-weight:bold; color:#33a351;');
console.log('%c🔒 Enterprise Grade Security | Free & Private', 'font-size:14px; color:#6c757d;');
console.log('%c📱 Ctrl+1-5 for quick navigation', 'font-size:12px; color:#6c757d;');
