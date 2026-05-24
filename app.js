document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.getAttribute('data-view');
            
            // Update active nav
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            // Show active view
            viewSections.forEach(v => v.style.display = 'none');
            document.getElementById(`view-${viewId}`).style.display = 'block';

            // Load data if needed
            if (viewId === 'history') loadHistory();
            if (viewId === 'dashboard') loadStats();
        });
    });

    // Scanner Logic
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const imagePreview = document.getElementById('image-preview');
    const dropContent = document.querySelector('.drop-content');
    const actionButtons = document.getElementById('action-buttons');
    const btnClear = document.getElementById('btn-clear');
    const btnAnalyze = document.getElementById('btn-analyze');
    
    // UI States
    const emptyState = document.getElementById('empty-results');
    const loadingState = document.getElementById('loading-state');
    const resultsData = document.getElementById('results-data');
    
    let currentFile = null;

    // Drag & Drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    dropZone.addEventListener('click', () => {
        if (!currentFile) fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    function handleFile(file) {
        if (!file.type.startsWith('image/')) {
            showToast('Please upload a valid image file (JPG, PNG, WEBP)', 'error');
            return;
        }

        if (file.size > 15 * 1024 * 1024) {
            showToast('File too large. Maximum size is 15MB', 'error');
            return;
        }

        currentFile = file;
        const reader = new FileReader();
        reader.onload = (e) => {
            imagePreview.src = e.target.result;
            imagePreview.style.display = 'block';
            dropContent.style.display = 'none';
            actionButtons.style.display = 'flex';
            
            // Reset results
            resultsData.style.display = 'none';
            emptyState.style.display = 'flex';
            loadingState.style.display = 'none';
        };
        reader.readAsDataURL(file);
    }

    btnClear.addEventListener('click', () => {
        currentFile = null;
        fileInput.value = '';
        imagePreview.style.display = 'none';
        imagePreview.src = '';
        dropContent.style.display = 'block';
        actionButtons.style.display = 'none';
        
        resultsData.style.display = 'none';
        loadingState.style.display = 'none';
        emptyState.style.display = 'flex';
    });

    // API Call
    btnAnalyze.addEventListener('click', async () => {
        if (!currentFile) return;

        // UI Update
        emptyState.style.display = 'none';
        resultsData.style.display = 'none';
        loadingState.style.display = 'flex';
        btnAnalyze.disabled = true;

        const formData = new FormData();
        formData.append('file', currentFile);

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || 'Analysis failed');
            }

            renderResults(data);
            showToast('Analysis complete', 'success');

        } catch (error) {
            console.error('API Error:', error);
            showToast(error.message, 'error');
            loadingState.style.display = 'none';
            emptyState.style.display = 'flex';
        } finally {
            btnAnalyze.disabled = false;
        }
    });

    function renderResults(data) {
        loadingState.style.display = 'none';
        resultsData.style.display = 'flex';

        // Verdict Card
        const verdictCard = document.getElementById('verdict-card');
        const verdictBadge = document.getElementById('verdict-badge');
        const aiSummary = document.getElementById('ai-summary');
        
        verdictCard.className = `verdict-card ${data.verdict.toLowerCase()}`;
        
        let icon = 'shield-question';
        if (data.verdict === 'FRAUD') icon = 'alert-triangle';
        else if (data.verdict === 'GENUINE') icon = 'shield-check';
        
        verdictBadge.innerHTML = `<i data-lucide="${icon}"></i> ${data.verdict}`;
        aiSummary.innerHTML = `<p>${data.gemini_summary || 'Analysis complete based on forensic rules.'}</p>`;

        // Circle Chart
        const circle = document.querySelector('.circle');
        const percentage = document.querySelector('.percentage');
        circle.setAttribute('stroke-dasharray', `${data.confidence}, 100`);
        percentage.textContent = `${Math.round(data.confidence)}%`;

        // Info Grid
        document.getElementById('info-amount').textContent = 
            data.transaction_details.amount ? `₹${data.transaction_details.amount.toFixed(2)}` : 'Unknown';
        document.getElementById('info-app').textContent = 
            data.transaction_details.app || 'Unknown';
        document.getElementById('info-utr').textContent = 
            data.transaction_details.transaction_id || 'Not Found';

        // Risk Factors List
        const reasonsList = document.getElementById('reasons-list');
        reasonsList.innerHTML = '';
        
        if (data.fraud_reasons && data.fraud_reasons.length > 0) {
            data.fraud_reasons.forEach(reason => {
                const item = document.createElement('div');
                item.className = `reason-item ${reason.severity.toLowerCase()}`;
                
                let rIcon = 'alert-circle';
                if (reason.severity === 'CRITICAL') rIcon = 'octagon-alert';
                else if (reason.severity === 'HIGH') rIcon = 'alert-triangle';

                item.innerHTML = `
                    <i data-lucide="${rIcon}"></i>
                    <div class="reason-content">
                        <h4>${reason.name}</h4>
                        <p>${reason.description}</p>
                    </div>
                `;
                reasonsList.appendChild(item);
            });
        } else if (data.verdict === 'GENUINE') {
            reasonsList.innerHTML = `
                <div class="reason-item" style="border-left-color: var(--success); background-color: rgba(16, 185, 129, 0.05);">
                    <i data-lucide="check-circle" style="color: var(--success)"></i>
                    <div class="reason-content">
                        <h4>No Fraud Indicators Found</h4>
                        <p>The screenshot passed all AI and forensic checks. It appears to be a legitimate payment confirmation.</p>
                    </div>
                </div>
            `;
        }

        // ELA Image
        const elaContainer = document.getElementById('ela-container');
        if (data.ela_image && data.ela_score > 25) {
            document.getElementById('ela-image').src = `data:image/png;base64,${data.ela_image}`;
            elaContainer.style.display = 'block';
        } else {
            elaContainer.style.display = 'none';
        }

        // Re-init icons for newly added HTML
        lucide.createIcons();
    }

    // History View
    document.getElementById('refresh-history').addEventListener('click', loadHistory);

    async function loadHistory() {
        try {
            const res = await fetch('/api/history?limit=20');
            const data = await res.json();
            
            const tbody = document.getElementById('history-tbody');
            tbody.innerHTML = '';
            
            if (data.scans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-secondary)">No scan history yet.</td></tr>';
                return;
            }

            data.scans.forEach(scan => {
                const date = new Date(scan.scan_time).toLocaleString();
                const tr = document.createElement('tr');
                
                const amt = scan.transaction_details.amount ? `₹${scan.transaction_details.amount}` : '-';
                const app = scan.transaction_details.app || 'Unknown';
                
                tr.innerHTML = `
                    <td>${date}</td>
                    <td>${scan.filename}</td>
                    <td>${app}</td>
                    <td>${amt}</td>
                    <td><span class="badge ${scan.verdict.toLowerCase()}">${scan.verdict}</span></td>
                    <td>${scan.risk_score}/100</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Failed to load history:', e);
        }
    }

    // Dashboard View
    async function loadStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            
            document.getElementById('stat-total').textContent = data.total_scans;
            document.getElementById('stat-fraud').textContent = data.fraud_detected;
            document.getElementById('stat-genuine').textContent = data.genuine_detected;
            document.getElementById('stat-risk').textContent = `${data.avg_risk_score}/100`;
            
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    }

    // Toast Notifications
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        let icon = 'info';
        if (type === 'error') icon = 'x-circle';
        if (type === 'success') icon = 'check-circle';
        
        toast.innerHTML = `
            <i data-lucide="${icon}"></i>
            <span>${message}</span>
        `;
        
        container.appendChild(toast);
        lucide.createIcons();
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
});
