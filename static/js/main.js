// Maritime IDS JavaScript

// DOM Ready
$(document).ready(function() {
    console.log('Maritime IDS - System Ready');
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        $('.alert:not(.alert-permanent)').fadeOut('slow');
    }, 5000);
    
    // Add animation to cards on scroll
    observeElements();
});

// Observe elements for scroll animations
function observeElements() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in-up');
            }
        });
    });
    
    document.querySelectorAll('.card, .attack-card').forEach((el) => {
        observer.observe(el);
    });
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
    }
    form.classList.add('was-validated');
}

// Password strength indicator
function checkPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]+/)) strength++;
    if (password.match(/[A-Z]+/)) strength++;
    if (password.match(/[0-9]+/)) strength++;
    if (password.match(/[$@#&!]+/)) strength++;
    
    return strength;
}

// Show loading spinner
function showLoading(button) {
    const originalText = button.innerHTML;
    button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
    button.disabled = true;
    button.dataset.originalText = originalText;
}

// Hide loading spinner
function hideLoading(button) {
    button.innerHTML = button.dataset.originalText;
    button.disabled = false;
}

// API call helper
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(endpoint, options);
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('API call error:', error);
        throw error;
    }
}

// Show toast notification
function showToast(message, type = 'info') {
    const toastHtml = `
        <div class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    
    const toastContainer = document.getElementById('toastContainer');
    if (toastContainer) {
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toastElement = toastContainer.lastElementChild;
        const toast = new bootstrap.Toast(toastElement);
        toast.show();
    }
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

// Export data as CSV
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
}

function convertToCSV(data) {
    const headers = Object.keys(data[0]);
    const csvRows = [headers.join(',')];
    
    for (const row of data) {
        const values = headers.map(header => {
            const val = row[header];
            return `"${val}"`;
        });
        csvRows.push(values.join(','));
    }
    
    return csvRows.join('\n');
}

// Debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Smooth scroll
function smoothScroll(target) {
    document.querySelector(target).scrollIntoView({
        behavior: 'smooth'
    });
}

// Initialize charts (placeholder for Chart.js integration)
function initChart(canvasId, data, options) {
    // This will be implemented when adding Chart.js
    console.log('Chart initialized:', canvasId);
}

// Handle form submission with AJAX
function submitFormAjax(formId, successCallback) {
    const form = document.getElementById(formId);
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(form);
        const data = Object.fromEntries(formData);
        
        try {
            const result = await apiCall(form.action, form.method, data);
            if (successCallback) {
                successCallback(result);
            }
        } catch (error) {
            showToast('An error occurred. Please try again.', 'danger');
        }
    });
}

// Real-time updates (to be used with WebSocket)
let wsConnection = null;

function connectWebSocket(url) {
    wsConnection = new WebSocket(url);
    
    wsConnection.onopen = function() {
        console.log('WebSocket connected');
        showToast('Real-time monitoring active', 'success');
    };
    
    wsConnection.onmessage = function(event) {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    wsConnection.onerror = function(error) {
        console.error('WebSocket error:', error);
        showToast('Connection error', 'danger');
    };
    
    wsConnection.onclose = function() {
        console.log('WebSocket disconnected');
        // Attempt to reconnect after 5 seconds
        setTimeout(() => connectWebSocket(url), 5000);
    };
}

function handleWebSocketMessage(data) {
    // Handle incoming WebSocket messages
    console.log('WebSocket message:', data);
}

// Health check
async function checkSystemHealth() {
    try {
        const health = await apiCall('/api/health');
        return health.status === 'healthy';
    } catch (error) {
        return false;
    }
}

// Auto-refresh
function startAutoRefresh(callback, interval = 5000) {
    return setInterval(callback, interval);
}

function stopAutoRefresh(intervalId) {
    clearInterval(intervalId);
}
