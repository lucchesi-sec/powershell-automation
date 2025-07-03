// PowerShell Enterprise Automation Platform - Custom JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Enhanced Dark Mode with Default Setting
    initializeDarkMode();
    
    // Enhanced Search Functionality
    enhanceSearch();
    
    // Enhanced Navigation
    enhanceNavigation();
    
    // Smooth Scrolling
    enableSmoothScrolling();
    
    // Performance Monitoring
    monitorPerformance();
});

// Dark Mode Management
function initializeDarkMode() {
    // Set dark mode as default for enterprise look
    const savedTheme = localStorage.getItem('theme');
    if (!savedTheme) {
        localStorage.setItem('theme', 'auto'); // Respect system preference
    }
    
    // Enhanced theme switcher with smooth transitions
    const themeToggle = document.querySelector('[data-bs-theme-toggle]');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.style.transition = 'all 0.3s ease';
            setTimeout(() => {
                document.body.style.transition = '';
            }, 300);
        });
    }
}

// Enhanced Search Functionality
function enhanceSearch() {
    const searchInput = document.querySelector('#search-query');
    if (searchInput) {
        // Add search suggestions and better UX
        let searchTimeout;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                // Add visual feedback during search
                this.style.borderColor = '#00BCF2';
                setTimeout(() => {
                    this.style.borderColor = '';
                }, 200);
            }, 150);
        });
        
        // Enhanced keyboard navigation
        searchInput.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                this.blur();
            }
        });
    }
}

// Enhanced Navigation
function enhanceNavigation() {
    // Breadcrumb enhancement
    const breadcrumbs = document.querySelectorAll('.breadcrumb-item');
    breadcrumbs.forEach(item => {
        item.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(2px)';
        });
        
        item.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
    
    // Table of Contents enhancement
    const tocLinks = document.querySelectorAll('.toc a');
    let activeSection = null;
    
    // Highlight current section in TOC
    function updateTOC() {
        const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
        let current = null;
        
        headings.forEach(heading => {
            const rect = heading.getBoundingClientRect();
            if (rect.top <= 100) {
                current = heading;
            }
        });
        
        if (current && current !== activeSection) {
            tocLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current.id) {
                    link.classList.add('active');
                }
            });
            activeSection = current;
        }
    }
    
    window.addEventListener('scroll', updateTOC);
    updateTOC(); // Initial call
}

// Smooth Scrolling
function enableSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Performance Monitoring
function monitorPerformance() {
    // Monitor page load performance
    window.addEventListener('load', function() {
        const perfData = performance.getEntriesByType('navigation')[0];
        if (perfData && perfData.loadEventEnd > 2000) {
            console.log('Page load time:', perfData.loadEventEnd, 'ms');
        }
    });
    
    // Lazy load images
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                }
            });
        });
        
        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }
}

// Accessibility Enhancements
function enhanceAccessibility() {
    // Add skip link
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.textContent = 'Skip to main content';
    skipLink.className = 'sr-only sr-only-focusable';
    skipLink.style.cssText = `
        position: absolute;
        top: -40px;
        left: 6px;
        z-index: 1000;
        padding: 8px 16px;
        background: #0078D4;
        color: white;
        text-decoration: none;
        border-radius: 4px;
    `;
    
    skipLink.addEventListener('focus', function() {
        this.style.top = '6px';
    });
    
    skipLink.addEventListener('blur', function() {
        this.style.top = '-40px';
    });
    
    document.body.prepend(skipLink);
    
    // Ensure main content has ID
    const mainContent = document.querySelector('main') || document.querySelector('.main-panel');
    if (mainContent && !mainContent.id) {
        mainContent.id = 'main-content';
    }
}

// Initialize accessibility on load
document.addEventListener('DOMContentLoaded', enhanceAccessibility);

// PowerShell-specific functionality
function addPowerShellFeatures() {
    // Add PowerShell command autocomplete hints
    const codeInputs = document.querySelectorAll('input[type="text"][placeholder*="command"]');
    
    codeInputs.forEach(input => {
        const commands = [
            'Get-Process', 'Get-Service', 'Get-EventLog', 'Get-WinEvent',
            'Set-ExecutionPolicy', 'Get-Help', 'Get-Command', 'Get-Module',
            'Import-Module', 'New-Object', 'Where-Object', 'ForEach-Object',
            'Select-Object', 'Sort-Object', 'Measure-Object', 'Compare-Object'
        ];
        
        input.addEventListener('input', function() {
            const value = this.value.toLowerCase();
            if (value.length > 2) {
                const matches = commands.filter(cmd => 
                    cmd.toLowerCase().startsWith(value)
                );
                
                if (matches.length > 0) {
                    // Could add autocomplete dropdown here
                    console.log('PowerShell suggestions:', matches);
                }
            }
        });
    });
}
