/**
 * Content Script for FraudShield Extension
 * 
 * This script runs in the context of web pages and can:
 * - Scan email content on webmail sites
 * - Analyze page content for phishing indicators
 * - Add visual warnings to suspicious links
 */

// Configuration for which sites to enable email scanning
const EMAIL_PROVIDERS = [
  'mail.google.com',
  'outlook.live.com',
  'outlook.office.com',
  'mail.yahoo.com',
  'protonmail.com'
];

// Initialize content script
function initialize() {
  const currentDomain = window.location.hostname;
  
  // Check if we're on a webmail site
  if (EMAIL_PROVIDERS.some(provider => currentDomain.includes(provider))) {
    setupEmailScanning();
  }
  
  // General page scanning for all sites
  scanPageForPhishingIndicators();
  
  // Add event listeners for dynamic content
  observePageChanges();
}

/**
 * Sets up email scanning functionality for webmail providers
 */
function setupEmailScanning() {
  console.log('FraudShield: Email scanning initialized');
  
  // This would implement provider-specific selectors and event listeners
  // For demonstration purposes, we're just logging that it's initialized
  
  // In a real extension, this would:
  // 1. Find email message containers based on the specific webmail provider
  // 2. Extract sender, subject, and content
  // 3. Send to background script for analysis
  // 4. Add visual warnings if suspicious
}

/**
 * Scans the page for common phishing indicators
 */
function scanPageForPhishingIndicators() {
  // Look for login forms
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[id*="email"]');
    
    if (hasPasswordField && hasEmailField) {
      // This appears to be a login form, check if it's on a suspicious domain
      analyzeLoginForm(form);
    }
  });
  
  // Check for suspicious links
  const links = document.querySelectorAll('a[href]');
  links.forEach(link => {
    const href = link.getAttribute('href');
    if (href && href.startsWith('http')) {
      analyzeLink(link, href);
    }
  });
}

/**
 * Analyzes a login form for potential security issues
 * @param {HTMLFormElement} form - The form to analyze
 */
function analyzeLoginForm(form) {
  // Check if form submits to a different domain (potential phishing)
  const formAction = form.getAttribute('action');
  
  if (formAction && formAction.startsWith('http')) {
    try {
      const formDomain = new URL(formAction).hostname;
      const pageDomain = window.location.hostname;
      
      if (formDomain !== pageDomain && !formDomain.endsWith('.' + pageDomain)) {
        // Form submits to a different domain, which could be suspicious
        warnAboutSuspiciousForm(form);
      }
    } catch (e) {
      console.error('Error analyzing form:', e);
    }
  }
  
  // Check if the form is secure (HTTPS)
  if (window.location.protocol !== 'https:') {
    warnAboutInsecureForm(form);
  }
}

/**
 * Adds a warning about a suspicious form
 * @param {HTMLFormElement} form - The suspicious form
 */
function warnAboutSuspiciousForm(form) {
  const warningElement = document.createElement('div');
  warningElement.className = 'fraudshield-warning';
  warningElement.style.cssText = `
    background-color: #FFE0E0;
    border: 1px solid #FF5252;
    color: #D32F2F;
    padding: 10px;
    margin: 10px 0;
    border-radius: 4px;
    font-family: Arial, sans-serif;
  `;
  warningElement.textContent = '⚠️ Warning: This form submits to a different website. Be careful about entering sensitive information.';
  
  form.parentNode.insertBefore(warningElement, form);
}

/**
 * Adds a warning about an insecure form
 * @param {HTMLFormElement} form - The insecure form
 */
function warnAboutInsecureForm(form) {
  const warningElement = document.createElement('div');
  warningElement.className = 'fraudshield-warning';
  warningElement.style.cssText = `
    background-color: #FFF3E0;
    border: 1px solid #FFB74D;
    color: #E65100;
    padding: 10px;
    margin: 10px 0;
    border-radius: 4px;
    font-family: Arial, sans-serif;
  `;
  warningElement.textContent = '⚠️ Warning: This form is not secure (not using HTTPS). Your information could be intercepted.';
  
  form.parentNode.insertBefore(warningElement, form);
}

/**
 * Analyzes a link for potential security issues
 * @param {HTMLAnchorElement} linkElement - The link element
 * @param {string} href - The href attribute value
 */
function analyzeLink(linkElement, href) {
  // Simple checks for obviously suspicious links
  const suspiciousPatterns = [
    /\.(tk|ml|ga|cf|gq)$/i,
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/,
    /paypal.*\.(?!paypal\.com)/i,
    /amazon.*\.(?!amazon\.com)/i,
    /apple.*\.(?!apple\.com)/i,
    /microsoft.*\.(?!microsoft\.com)/i,
    /netflix.*\.(?!netflix\.com)/i,
    /google.*\.(?!google\.com)/i,
    /facebook.*\.(?!facebook\.com)/i
  ];
  
  try {
    const url = new URL(href);
    const domain = url.hostname;
    
    // Check against suspicious patterns
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(domain));
    
    if (isSuspicious) {
      // Add a visual warning to the link
      highlightSuspiciousLink(linkElement);
    }
  } catch (e) {
    // Invalid URL, ignore
  }
}

/**
 * Highlights a suspicious link with a warning style
 * @param {HTMLAnchorElement} linkElement - The suspicious link element
 */
function highlightSuspiciousLink(linkElement) {
  // Save original styles to restore on mouseout
  const originalStyle = {
    backgroundColor: linkElement.style.backgroundColor,
    border: linkElement.style.border,
    color: linkElement.style.color,
    textDecoration: linkElement.style.textDecoration
  };
  
  // Add warning styles
  linkElement.style.backgroundColor = '#FFF3E0';
  linkElement.style.border = '1px dashed #FF5252';
  linkElement.style.padding = '0 3px';
  linkElement.style.borderRadius = '2px';
  linkElement.style.color = '#D32F2F';
  linkElement.style.textDecoration = 'line-through';
  
  // Add warning tooltip
  linkElement.title = 'Warning: This link may be suspicious - FraudShield';
  
  // Add warning icon
  const warningIcon = document.createElement('span');
  warningIcon.textContent = ' ⚠️ ';
  warningIcon.style.fontSize = '0.8em';
  linkElement.appendChild(warningIcon);
  
  // Add click confirmation
  linkElement.addEventListener('click', function(e) {
    const proceed = confirm('This link appears suspicious. Are you sure you want to proceed?');
    if (!proceed) {
      e.preventDefault();
    }
  });
  
  // Optional: Restore original style on mouseout (less intrusive)
  // linkElement.addEventListener('mouseout', function() {
  //   linkElement.style.backgroundColor = originalStyle.backgroundColor;
  //   linkElement.style.border = originalStyle.border;
  //   linkElement.style.color = originalStyle.color;
  //   linkElement.style.textDecoration = originalStyle.textDecoration;
  // });
}

/**
 * Sets up a mutation observer to monitor page changes
 * This allows us to scan dynamically loaded content
 */
function observePageChanges() {
  // Create a MutationObserver to watch for changes to the DOM
  const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      // If nodes were added, scan them for phishing indicators
      if (mutation.addedNodes && mutation.addedNodes.length > 0) {
        mutation.addedNodes.forEach(function(node) {
          // Only process element nodes
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Check if the added node contains forms
            const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
            forms.forEach(analyzeLoginForm);
            
            // Check if the added node contains links
            const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
            links.forEach(link => {
              const href = link.getAttribute('href');
              if (href && href.startsWith('http')) {
                analyzeLink(link, href);
              }
            });
          }
        });
      }
    });
  });
  
  // Start observing the document with the configured parameters
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Initialize the content script
initialize();

console.log('FraudShield content script initialized');