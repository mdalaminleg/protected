(function() {
    'use strict';
    
    const API_BASE = 'https://sciverseacademy.pages.dev/api';
    const originalFetch = window.fetch;
    
    window.fetch = function(url, options) {
        if (typeof url === 'string' && url.startsWith('/api/')) {
            url = API_BASE + url.substring(4);
        } else if (typeof url === 'string' && url.startsWith('/api')) {
            url = API_BASE + url.substring(3);
        } else if (typeof url === 'string' && url === '/api') {
            url = API_BASE;
        }
        return originalFetch.call(this, url, options);
    };
})();
