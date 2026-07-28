(function() {
    'use strict';

    const API_BASE = 'https://sciverseacademy.pages.dev/api';

    // ── PERSISTENT DEVICE ID ──
    // Generated once per browser/device and stored in localStorage. This is
    // what the backend now uses for the device lock instead of User-Agent + IP —
    // it doesn't change when the user switches wifi/mobile data (unlike IP),
    // and isn't shared across every phone of the same model (unlike UA).
    // It only changes if site data / localStorage is cleared, which is a
    // deliberate action, not something that happens from normal use.
    function getDeviceId() {
        try {
            let id = localStorage.getItem('sv_device_id');
            if (!id) {
                id = (window.crypto && window.crypto.randomUUID)
                    ? window.crypto.randomUUID()
                    : 'dev-' + Date.now() + '-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
                localStorage.setItem('sv_device_id', id);
            }
            return id;
        } catch (e) {
            // localStorage unavailable (private mode edge cases) — fall back to
            // a per-session id rather than breaking the request entirely.
            if (!window.__sv_session_device_id) {
                window.__sv_session_device_id = 'session-' + Date.now() + '-' + Math.random().toString(36).slice(2);
            }
            return window.__sv_session_device_id;
        }
    }

    const originalFetch = window.fetch;

    window.fetch = function(url, options) {
        if (typeof url === 'string' && url.startsWith('/api/')) {
            url = API_BASE + url.substring(4);
        } else if (typeof url === 'string' && url.startsWith('/api')) {
            url = API_BASE + url.substring(3);
        } else if (typeof url === 'string' && url === '/api') {
            url = API_BASE;
        }

        const isApiCall = typeof url === 'string' && url.indexOf(API_BASE) === 0;

        if (isApiCall) {
            options = options || {};
            const headers = options.headers;
            if (headers instanceof Headers) {
                if (!headers.has('X-Device-Id')) headers.set('X-Device-Id', getDeviceId());
            } else {
                options.headers = Object.assign({}, headers || {}, { 'X-Device-Id': getDeviceId() });
            }
        }

        return originalFetch.call(this, url, options);
    };
})();
