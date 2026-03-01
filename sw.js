const CACHE_NAME = 'vvc-attendance-v9';
const ASSETS_TO_CACHE = [
    'scan.php',
    'manifest.json',
    'https://unpkg.com/html5-qrcode/html5-qrcode.min.js',
    'https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css',
    'assets/fonts/MomoTrustDisplay-Regular.woff2',
    'assets/fonts/MomoTrustDisplay-Regular.woff',
    'assets/fonts/MomoTrustDisplay-Regular.ttf',
    'https://cdn-icons-png.flaticon.com/512/11693/11693253.png'
];

// Install Event - Optional pre-caching
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            // We use a safe approach: try to cache but don't fail if some assets are missing
            const safeToCache = ASSETS_TO_CACHE.map(url => {
                return fetch(url).then(response => {
                    if (response.ok) return cache.put(url, response);
                }).catch(err => console.warn('Pre-cache failed for:', url, err));
            });
            return Promise.all(safeToCache);
        })
    );
    self.skipWaiting();
});

// Activate Event - Cleanup old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cache) => {
                    if (cache !== CACHE_NAME) {
                        return caches.delete(cache);
                    }
                })
            );
        })
    );
    return self.clients.claim();
});

// Fetch Event - Network First Strategy
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                // If network fetch succeeds, clone and update cache
                if (response.ok) {
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseClone);
                    });
                }
                return response;
            })
            .catch(() => {
                // If network fails (offline), try to serve from cache
                return caches.match(event.request);
            })
    );
});

// Push Event - Background notification handler
self.addEventListener('push', (event) => {
    console.log('[Service Worker] Push Received.');

    let data = {
        title: 'វត្តមាន (Attendance)',
        body: 'មានការជូនដំណឹងថ្មីសម្រាប់អ្នក!'
    };

    if (event.data) {
        try {
            const jsonData = event.data.json();
            data.title = jsonData.title || data.title;
            data.body = jsonData.body || data.body;
        } catch (e) {
            data.body = event.data.text() || data.body;
        }
    }

    const options = {
        body: data.body,
        icon: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
        badge: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
        vibrate: [200, 100, 200],
        tag: 'vvc-notif-' + Date.now(),
        renotify: true,
        data: {
            url: 'scan.php'
        }
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// Notification Click Event
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('scan.php')
    );
});
