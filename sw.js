const CACHE_NAME = 'vvc-attendance-v11';
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

// Install Event - Pre-cache everything
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS_TO_CACHE);
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

// Fetch Event - Stale-While-Revalidate Strategy (Instant Load)
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;

    // Logic: Serve from cache immediately, then update cache from network in background
    event.respondWith(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.match(event.request).then((cachedResponse) => {
                const fetchPromise = fetch(event.request).then((networkResponse) => {
                    if (networkResponse.ok) {
                        cache.put(event.request, networkResponse.clone());
                    }
                    return networkResponse;
                }).catch(() => {
                    // If network fails, we already have the cachedResponse (even if it's undefined)
                });

                // Return cached version IF it exists, otherwise wait for network
                return cachedResponse || fetchPromise;
            });
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
