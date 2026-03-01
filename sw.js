const CACHE_NAME = 'vvc-attendance-v8';
const ASSETS_TO_CACHE = [
    'scan.php',
    'https://unpkg.com/html5-qrcode/html5-qrcode.min.js',
    'https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css'
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

// Push Event - This is what happens when a notification is sent from the server
self.addEventListener('push', (event) => {
    let data = { title: 'ព័ត៌មានថ្មី', body: 'មានការអាប់ដេតថ្មីពីប្រព័ន្ធ។' };

    if (event.data) {
        try {
            data = event.data.json();
        } catch (e) {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body,
        icon: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
        badge: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now(),
            primaryKey: '2'
        },
        actions: [
            { action: 'explore', title: 'មើលព័ត៌មាន', icon: '' },
            { action: 'close', title: 'បិទ', icon: '' },
        ]
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
