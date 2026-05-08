importScripts("https://www.gstatic.com/firebasejs/9.0.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/9.0.0/firebase-messaging-compat.js");

firebase.initializeApp({
  apiKey: "AIzaSyBTlrKycJRtWAU7mRzlfrCEeC6GCWgQERA",
  messagingSenderId: "514446176088",
  projectId: "vvc-app-845aa",
  appId: "1:514446176088:web:974e860df1810804f33f2d",
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  console.log("[firebase-messaging-sw.js] Background Message:", payload);
  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
    icon: "/icons/Icon-192.png",
  };

  return self.registration.showNotification(
    notificationTitle,
    notificationOptions
  );
});
