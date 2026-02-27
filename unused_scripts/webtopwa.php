<?php
// Simple standalone PWA installer/launcher page
// Language: Khmer + English
?>
<!DOCTYPE html>
<html lang="km">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta name="theme-color" content="#3498db">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Attendance">
  <link rel="apple-touch-icon" href="icons/icon-192.png">
  <link rel="manifest" href="manifest.php">
  <title>Web → PWA Installer</title>
  <link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <style>
    :root{
      --primary:#3498db;--primary-dark:#2d82c2;--bg:#f5f7fb;--card:#ffffff;--text:#1f2d3d;--muted:#5b6b7b;
      --radius:16px;--shadow:0 10px 30px rgba(31,45,61,.08)
    }
    html,body{height:100%}
    body{margin:0;font-family:'Kantumruy Pro',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
    .wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:22px}
    .card{width:100%;max-width:520px;background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow);padding:26px 22px 22px}
    .head{display:flex;align-items:center;gap:14px;margin-bottom:10px}
    .logo{width:56px;height:56px;border-radius:14px;object-fit:cover;box-shadow:0 6px 20px rgba(0,0,0,.12);background:#ecf0f3}
    h1{font-size:1.25rem;margin:0}
    .sub{margin:4px 0 0;color:var(--muted);font-size:.92rem}
    .actions{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
    .btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:11px;padding:12px 16px;font-weight:700;cursor:pointer}
    .btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff;box-shadow:0 8px 20px rgba(52,152,219,.3)}
    .btn-ghost{background:#ecf0f3;color:#1f2d3d}
    .note{margin-top:14px;font-size:.9rem;color:var(--muted)}

    /* Overlay */
    #pwa-install-prompt{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);z-index:5000;align-items:center;justify-content:center}
    .pwa-modal{background:#fff;width:92%;max-width:380px;border-radius:20px;padding:26px 24px 22px;box-shadow:0 18px 48px -8px rgba(0,0,0,.25);position:relative;animation:pwaPop .35s cubic-bezier(.34,1.56,.64,1)}
    @keyframes pwaPop{from{transform:translateY(22px) scale(.92);opacity:0}to{transform:translateY(0) scale(1);opacity:1}}
    .pwa-close{position:absolute;top:10px;right:10px;background:rgba(0,0,0,.06);border:none;width:34px;height:34px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px}
    .pwa-icon{width:74px;height:74px;border-radius:22px;box-shadow:0 6px 18px rgba(0,0,0,.18);object-fit:cover;margin-bottom:12px}
    .pwa-title{margin:0 0 6px;font-size:1.15rem;font-weight:800;color:#143451;text-align:center}
    .pwa-desc{margin:0;color:#4b5b6a;font-size:.86rem;line-height:1.45;text-align:center}
    .pwa-actions{margin-top:18px;display:flex;gap:10px;flex-wrap:wrap}
    .pwa-btn{display:inline-flex;align-items:center;gap:8px;padding:12px 18px;border-radius:10px;border:none;cursor:pointer;font-weight:700;font-size:.95rem}
    .pwa-btn-primary{background:linear-gradient(135deg,#3498db,#2d82c2);color:#fff;box-shadow:0 4px 14px rgba(52,152,219,.35)}
    .pwa-btn-text{background:#ecf0f3;color:#2c3e50}
    #iosSteps{display:none;margin-top:10px;color:#34495e;font-size:.95rem}
    #iosSteps ol{margin:8px 0 0 20px;padding:0}
    #iosSteps li{margin:6px 0}
    #iosSteps .hint{margin-top:8px;color:#5d6d7e;font-size:.85rem}
  </style>
  <script>
  // Register Service Worker ASAP
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('sw.js').catch(e=>console.warn('SW registration failed', e));
    });
  }
  </script>
</head>
<body>
  <div class="wrap">
    <div class="card" role="region" aria-label="PWA installer">
      <div class="head">
        <img src="icons/icon-192.png" class="logo" alt="App Icon" onerror="this.style.display='none'">
        <div>
          <h1>បម្លែង Web ទៅ App (PWA)</h1>
          <p class="sub">Convert your website into a mobile-like app. Install on iOS & Android.</p>
        </div>
      </div>

      <div class="actions">
        <button id="openPwaInstall" class="btn btn-primary"><i class="fa-solid fa-download"></i> Install App</button>
        <a href="scan.php" class="btn btn-ghost"><i class="fa-solid fa-up-right-from-square"></i> Open App</a>
      </div>
      <div class="note">After installation, the app opens from your Home Screen without the browser UI and works offline (where supported).</div>
    </div>
  </div>

  <!-- Modal / Overlay -->
  <div id="pwa-install-prompt">
    <div class="pwa-modal" role="dialog" aria-labelledby="pwaTitle" aria-modal="true">
      <button id="pwaDismissBtn" class="pwa-close" aria-label="Close">×</button>
      <div style="text-align:center;display:flex;flex-direction:column;align-items:center;">
        <img src="icons/icon-192.png" alt="App Icon" class="pwa-icon" onerror="this.style.display='none'">
        <h3 id="pwaTitle" class="pwa-title">ដំឡើងកម្មវិធី</h3>
        <p class="pwa-desc">បន្ថែមទៅអេក្រង់ដើម ដើម្បីចូលប្រើរហ័ស និង Offline បាន។</p>
      </div>
      <div class="pwa-actions">
        <button id="pwaInstallBtn" class="pwa-btn pwa-btn-primary"><i class="fa-solid fa-download"></i> Install</button>
        <button id="pwaLaterBtn" class="pwa-btn pwa-btn-text">ពេលក្រោយ</button>
      </div>
      <div id="iosSteps">
        <ol>
          <li>ចុចប៊ូតុង Share ក្នុង browser (រូបសញ្ញា ក្រៅចង្អុលឡើង).</li>
          <li>រមលតាមម៉ឺនុយ ហើយជ្រើស “Add to Home Screen”.</li>
          <li>ចុច Add ដើម្បីបន្ថែមកម្មវិធីទៅអេក្រង់ដើម។</li>
        </ol>
        <div class="hint">iPhone/iPad មិនមាន popup Install ដោយស្វ័យប្រវត្តិទេ — សូមអនុវត្តតាមជំហានខាងលើ។</div>
      </div>
    </div>
  </div>

  <script>
    let deferredPrompt = null;

    function isIOS() {
      return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    }

    function isStandalone() {
      return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
    }

    // Handle Android prompt event
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
      const btn = document.getElementById('openPwaInstall');
      if (btn) btn.style.display = 'inline-flex';
    });

    // Show header/button on iOS too
    document.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('openPwaInstall');
      if (isStandalone()) {
        if (btn) btn.style.display = 'none';
        return;
      }
      if (isIOS()) {
        if (btn) btn.style.display = 'inline-flex';
      }
    });

    // Open overlay on click
    document.getElementById('openPwaInstall').addEventListener('click', () => {
      const overlay = document.getElementById('pwa-install-prompt');
      const iosSteps = document.getElementById('iosSteps');
      const installBtn = document.getElementById('pwaInstallBtn');
      overlay.style.display = 'flex';

      if (isIOS()) {
        iosSteps.style.display = 'block';
        installBtn.style.display = 'none';
      } else {
        iosSteps.style.display = 'none';
        installBtn.style.display = 'inline-flex';
      }
    });

    // Install button
    document.getElementById('pwaInstallBtn').addEventListener('click', async () => {
      if (!deferredPrompt) return; // Android/Chromium only
      try {
        deferredPrompt.prompt();
        const choice = await deferredPrompt.userChoice;
        deferredPrompt = null;
        if (choice && choice.outcome === 'accepted') {
          document.getElementById('pwa-install-prompt').style.display = 'none';
          document.getElementById('openPwaInstall').style.display = 'none';
        }
      } catch (e) {
        console.warn('Install flow failed', e);
      }
    });

    // Close / Later
    document.getElementById('pwaDismissBtn').addEventListener('click', () => {
      document.getElementById('pwa-install-prompt').style.display = 'none';
    });
    document.getElementById('pwaLaterBtn').addEventListener('click', () => {
      document.getElementById('pwa-install-prompt').style.display = 'none';
    });

    // App installed
    window.addEventListener('appinstalled', () => {
      const overlay = document.getElementById('pwa-install-prompt');
      const btn = document.getElementById('openPwaInstall');
      if (overlay) overlay.style.display = 'none';
      if (btn) btn.style.display = 'none';
    });
  </script>
</body>
</html>
