/**
 * VVC Anti-Inspect & Developer Password Unlock Shield
 * When locked: Blocks Right-click, F12, and DevTools shortcuts.
 * When attempting to Inspect: Prompts for Developer Password.
 * Auto-Lock Triggers:
 *  1. Tab switch / Minimized window (visibilitychange: hidden)
 *  2. Window blur (switching application)
 *  3. Page unload / Refresh / Exit (beforeunload, pagehide)
 *  4. Inactivity timeout (3 minutes idle)
 *  5. DevTools closed detection
 */

const STORAGE_KEY = 'vvc_devtools_unlocked';
const DEFAULT_PASSWORDS = ['vvc@dev2026', 'adminpass', 'vvc2026', 'admin'];
const IDLE_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes

let idleTimer: any = null;
let devToolsOpenPreviously = false;

export const isDevToolsUnlocked = (): boolean => {
  try {
    return sessionStorage.getItem(STORAGE_KEY) === 'true';
  } catch (_) {
    return false;
  }
};

export const setDevToolsUnlocked = (unlocked: boolean, notify = false): void => {
  try {
    if (unlocked) {
      sessionStorage.setItem(STORAGE_KEY, 'true');
      resetIdleTimer();
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
      if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
      }
      try {
        console.clear();
      } catch (_) {}
      if (notify) {
        showToastNotification('🔒 Developer Mode & Inspect ត្រូវបាន Lock ដោយស្វ័យប្រវត្តិ!', 'warning');
      }
    }
  } catch (_) {}
};

const resetIdleTimer = () => {
  if (idleTimer) {
    clearTimeout(idleTimer);
  }
  if (isDevToolsUnlocked()) {
    idleTimer = setTimeout(() => {
      if (isDevToolsUnlocked()) {
        setDevToolsUnlocked(false, true);
      }
    }, IDLE_TIMEOUT_MS);
  }
};

/**
 * Show modern, sleek Developer Password Prompt Modal
 */
export const promptDeveloperUnlock = (): void => {
  if (isDevToolsUnlocked()) {
    showToastNotification('🔓 Developer Mode បានដោះសោររួចរាល់ហើយ! លោកអ្នកអាច Inspect បានធម្មតា។', 'success');
    return;
  }

  // Remove existing modal if any
  const existing = document.getElementById('vvc-dev-unlock-modal');
  if (existing) {
    existing.remove();
  }

  const modal = document.createElement('div');
  modal.id = 'vvc-dev-unlock-modal';
  modal.style.position = 'fixed';
  modal.style.inset = '0';
  modal.style.zIndex = '99999999';
  modal.style.display = 'flex';
  modal.style.alignItems = 'center';
  modal.style.justifyContent = 'center';
  modal.style.backgroundColor = 'rgba(2, 6, 23, 0.85)';
  modal.style.backdropFilter = 'blur(8px)';
  modal.style.fontFamily = "'Battambang', 'Outfit', sans-serif";
  modal.style.animation = 'fadeIn 0.2s ease-out';

  modal.innerHTML = `
    <div style="
      background: #0f172a;
      border: 1px solid rgba(59, 130, 246, 0.3);
      border-radius: 16px;
      padding: 28px;
      width: 90%;
      max-width: 440px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 20px rgba(59, 130, 246, 0.2);
      color: #f8fafc;
      text-align: center;
    ">
      <div style="
        width: 56px;
        height: 56px;
        border-radius: 50%;
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(37, 99, 235, 0.4));
        border: 2px solid #3b82f6;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 16px auto;
        font-size: 26px;
      ">
        🔐
      </div>
      
      <h3 style="margin: 0 0 8px 0; font-size: 18px; font-weight: 700; color: #ffffff;">
        ផ្ទៀងផ្ទាត់លេខសម្ងាត់ Developer
      </h3>
      <p style="margin: 0 0 20px 0; font-size: 13px; color: #94a3b8; line-height: 1.5;">
        ទំព័រនេះត្រូវបានការពារដោយប្រព័ន្ធសុវត្ថិភាព។ សូមបញ្ចូលលេខសម្ងាត់ Developer ដើម្បីបើកសិទ្ធិ <strong>Inspect & DevTools</strong> (ប្រព័ន្ធនឹង Lock វិញស្វ័យប្រវត្តិនៅពេលលោកអ្នកចាកចេញ)។
      </p>

      <form id="vvc-dev-form" style="margin-bottom: 0;">
        <div style="position: relative; margin-bottom: 16px; text-align: left;">
          <label style="display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px;">
            លេខសម្ងាត់ (Developer Password)
          </label>
          <input 
            type="password" 
            id="vvc-dev-input" 
            placeholder="បញ្ចូលលេខសម្ងាត់..." 
            autocomplete="off"
            style="
              width: 100%;
              padding: 10px 14px;
              background: #1e293b;
              border: 1px solid #334155;
              border-radius: 8px;
              color: #ffffff;
              font-size: 14px;
              outline: none;
              box-sizing: border-box;
              transition: border-color 0.2s;
            "
          />
          <div id="vvc-dev-error" style="display: none; color: #ef4444; font-size: 12px; margin-top: 6px; font-weight: 500;">
            ❌ លេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!
          </div>
        </div>

        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button 
            type="button" 
            id="vvc-dev-cancel"
            style="
              padding: 9px 18px;
              background: #334155;
              border: none;
              border-radius: 8px;
              color: #cbd5e1;
              font-size: 13px;
              font-weight: 600;
              cursor: pointer;
            "
          >
            បោះបង់
          </button>
          <button 
            type="submit" 
            id="vvc-dev-submit"
            style="
              padding: 9px 20px;
              background: linear-gradient(135deg, #2563eb, #1d4ed8);
              border: none;
              border-radius: 8px;
              color: #ffffff;
              font-size: 13px;
              font-weight: 600;
              cursor: pointer;
              box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
            "
          >
            ដោះសោរ 🔓
          </button>
        </div>
      </form>
    </div>
  `;

  document.body.appendChild(modal);

  const inputEl = document.getElementById('vvc-dev-input') as HTMLInputElement;
  const formEl = document.getElementById('vvc-dev-form') as HTMLFormElement;
  const cancelBtn = document.getElementById('vvc-dev-cancel') as HTMLButtonElement;
  const errorEl = document.getElementById('vvc-dev-error') as HTMLDivElement;

  if (inputEl) {
    inputEl.focus();
  }

  cancelBtn.onclick = () => {
    modal.remove();
  };

  formEl.onsubmit = (e) => {
    e.preventDefault();
    const entered = (inputEl?.value || '').trim();

    // Check custom configured password or default list
    const customPassword = localStorage.getItem('vvc_developer_pwd');
    const allowed = customPassword ? [customPassword, ...DEFAULT_PASSWORDS] : DEFAULT_PASSWORDS;

    if (allowed.includes(entered)) {
      setDevToolsUnlocked(true);
      modal.remove();
      showToastNotification('✅ Developer Mode ត្រូវបានដោះសោរជោគជ័យ! លោកអ្នកអាច Inspect បានហើយ។', 'success');
    } else {
      if (errorEl) {
        errorEl.style.display = 'block';
      }
      if (inputEl) {
        inputEl.style.borderColor = '#ef4444';
        inputEl.value = '';
        inputEl.focus();
      }
    }
  };
};

const showToastNotification = (msg: string, type: 'success' | 'warning' = 'success') => {
  const toast = document.createElement('div');
  toast.style.position = 'fixed';
  toast.style.bottom = '24px';
  toast.style.right = '24px';
  toast.style.zIndex = '999999999';
  toast.style.padding = '12px 20px';
  toast.style.background = type === 'success' ? '#065f46' : '#991b1b';
  toast.style.border = type === 'success' ? '1px solid #10b981' : '1px solid #ef4444';
  toast.style.borderRadius = '10px';
  toast.style.color = '#ffffff';
  toast.style.fontSize = '13px';
  toast.style.fontWeight = '600';
  toast.style.boxShadow = '0 10px 25px rgba(0,0,0,0.5)';
  toast.style.fontFamily = "'Battambang', 'Outfit', sans-serif";
  toast.innerText = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
};

export const initAntiInspect = (): void => {
  // Expose global unlock/lock helper functions for developers
  (window as any).unlockDevTools = promptDeveloperUnlock;
  (window as any).lockDevTools = () => {
    setDevToolsUnlocked(false, true);
  };

  // 1. User activity listener to reset idle auto-lock timer
  const onActivity = () => {
    if (isDevToolsUnlocked()) {
      resetIdleTimer();
    }
  };
  window.addEventListener('mousemove', onActivity, { passive: true });
  window.addEventListener('keydown', onActivity, { passive: true });
  window.addEventListener('click', onActivity, { passive: true });
  window.addEventListener('scroll', onActivity, { passive: true });

  // 2. Auto-Lock on Tab Switch or Window Minimize
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && isDevToolsUnlocked()) {
      setDevToolsUnlocked(false, false);
    }
  });

  // 3. Auto-Lock on Window Blur / App Switch
  window.addEventListener('blur', () => {
    if (isDevToolsUnlocked()) {
      // Delay slightly in case blur was from DevTools itself
      setTimeout(() => {
        if (document.hidden) {
          setDevToolsUnlocked(false, false);
        }
      }, 500);
    }
  });

  // 4. Auto-Lock on Page Unload / Navigation / Exit
  window.addEventListener('beforeunload', () => {
    setDevToolsUnlocked(false, false);
  });
  window.addEventListener('pagehide', () => {
    setDevToolsUnlocked(false, false);
  });

  // 5. DevTools Closed Detection via Window Dimensions Check
  setInterval(() => {
    const threshold = 160;
    const isDevToolsOpen = (window.outerWidth - window.innerWidth > threshold) || (window.outerHeight - window.innerHeight > threshold);

    if (devToolsOpenPreviously && !isDevToolsOpen) {
      // User just closed DevTools -> Auto-Lock immediately!
      if (isDevToolsUnlocked()) {
        setDevToolsUnlocked(false, true);
      }
    }
    devToolsOpenPreviously = isDevToolsOpen;
  }, 1000);

  // 6. Right-Click Interceptor
  document.addEventListener('contextmenu', (e: MouseEvent) => {
    if (!isDevToolsUnlocked()) {
      e.preventDefault();
      promptDeveloperUnlock();
      return false;
    }
  });

  // 7. DevTools Shortcut Keys Interceptor
  document.addEventListener('keydown', (e: KeyboardEvent) => {
    if (isDevToolsUnlocked()) {
      return; // Allowed when unlocked
    }

    // F12 key
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      promptDeveloperUnlock();
      return false;
    }

    // Ctrl + Shift + I (Inspect)
    // Ctrl + Shift + J (Console)
    // Ctrl + Shift + C (Element Selector)
    if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c' || e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
      e.preventDefault();
      e.stopPropagation();
      promptDeveloperUnlock();
      return false;
    }

    // Ctrl + U (View Page Source)
    if (e.ctrlKey && (e.key === 'U' || e.key === 'u' || e.keyCode === 85)) {
      e.preventDefault();
      e.stopPropagation();
      promptDeveloperUnlock();
      return false;
    }

    // Ctrl + Alt + D (Secret Developer Unlock Shortcut)
    if (e.ctrlKey && e.altKey && (e.key === 'D' || e.key === 'd')) {
      e.preventDefault();
      e.stopPropagation();
      promptDeveloperUnlock();
      return false;
    }
  });

  // 8. Security Banner
  if (!isDevToolsUnlocked()) {
    try {
      console.log(
        '%c🔒 VVC SECURITY SHIELD 🔒',
        'color: #3b82f6; font-size: 20px; font-weight: 800; background: #0f172a; padding: 4px 8px; border-radius: 4px;'
      );
      console.log(
        '%cដើម្បី Inspect សូមប្រើ Shortcut Ctrl + Alt + D ឬចុចស្តាំដើម្បីបញ្ចូល Password។ (ប្រព័ន្ធនឹង Lock វិញស្វ័យប្រវត្តិនៅពេលចាកចេញ)',
        'color: #94a3b8; font-size: 13px;'
      );
    } catch (_) {}
  }
};
