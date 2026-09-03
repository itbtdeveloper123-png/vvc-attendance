import { useEffect, useRef, useCallback, useState } from 'react';

export interface RealtimeSyncOptions {
  intervalMs?: number;
  channelName?: string;
  onSync: (isSilent?: boolean) => void | Promise<void>;
  enabled?: boolean;
}

export function useRealtimeSync({
  intervalMs = 6000,
  channelName = 'vvc_admin_realtime',
  onSync,
  enabled = true,
}: RealtimeSyncOptions) {
  const syncRef = useRef(onSync);
  syncRef.current = onSync;

  const [lastSyncTime, setLastSyncTime] = useState<string>('ទើបតែធ្វើបច្ចុប្បន្នភាព');
  const [isSyncing, setIsSyncing] = useState<boolean>(false);

  const triggerSync = useCallback(
    async (isSilent = true) => {
      if (!enabled) return;
      if (document.visibilityState !== 'visible' && isSilent) return;

      try {
        setIsSyncing(true);
        await Promise.resolve(syncRef.current(isSilent));
        const now = new Date();
        const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
        setLastSyncTime(timeStr);
      } catch (err) {
        console.warn('[RealtimeSync] sync error:', err);
      } finally {
        setIsSyncing(false);
      }
    },
    [enabled]
  );

  useEffect(() => {
    if (!enabled) return;

    // 1. Initial immediate sync on mount
    triggerSync(false);

    // 2. Heartbeat interval for real-time background sync
    const timer = setInterval(() => {
      triggerSync(true);
    }, intervalMs);

    // 3. SWR pattern: Revalidate immediately when user tabs back or focuses window
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        triggerSync(true);
      }
    };
    const handleFocus = () => {
      triggerSync(true);
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleFocus);

    // 4. Cross-Tab & Cross-Component Instant Sync via BroadcastChannel
    let bc: BroadcastChannel | null = null;
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        bc = new BroadcastChannel(channelName);
        bc.onmessage = (event) => {
          if (event.data?.type === 'DATA_UPDATED' || event.data?.type === 'SYNC') {
            triggerSync(true);
          }
        };
      }
    } catch (e) {
      // BroadcastChannel fallback
    }

    // 5. In-window custom event dispatch
    const handleCustomEvent = () => {
      triggerSync(true);
    };
    window.addEventListener('vvc_data_updated', handleCustomEvent);

    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('vvc_data_updated', handleCustomEvent);
      if (bc) {
        bc.close();
      }
    };
  }, [intervalMs, channelName, triggerSync, enabled]);

  return {
    lastSyncTime,
    isSyncing,
    refreshNow: () => triggerSync(false),
  };
}

/**
 * Global broadcast function to instantly trigger real-time revalidation
 * in all listening views, components, and open browser tabs.
 */
export function broadcastRealtimeUpdate(payload: { target?: string; action?: string; data?: any } = {}) {
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      const bc = new BroadcastChannel('vvc_admin_realtime');
      bc.postMessage({ type: 'DATA_UPDATED', ...payload });
      bc.close();
    }
  } catch (e) {}

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('vvc_data_updated', { detail: payload }));
  }
}
