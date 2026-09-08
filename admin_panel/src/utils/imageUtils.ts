/**
 * Resolves avatar and image URLs cleanly for Admin Panel.
 * Handles relative paths, full CDN paths, base64 data URIs, and fallbacks.
 */
export const getFullImageUrl = (path?: string | null): string => {
  if (!path || typeof path !== 'string') return '';
  const trimmed = path.trim();
  if (!trimmed) return '';

  // Data URIs or absolute URLs
  if (
    trimmed.startsWith('data:') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('blob:')
  ) {
    return trimmed;
  }

  // Clean leading slash
  const cleanPath = trimmed.replace(/^\/+/, '');

  if (cleanPath.startsWith('flutter/')) {
    return `https://app.vvc.asia/${cleanPath}`;
  }

  // Default path for uploads on the server is under flutter/ directory
  return `https://app.vvc.asia/flutter/${cleanPath}`;
};

export const getUserInitials = (name?: string | null): string => {
  if (!name || typeof name !== 'string') return 'U';
  const trimmed = name.trim();
  if (!trimmed) return 'U';

  const parts = trimmed.split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0].slice(0, 1) + parts[1].slice(0, 1)).toUpperCase();
  }
  return trimmed.slice(0, 2).toUpperCase();
};
