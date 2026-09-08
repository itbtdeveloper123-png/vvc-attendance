import React, { useState, useEffect, useMemo } from 'react';
import { getFullImageUrl, getUserInitials } from '../utils/imageUtils';

interface UserAvatarProps {
  avatar?: string | null;
  name?: string | null;
  size?: number | string;
  borderRadius?: string;
  fontSize?: string;
  style?: React.CSSProperties;
  className?: string;
}

export const UserAvatar: React.FC<UserAvatarProps> = ({
  avatar,
  name = '',
  size = 46,
  borderRadius = '12px',
  fontSize = '14px',
  style,
  className,
}) => {
  const [hasError, setHasError] = useState(false);
  const [triedFallback, setTriedFallback] = useState(false);

  const initialUrl = useMemo(() => getFullImageUrl(avatar), [avatar]);
  const [currentSrc, setCurrentSrc] = useState(initialUrl);

  useEffect(() => {
    setCurrentSrc(getFullImageUrl(avatar));
    setHasError(false);
    setTriedFallback(false);
  }, [avatar]);

  const initials = useMemo(() => getUserInitials(name), [name]);

  const handleImgError = () => {
    // If the image was requested from /flutter/uploads/..., try fallback to /uploads/...
    if (!triedFallback && currentSrc.includes('/flutter/uploads/')) {
      setTriedFallback(true);
      setCurrentSrc(currentSrc.replace('/flutter/uploads/', '/uploads/'));
    } else {
      setHasError(true);
    }
  };

  const showImage = Boolean(currentSrc) && !hasError;
  const dimension = typeof size === 'number' ? `${size}px` : size;

  return (
    <div
      className={className}
      style={{
        width: dimension,
        height: dimension,
        borderRadius,
        background: showImage ? 'transparent' : 'rgba(99, 102, 241, 0.12)',
        color: 'var(--primary, #6366f1)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontWeight: 800,
        fontSize,
        overflow: 'hidden',
        flexShrink: 0,
        border: '1px solid var(--border, rgba(255,255,255,0.1))',
        boxShadow: '0 2px 5px rgba(0,0,0,0.04)',
        position: 'relative',
        ...style,
      }}
    >
      {showImage ? (
        <img
          src={currentSrc}
          alt=""
          onError={handleImgError}
          loading="lazy"
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            display: 'block',
          }}
        />
      ) : (
        <span>{initials}</span>
      )}
    </div>
  );
};
