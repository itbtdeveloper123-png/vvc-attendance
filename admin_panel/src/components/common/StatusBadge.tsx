import React from 'react';
import { CheckCircle2, Clock, XCircle, AlertCircle, Shield } from 'lucide-react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const norm = status?.toLowerCase() || '';

  if (norm === 'good' || norm === 'approved' || norm === 'success' || norm === 'active') {
    return (
      <span className="badge badge-good" style={{ fontSize: size === 'sm' ? '11px' : '12px' }}>
        <CheckCircle2 size={size === 'sm' ? 12 : 14} />
        <span>{status === 'Good' ? '✅ Good' : status === 'Approved' ? 'យល់ព្រម (Approved)' : status}</span>
      </span>
    );
  }

  if (norm === 'late' || norm === 'pending' || norm === 'warning') {
    return (
      <span className="badge badge-late" style={{ fontSize: size === 'sm' ? '11px' : '12px' }}>
        <Clock size={size === 'sm' ? 12 : 14} />
        <span>{status === 'Late' ? '⚠️ មកយឺត (Late)' : status === 'Pending' ? 'រង់ចាំ (Pending)' : status}</span>
      </span>
    );
  }

  if (norm === 'absent' || norm === 'rejected' || norm === 'danger' || norm === 'inactive') {
    return (
      <span className="badge badge-absent" style={{ fontSize: size === 'sm' ? '11px' : '12px' }}>
        <XCircle size={size === 'sm' ? 12 : 14} />
        <span>{status === 'Absent' ? '❌ អវត្តមាន (Absent)' : status === 'Rejected' ? 'បដិសេធ (Rejected)' : status}</span>
      </span>
    );
  }

  return (
    <span className="badge badge-primary" style={{ fontSize: size === 'sm' ? '11px' : '12px' }}>
      <Shield size={size === 'sm' ? 12 : 14} />
      <span>{status}</span>
    </span>
  );
};
