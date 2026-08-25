import React, { useState, useEffect, useRef } from 'react';
import {
  Video,
  Play,
  Pause,
  FileText,
  Calendar,
  Plus,
  Sparkles,
  Trash2,
  Check,
  RotateCw,
  Search,
  Filter,
  ExternalLink,
  Volume2,
  Image as ImageIcon,
  Table as TableIcon,
  Layers,
  LayoutGrid,
  X,
  Upload,
  Clock,
  Building2,
  ChevronRight,
  Eye,
  Edit3,
  Copy,
  RefreshCw,
  Bot
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { adminApi, MeetingItem } from '../api/adminApi';

const DEFAULT_DEPARTMENTS = [
  'Store 318 & SKKS2',
  'Store 318',
  'Store SKKS2',
  'Warehouse PSP',
  'IT & HRM',
  'រដ្ឋបាល (Admin)',
  'គណនេយ្យ (Accounting)',
  'ផ្នែកលក់ (Sales)',
  'General'
];

const getFullMediaUrl = (url?: string | null): string => {
  if (!url) return '';
  const trimmed = url.trim();
  if (!trimmed) return '';
  if (
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('blob:') ||
    trimmed.startsWith('data:')
  ) {
    return trimmed;
  }
  return `https://app.vvc.asia/flutter/${trimmed.replace(/^\/+/, '')}`;
};

export const MeetingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'list' | 'create'>('list');
  const [meetings, setMeetings] = useState<MeetingItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [deptFilter, setDeptFilter] = useState('ALL');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');

  // Modals
  const [viewModalMeeting, setViewModalMeeting] = useState<MeetingItem | null>(null);
  const [editModalMeeting, setEditModalMeeting] = useState<MeetingItem | null>(null);
  const [lightboxImage, setLightboxImage] = useState<string | null>(null);

  // Audio Playback State in Cards
  const [currentlyPlayingAudio, setCurrentlyPlayingAudio] = useState<string | null>(null);
  const audioPlayerRef = useRef<HTMLAudioElement | null>(null);

  // AI Summary Modal State
  const [aiModalMeeting, setAiModalMeeting] = useState<MeetingItem | null>(null);
  const [aiModalSummary, setAiModalSummary] = useState<string | null>(null);
  const [aiModalTranscript, setAiModalTranscript] = useState<string | null>(null);
  const [aiModalLoading, setAiModalLoading] = useState(false);
  const [aiModalError, setAiModalError] = useState<string | null>(null);
  const [aiModalTab, setAiModalTab] = useState<'summary' | 'transcript'>('summary');
  const [copiedText, setCopiedText] = useState(false);
  const [aiProgress, setAiProgress] = useState<number>(0);
  const [aiProgressStep, setAiProgressStep] = useState<string>('');
  const [aiProgressElapsed, setAiProgressElapsed] = useState<number>(0);

  // Karaoke Audio-Transcript Sync State
  const [aiModalAudioCurrentTime, setAiModalAudioCurrentTime] = useState<number>(0);
  const [aiModalAudioDuration, setAiModalAudioDuration] = useState<number>(0);
  const [aiModalAudioPlaying, setAiModalAudioPlaying] = useState<boolean>(false);
  const [aiModalPlaybackRate, setAiModalPlaybackRate] = useState<number>(1);
  const aiModalAudioRef = useRef<HTMLAudioElement | null>(null);
  const activeTranscriptRef = useRef<HTMLDivElement | null>(null);

  // Real-time smooth timer ticker while audio is playing
  useEffect(() => {
    let timer: any = null;
    if (aiModalAudioPlaying && aiModalAudioRef.current) {
      timer = setInterval(() => {
        if (aiModalAudioRef.current) {
          const ct = aiModalAudioRef.current.currentTime || 0;
          setAiModalAudioCurrentTime(ct);
          const dur = aiModalAudioRef.current.duration || 0;
          if (dur > 0) setAiModalAudioDuration(dur);
        }
      }, 150);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [aiModalAudioPlaying]);

  // Auto-scroll active dialogue to top of viewport when playing
  useEffect(() => {
    if (aiModalAudioPlaying && activeTranscriptRef.current && aiModalTab === 'transcript') {
      activeTranscriptRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [aiModalAudioCurrentTime, aiModalAudioPlaying, aiModalTab]);

  // Create Form State
  const [createForm, setCreateForm] = useState({
    topic: '',
    department: 'Store 318 & SKKS2',
    date: new Date().toISOString().split('T')[0],
    duration: '30 នាទី',
    description: '',
    external_url: '',
    audio_url: '',
    photo_url: '',
  });
  const [coverPhotoFile, setCoverPhotoFile] = useState<File | null>(null);
  const [coverPhotoPreview, setCoverPhotoPreview] = useState<string | null>(null);
  const [relatedPhotoFiles, setRelatedPhotoFiles] = useState<File[]>([]);
  const [relatedPhotoPreviews, setRelatedPhotoPreviews] = useState<string[]>([]);
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [audioFilePreviewUrl, setAudioFilePreviewUrl] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  // Edit Form State
  const [editForm, setEditForm] = useState({
    id: 0,
    topic: '',
    department: 'Store 318 & SKKS2',
    date: new Date().toISOString().split('T')[0],
    duration: '30 នាទី',
    description: '',
    external_url: '',
    audio_url: '',
    photo_url: '',
    existing_photos: [] as string[]
  });
  const [editCoverPhotoFile, setEditCoverPhotoFile] = useState<File | null>(null);
  const [editCoverPhotoPreview, setEditCoverPhotoPreview] = useState<string | null>(null);
  const [editRelatedPhotoFiles, setEditRelatedPhotoFiles] = useState<File[]>([]);
  const [editRelatedPhotoPreviews, setEditRelatedPhotoPreviews] = useState<string[]>([]);
  const [editAudioFile, setEditAudioFile] = useState<File | null>(null);
  const [editAudioFilePreviewUrl, setEditAudioFilePreviewUrl] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  const loadMeetings = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchMeetings();
      if (res && res.success && Array.isArray(res.meetings || res.data)) {
        setMeetings(res.meetings || res.data);
      }
    } catch (err) {
      console.error('Error fetching meetings:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadMeetings();
  }, []);

  const handleOpenAiModal = async (m: MeetingItem, force = false) => {
    setAiModalMeeting(m);
    setAiModalTab('summary');
    setAiModalError(null);
    setCopiedText(false);

    const existingSummary = m.summary?.trim() || '';
    const existingTranscript = (m.transcript_text || (m as any).transcript)?.trim() || '';
    const hasAudio = !!(m.hasAudio || m.audio_url || (m as any).mp3_url || (m as any).audio_file_path || (m as any).audio_path);

    // If both summary and transcript exist (or meeting has no audio), use cache
    if (!force && existingSummary && (existingTranscript || !hasAudio)) {
      setAiModalSummary(existingSummary);
      setAiModalTranscript(existingTranscript || null);
      setAiModalLoading(false);
      return;
    }

    setAiModalSummary(existingSummary || null);
    setAiModalTranscript(existingTranscript || null);
    setAiModalLoading(true);
    setAiProgress(10);
    setAiProgressStep('📤 កំពុងរៀបចំ និងផ្ទុកទិន្នន័យសំឡេងកិច្ចប្រជុំ...');
    setAiProgressElapsed(0);

    let progressVal = 10;
    let elapsedVal = 0;
    const progressTimer = setInterval(() => {
      elapsedVal += 1;
      setAiProgressElapsed(elapsedVal);

      if (progressVal < 35) {
        progressVal += 4;
        setAiProgress(progressVal);
        setAiProgressStep('📤 កំពុងផ្ទុកទិន្នន័យសំឡេង និងបញ្ជូនទៅកាន់ AI Engine...');
      } else if (progressVal < 70) {
        progressVal += 2;
        setAiProgress(Math.floor(progressVal));
        setAiProgressStep('🎙️ AI កំពុងស្តាប់សំឡេង និងស្រង់យកពាក្យសម្តីនិយាយ (Transcribing Audio)...');
      } else if (progressVal < 90) {
        progressVal += 1;
        setAiProgress(Math.floor(progressVal));
        setAiProgressStep('🧠 AI កំពុងវិភាគ និងរៀបចំកំណត់ហេតុសង្ខេប (Summarizing Minutes)...');
      } else if (progressVal < 98) {
        progressVal += 0.4;
        setAiProgress(Math.floor(progressVal));
        setAiProgressStep('✨ កំពុងផ្គូផ្គង Karaoke Timestamps & រក្សាទុកទិន្នន័យ...');
      }
    }, 1000);

    try {
      const res = await adminApi.summarizeMeeting(m.id, force);
      if (res && (res.success || res.status === 'success')) {
        clearInterval(progressTimer);
        setAiProgress(100);
        setAiProgressStep('🚀 រួចរាល់ ១០០%!');
        await new Promise(r => setTimeout(r, 450));

        const summaryText = res.summary || '';
        const transcriptText = res.transcript || res.transcript_text || '';
        setAiModalSummary(summaryText);
        setAiModalTranscript(transcriptText);

        // Update in meetings list state
        setMeetings(prev => prev.map(item => item.id === m.id ? { ...item, summary: summaryText, transcript_text: transcriptText } : item));
      } else {
        clearInterval(progressTimer);
        setAiModalError(res?.message || 'មិនអាចទាញយកសេចក្តីសង្ខេប AI បានទេ។');
      }
    } catch (err: any) {
      clearInterval(progressTimer);
      const serverMsg = err?.response?.data?.message || err?.message || 'កំហុសក្នុងការតភ្ជាប់ AI Service';
      setAiModalError(serverMsg);
    } finally {
      clearInterval(progressTimer);
      setAiModalLoading(false);
    }
  };

  const handleCopyAiContent = () => {
    const text = aiModalTab === 'summary' ? (aiModalSummary || '') : (aiModalTranscript || '');
    if (text) {
      navigator.clipboard.writeText(text);
      setCopiedText(true);
      setTimeout(() => setCopiedText(false), 2000);
    }
  };

  const parseInlineBold = (text: string) => {
    const parts = text.split(/(\*\*.*?\*\*)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={idx} style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
            {part.slice(2, -2)}
          </strong>
        );
      }
      return part;
    });
  };

  const renderKhmerFormattedText = (rawText: string) => {
    if (!rawText) return null;

    const lines = rawText.split('\n');
    const elements: React.ReactNode[] = [];

    let currentListItems: React.ReactNode[] = [];
    let listKey = 0;

    const flushList = () => {
      if (currentListItems.length > 0) {
        elements.push(
          <div key={`list-${listKey++}`} style={{ display: 'flex', flexDirection: 'column', gap: '6px', margin: '6px 0 14px 0' }}>
            {currentListItems}
          </div>
        );
        currentListItems = [];
      }
    };

    lines.forEach((line, idx) => {
      const trimmed = line.trim();

      if (!trimmed) {
        flushList();
        return;
      }

      // Divider line
      if (trimmed === '---' || trimmed === '***' || trimmed === '___') {
        flushList();
        elements.push(
          <hr key={`hr-${idx}`} style={{ border: 'none', height: '1px', background: 'var(--border-color)', margin: '16px 0', opacity: 0.8 }} />
        );
        return;
      }

      // Main Header #
      if (trimmed.startsWith('# ') || trimmed.startsWith('## ')) {
        flushList();
        const titleText = trimmed.replace(/^#+\s*/, '');
        elements.push(
          <div
            key={`h1-${idx}`}
            style={{
              margin: '14px 0 12px 0',
              padding: '10px 16px',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(168, 85, 247, 0.08) 100%)',
              borderLeft: '4px solid var(--primary)',
              borderRadius: '8px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.03)'
            }}
          >
            <div style={{ margin: 0, fontSize: '15.5px', fontWeight: 800, color: 'var(--primary)', fontFamily: "'Kantumruy Pro', 'Inter', sans-serif" }}>
              {parseInlineBold(titleText)}
            </div>
          </div>
        );
        return;
      }

      // Section Subheaders ### 📌, 🎯, ✅, 📋, 1., 2.
      if (trimmed.startsWith('### ') || trimmed.match(/^(📌|🎯|✅|📋|📝|💡|⚠️)\s*/)) {
        flushList();
        const sectionTitle = trimmed.replace(/^###\s*/, '');
        let badgeBg = 'rgba(59, 130, 246, 0.1)';
        let badgeColor = '#2563eb';
        let borderClr = 'rgba(59, 130, 246, 0.25)';

        if (sectionTitle.includes('២.') || sectionTitle.includes('🎯') || sectionTitle.includes('ចំណុច')) {
          badgeBg = 'rgba(245, 158, 11, 0.1)';
          badgeColor = '#d97706';
          borderClr = 'rgba(245, 158, 11, 0.25)';
        } else if (sectionTitle.includes('៣.') || sectionTitle.includes('✅') || sectionTitle.includes('សម្រេច')) {
          badgeBg = 'rgba(16, 185, 129, 0.1)';
          badgeColor = '#059669';
          borderClr = 'rgba(16, 185, 129, 0.25)';
        } else if (sectionTitle.includes('៤.') || sectionTitle.includes('📋') || sectionTitle.includes('សកម្មភាព') || sectionTitle.includes('Next Steps')) {
          badgeBg = 'rgba(139, 92, 246, 0.1)';
          badgeColor = '#7c3aed';
          borderClr = 'rgba(139, 92, 246, 0.25)';
        }

        elements.push(
          <div
            key={`sec-${idx}`}
            style={{
              margin: '18px 0 10px 0',
              padding: '8px 14px',
              background: badgeBg,
              border: `1px solid ${borderClr}`,
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <div style={{ fontSize: '14.5px', fontWeight: 800, color: badgeColor, fontFamily: "'Kantumruy Pro', 'Inter', sans-serif" }}>
              {parseInlineBold(sectionTitle)}
            </div>
          </div>
        );
        return;
      }

      // Metadata bullet point (* **Key:** Value)
      const metaMatch = trimmed.match(/^[\*\-]\s+\*\*(.*?)\*\*\s*[:៖]\s*(.*)/);
      if (metaMatch) {
        const key = metaMatch[1];
        const val = metaMatch[2];
        currentListItems.push(
          <div
            key={`meta-${idx}`}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '8px',
              padding: '6px 12px',
              background: 'rgba(255, 255, 255, 0.03)',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              fontSize: '13.5px',
              lineHeight: 1.8,
              fontFamily: "'Kantumruy Pro', 'Inter', sans-serif"
            }}
          >
            <span style={{ fontWeight: 700, color: 'var(--primary)', flexShrink: 0, minWidth: '110px' }}>
              {key}:
            </span>
            <span style={{ color: 'var(--text-primary)', flex: 1 }}>
              {parseInlineBold(val)}
            </span>
          </div>
        );
        return;
      }

      // List items (* or -)
      const bulletMatch = trimmed.match(/^[\*\-]\s+(.*)/);
      if (bulletMatch) {
        const content = bulletMatch[1];
        currentListItems.push(
          <div
            key={`li-${idx}`}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '4px 0',
              lineHeight: 1.85,
              fontSize: '14px',
              color: 'var(--text-primary)',
              fontFamily: "'Kantumruy Pro', 'Inter', sans-serif"
            }}
          >
            <span style={{ color: '#f59e0b', fontSize: '16px', lineHeight: 1.4, flexShrink: 0 }}>•</span>
            <div style={{ flex: 1 }}>{parseInlineBold(content)}</div>
          </div>
        );
        return;
      }

      // Numbered items (1. 2.)
      const numMatch = trimmed.match(/^(\d+)[\.\)]\s+(.*)/);
      if (numMatch) {
        const num = numMatch[1];
        const content = numMatch[2];
        currentListItems.push(
          <div
            key={`num-${idx}`}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '6px 10px',
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: '8px',
              marginBottom: '4px',
              lineHeight: 1.85,
              fontSize: '14px',
              color: 'var(--text-primary)',
              fontFamily: "'Kantumruy Pro', 'Inter', sans-serif"
            }}
          >
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                minWidth: '22px',
                height: '22px',
                borderRadius: '6px',
                background: 'rgba(99, 102, 241, 0.15)',
                color: 'var(--primary)',
                fontSize: '12px',
                fontWeight: 700,
                flexShrink: 0,
                marginTop: '3px'
              }}
            >
              {num}
            </span>
            <div style={{ flex: 1 }}>{parseInlineBold(content)}</div>
          </div>
        );
        return;
      }

      // Speaker Dialogue formatting in Transcript (e.g. "ឈ្មោះ: ខ្លឹមសារ")
      const speakerMatch = trimmed.match(/^([\u1780-\u17FF\w\s\(\)]+)\s*[:៖]\s*(.*)/);
      if (speakerMatch && aiModalTab === 'transcript') {
        flushList();
        const speaker = speakerMatch[1];
        const dialogue = speakerMatch[2];
        elements.push(
          <div
            key={`dlg-${idx}`}
            style={{
              margin: '8px 0',
              padding: '10px 14px',
              background: 'rgba(99, 102, 241, 0.04)',
              border: '1px solid rgba(99, 102, 241, 0.12)',
              borderRadius: '10px',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
              fontFamily: "'Kantumruy Pro', 'Inter', sans-serif"
            }}
          >
            <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--primary)' }}>
              🗣️ {speaker}
            </span>
            <span style={{ fontSize: '14px', lineHeight: 1.85, color: 'var(--text-primary)' }}>
              {parseInlineBold(dialogue)}
            </span>
          </div>
        );
        return;
      }

      // Normal Paragraph
      flushList();
      elements.push(
        <p
          key={`p-${idx}`}
          style={{
            margin: '0 0 10px 0',
            lineHeight: 1.9,
            fontSize: '14px',
            color: 'var(--text-primary)',
            fontFamily: "'Kantumruy Pro', 'Inter', sans-serif"
          }}
        >
          {parseInlineBold(trimmed)}
        </p>
      );
    });

    flushList();
    return <div style={{ display: 'flex', flexDirection: 'column' }}>{elements}</div>;
  };

  const formatSecondsToTime = (totalSeconds: number) => {
    const s = Math.max(0, Math.floor(totalSeconds));
    const mins = Math.floor(s / 60);
    const secs = s % 60;
    const hours = Math.floor(mins / 60);
    if (hours > 0) {
      const remMins = mins % 60;
      return `${hours}:${remMins < 10 ? '0' : ''}${remMins}:${secs < 10 ? '0' : ''}${secs}`;
    }
    return `${mins < 10 ? '0' : ''}${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  const renderKaraokeTranscript = (rawTranscript: string) => {
    if (!rawTranscript) return null;

    // Filter out non-dialogue header lines
    const rawLines = rawTranscript
      .split('\n')
      .map(l => l.trim())
      .filter(l => {
        if (!l) return false;
        if (l === '---' || l === '***' || l === '___') return false;
        if (l.startsWith('###') || l.startsWith('#')) return false;
        if (l.startsWith('===') && l.endsWith('===')) return false;
        if (l.includes('នេះជាអត្ថបទសន្ទនា') || l.includes('Full Transcript') || l.includes('Full Meeting Transcript')) return false;
        return true;
      });

    if (rawLines.length === 0) return null;

    interface TranscriptBlock {
      id: number;
      startTime: number;
      endTime: number;
      speaker: string;
      text: string;
      raw: string;
    }

    const blocks: TranscriptBlock[] = [];

    rawLines.forEach((line, idx) => {
      let startTime = -1;
      let lineBody = line;

      // Flexible timestamp match: [00:15], (00:15), [00:15:30], **[00:15]**, 00:15
      const timeMatch = lineBody.match(/(?:^|\[|\(|\*\*|\s)(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\]|\)|\*\*|\s)?\s*(.*)/);
      if (timeMatch && !timeMatch[4]?.startsWith(':') && !timeMatch[4]?.startsWith('៖')) {
        if (timeMatch[3] !== undefined) {
          startTime = parseInt(timeMatch[1], 10) * 3600 + parseInt(timeMatch[2], 10) * 60 + parseInt(timeMatch[3], 10);
        } else {
          startTime = parseInt(timeMatch[1], 10) * 60 + parseInt(timeMatch[2], 10);
        }
        lineBody = timeMatch[4] || lineBody;
      }

      const speakerMatch = lineBody.match(/^(\*\*.*?\*\*|[\u1780-\u17FF\w\s\(\)]+)\s*[:៖]\s*(.*)/);
      let speaker = '';
      let dialogue = lineBody;

      if (speakerMatch) {
        speaker = speakerMatch[1].replace(/\*\*/g, '').trim();
        dialogue = speakerMatch[2].trim();
      }

      blocks.push({
        id: idx,
        startTime: startTime,
        endTime: -1,
        speaker: speaker,
        text: dialogue,
        raw: line
      });
    });

    const hasAnyRealTimestamps = blocks.some(b => b.startTime >= 0);

    if (!hasAnyRealTimestamps) {
      // Precise Khmer meeting speech pacing: 17.9 characters per second (Point 1 starts at 00:12)
      let runningTime = 0;
      blocks.forEach((b) => {
        const charLen = Math.max(8, (b.text || b.raw).length);
        const speechDuration = Math.max(1.0, Math.min(35, charLen / 17.9));
        b.startTime = runningTime;
        b.endTime = runningTime + speechDuration;
        runningTime += speechDuration;
      });
    } else {
      for (let i = 0; i < blocks.length; i++) {
        if (blocks[i].startTime < 0) {
          blocks[i].startTime = i > 0 ? blocks[i - 1].endTime : 0;
        }
        if (i < blocks.length - 1 && blocks[i + 1].startTime >= 0) {
          blocks[i].endTime = blocks[i + 1].startTime;
        } else {
          const charLen = Math.max(8, (blocks[i].text || blocks[i].raw).length);
          blocks[i].endTime = blocks[i].startTime + Math.max(1.0, charLen / 17.9);
        }
      }
    }

    let activeIdx = -1;
    for (let i = 0; i < blocks.length; i++) {
      if (aiModalAudioCurrentTime >= blocks[i].startTime && (i === blocks.length - 1 || aiModalAudioCurrentTime < blocks[i + 1].startTime)) {
        activeIdx = i;
        break;
      }
    }

    const handleSeekTo = (timeSecs: number) => {
      if (aiModalAudioRef.current) {
        aiModalAudioRef.current.currentTime = timeSecs;
        aiModalAudioRef.current.play();
        setAiModalAudioPlaying(true);
      }
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {/* Karaoke Interactive Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 14px', background: 'rgba(99, 102, 241, 0.08)', borderRadius: '10px', border: '1px solid rgba(99, 102, 241, 0.2)', fontSize: '12.5px', flexWrap: 'wrap', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--primary)', fontWeight: 700 }}>
            <Sparkles size={15} />
            <span>Karaoke Audio-Transcript Sync</span>
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
            💡 ចុចលើអត្ថបទសន្ទនាណាមួយ ដើម្បីចាក់សំឡេងត្រង់ចំណុចនោះភ្លាមៗ
          </div>
        </div>

        {blocks.map((block, idx) => {
          const isActive = idx === activeIdx;

          return (
            <div
              key={block.id}
              ref={isActive ? activeTranscriptRef : undefined}
              onClick={() => handleSeekTo(block.startTime)}
              title="ចុចដើម្បីស្តាប់ត្រង់ចំណុចនេះ"
              style={{
                scrollMarginTop: '14px',
                padding: '14px 18px',
                borderRadius: '12px',
                cursor: 'pointer',
                transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
                background: isActive
                  ? 'linear-gradient(135deg, rgba(99, 102, 241, 0.18) 0%, rgba(168, 85, 247, 0.14) 100%)'
                  : 'rgba(255, 255, 255, 0.02)',
                border: isActive ? '1px solid rgba(99, 102, 241, 0.45)' : '1px solid rgba(255, 255, 255, 0.05)',
                borderLeft: isActive ? '5px solid #6366f1' : '5px solid transparent',
                boxShadow: isActive ? '0 6px 20px rgba(99, 102, 241, 0.22)' : 'none',
                transform: isActive ? 'scale(1.01)' : 'scale(1)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}
            >
              {/* Top metadata line: Speaker + Timestamp badge */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {block.speaker ? (
                    <span
                      style={{
                        fontSize: '13.5px',
                        fontWeight: 800,
                        color: isActive ? '#4f46e5' : 'var(--text-primary)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}
                    >
                      <span>🗣️</span>
                      <span>{block.speaker}</span>
                    </span>
                  ) : (
                    <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>ចំណុចពិភាក្សា</span>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {isActive && (
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '3px 10px',
                        borderRadius: '12px',
                        background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
                        color: '#fff',
                        fontSize: '11px',
                        fontWeight: 700,
                        boxShadow: '0 2px 8px rgba(99, 102, 241, 0.35)'
                      }}
                    >
                      <Volume2 size={12} className="fa-spin" />
                      <span>កំពុងនិយាយ</span>
                    </span>
                  )}
                  <span
                    style={{
                      fontSize: '11.5px',
                      color: isActive ? 'var(--primary)' : 'var(--text-muted)',
                      fontWeight: isActive ? 700 : 500,
                      background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'rgba(0, 0, 0, 0.05)',
                      padding: '3px 8px',
                      borderRadius: '6px'
                    }}
                  >
                    ⏱️ {formatSecondsToTime(block.startTime)}
                  </span>
                </div>
              </div>

              {/* Dialogue Text with bold parsing */}
              <div
                style={{
                  fontSize: '14.5px',
                  lineHeight: 1.95,
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontWeight: isActive ? 600 : 400,
                  fontFamily: "'Kantumruy Pro', 'Inter', system-ui, sans-serif"
                }}
              >
                {parseInlineBold(block.text || block.raw)}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  const handleToggleAudio = (rawAudioUrl: string) => {
    const audioUrl = getFullMediaUrl(rawAudioUrl);
    if (!audioUrl) return;
    if (currentlyPlayingAudio === audioUrl) {
      if (audioPlayerRef.current) {
        audioPlayerRef.current.pause();
      }
      setCurrentlyPlayingAudio(null);
    } else {
      setCurrentlyPlayingAudio(audioUrl);
      if (audioPlayerRef.current) {
        audioPlayerRef.current.src = audioUrl;
        audioPlayerRef.current.load();
        const playPromise = audioPlayerRef.current.play();
        if (playPromise !== undefined) {
          playPromise.catch(e => console.log('Audio autoplay prevented or source not reachable', e));
        }
      }
    }
  };

  // Handle Cover Photo Selection
  const handleCoverPhotoChange = (file: File | null, isEdit = false) => {
    if (isEdit) {
      setEditCoverPhotoFile(file);
      if (file) {
        const url = URL.createObjectURL(file);
        setEditCoverPhotoPreview(url);
      } else {
        setEditCoverPhotoPreview(null);
      }
    } else {
      setCoverPhotoFile(file);
      if (file) {
        const url = URL.createObjectURL(file);
        setCoverPhotoPreview(url);
      } else {
        setCoverPhotoPreview(null);
      }
    }
  };

  // Handle Multiple Related Photos Selection
  const handleRelatedPhotosChange = (files: FileList | null, isEdit = false) => {
    if (!files) return;
    const newFiles = Array.from(files);
    const newUrls = newFiles.map(f => URL.createObjectURL(f));

    if (isEdit) {
      setEditRelatedPhotoFiles(prev => [...prev, ...newFiles]);
      setEditRelatedPhotoPreviews(prev => [...prev, ...newUrls]);
    } else {
      setRelatedPhotoFiles(prev => [...prev, ...newFiles]);
      setRelatedPhotoPreviews(prev => [...prev, ...newUrls]);
    }
  };

  const removeRelatedPhoto = (index: number, isEdit = false) => {
    if (isEdit) {
      setEditRelatedPhotoFiles(prev => prev.filter((_, i) => i !== index));
      setEditRelatedPhotoPreviews(prev => prev.filter((_, i) => i !== index));
    } else {
      setRelatedPhotoFiles(prev => prev.filter((_, i) => i !== index));
      setRelatedPhotoPreviews(prev => prev.filter((_, i) => i !== index));
    }
  };

  const removeExistingPhotoInEdit = (photoUrl: string) => {
    setEditForm(prev => ({
      ...prev,
      existing_photos: prev.existing_photos.filter(p => p !== photoUrl)
    }));
  };

  // Handle Audio File Selection
  const handleAudioFileChange = (file: File | null, isEdit = false) => {
    if (isEdit) {
      setEditAudioFile(file);
      if (file) {
        const url = URL.createObjectURL(file);
        setEditAudioFilePreviewUrl(url);
      } else {
        setEditAudioFilePreviewUrl(null);
      }
    } else {
      setAudioFile(file);
      if (file) {
        const url = URL.createObjectURL(file);
        setAudioFilePreviewUrl(url);
      } else {
        setAudioFilePreviewUrl(null);
      }
    }
  };

  // Submit Post Meeting
  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createForm.topic.trim()) {
      alert('សូមបញ្ចូលប្រធានបទកិច្ចប្រជុំ!');
      return;
    }

    setSubmitting(true);
    setSubmitSuccess(false);

    try {
      const formData = new FormData();
      formData.append('topic', createForm.topic);
      formData.append('title', createForm.topic);
      formData.append('department', createForm.department);
      formData.append('category', createForm.department);
      formData.append('date', createForm.date);
      formData.append('meeting_date', createForm.date);
      formData.append('duration', createForm.duration);
      formData.append('description', createForm.description);
      formData.append('summary', createForm.description);
      formData.append('external_url', createForm.external_url);
      formData.append('audio_url', createForm.audio_url);
      formData.append('photo_url', createForm.photo_url);

      if (coverPhotoFile) {
        formData.append('photo', coverPhotoFile);
      }
      if (audioFile) {
        formData.append('audio', audioFile);
      }
      relatedPhotoFiles.forEach(file => {
        formData.append('related_photos[]', file);
      });

      const res = await adminApi.saveMeeting(formData);
      if (res && (res.success || res.status === 'success')) {
        setSubmitSuccess(true);
        // Reset form
        setCreateForm({
          topic: '',
          department: 'Store 318 & SKKS2',
          date: new Date().toISOString().split('T')[0],
          duration: '30 នាទី',
          description: '',
          external_url: '',
          audio_url: '',
          photo_url: '',
        });
        setCoverPhotoFile(null);
        setCoverPhotoPreview(null);
        setRelatedPhotoFiles([]);
        setRelatedPhotoPreviews([]);
        setAudioFile(null);
        setAudioFilePreviewUrl(null);
        loadMeetings();

        setTimeout(() => {
          setSubmitSuccess(false);
          setActiveTab('list');
        }, 1500);
      } else {
        alert(res.message || 'កំហុសក្នុងការរក្សាទុកកិច្ចប្រជុំ');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSubmitting(false);
  };

  // Open Edit Modal
  const handleOpenEdit = (m: MeetingItem) => {
    const photos = Array.isArray(m.photos || m.related_photos) ? (m.photos || m.related_photos || []) : [];
    setEditForm({
      id: m.id,
      topic: m.topic || m.title || '',
      department: m.department || m.category || 'General',
      date: m.meeting_date || m.date || new Date().toISOString().split('T')[0],
      duration: m.duration || '30 នាទី',
      description: m.description || m.summary || '',
      external_url: m.external_url || '',
      audio_url: m.audio_url || m.mp3_url || m.audio_file_path || '',
      photo_url: m.photo_url || '',
      existing_photos: photos
    });
    setEditCoverPhotoFile(null);
    setEditCoverPhotoPreview(m.photo_url || null);
    setEditRelatedPhotoFiles([]);
    setEditRelatedPhotoPreviews([]);
    setEditAudioFile(null);
    setEditAudioFilePreviewUrl(m.audio_url || m.mp3_url || null);
    setEditModalMeeting(m);
  };

  // Submit Edit Meeting
  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editForm.topic.trim()) {
      alert('សូមបញ្ចូលប្រធានបទកិច្ចប្រជុំ!');
      return;
    }

    setEditSubmitting(true);
    try {
      const formData = new FormData();
      formData.append('id', String(editForm.id));
      formData.append('topic', editForm.topic);
      formData.append('title', editForm.topic);
      formData.append('department', editForm.department);
      formData.append('category', editForm.department);
      formData.append('date', editForm.date);
      formData.append('meeting_date', editForm.date);
      formData.append('duration', editForm.duration);
      formData.append('description', editForm.description);
      formData.append('summary', editForm.description);
      formData.append('external_url', editForm.external_url);
      formData.append('audio_url', editForm.audio_url);
      formData.append('photo_url', editForm.photo_url);
      formData.append('existing_photos', JSON.stringify(editForm.existing_photos));

      if (editCoverPhotoFile) {
        formData.append('photo', editCoverPhotoFile);
      }
      if (editAudioFile) {
        formData.append('audio', editAudioFile);
      }
      editRelatedPhotoFiles.forEach(file => {
        formData.append('related_photos[]', file);
      });

      const res = await adminApi.saveMeeting(formData);
      if (res && (res.success || res.status === 'success')) {
        setEditModalMeeting(null);
        loadMeetings();
      } else {
        alert(res.message || 'កំហុសក្នុងការកែប្រែកិច្ចប្រជុំ');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setEditSubmitting(false);
  };

  // Delete Meeting
  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបកិច្ចប្រជុំនេះមែនទេ? សកម្មភាពនេះមិនអាចត្រឡប់វិញបានឡើយ។')) {
      try {
        await adminApi.deleteMeeting(id);
        loadMeetings();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

  // Filter meetings
  const filteredMeetings = meetings.filter(m => {
    const topic = (m.topic || m.title || '').toLowerCase();
    const desc = (m.description || m.summary || '').toLowerCase();
    const dept = (m.department || m.category || '').toLowerCase();
    const s = searchTerm.toLowerCase();

    const matchesSearch = !searchTerm || topic.includes(s) || desc.includes(s) || dept.includes(s);
    const matchesDept = deptFilter === 'ALL' || (m.department || m.category) === deptFilter;

    return matchesSearch && matchesDept;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Hidden Audio Player instance */}
      <audio
        ref={audioPlayerRef}
        onEnded={() => setCurrentlyPlayingAudio(null)}
        style={{ display: 'none' }}
      />

      {/* Page Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(79, 70, 229, 0.03))',
          padding: '24px',
          borderRadius: '18px',
          border: '1px solid rgba(99, 102, 241, 0.15)'
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span
              style={{
                background: 'var(--primary)',
                color: '#fff',
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 4px 10px rgba(99, 102, 241, 0.3)'
              }}
            >
              <Video size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              គ្រប់គ្រងកិច្ចប្រជុំ (Meetings Management)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            បង្ហោះកិច្ចប្រជុំ ស្តាប់សំឡេង មើលរូបភាពពាក់ព័ន្ធ និងកត់ត្រាកំណត់ហេតុប្រជុំ
          </p>
        </div>

        {/* Header Action Button */}
        <div>
          {activeTab === 'list' ? (
            <button
              onClick={() => setActiveTab('create')}
              className="btn btn-primary"
              style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
            >
              <Plus size={16} />
              <span>+ បង្ហោះកិច្ចប្រជុំថ្មី</span>
            </button>
          ) : (
            <button
              onClick={() => setActiveTab('list')}
              className="btn btn-secondary"
              style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
            >
              <Layers size={16} />
              <span>← ត្រឡប់ទៅបញ្ជីកិច្ចប្រជុំ</span>
            </button>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: LIST MEETINGS                                                      */}
      {/* ========================================================================= */}
      {activeTab === 'list' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Toolbar: Search, Dept Filter, View Mode, Refresh */}
          <div
            className="hrm-card"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px', flexWrap: 'wrap' }}>
              {/* Search */}
              <div style={{ position: 'relative', flex: 1, minWidth: '220px' }}>
                <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  className="form-input"
                  placeholder="ស្វែងរកប្រធានបទ ឬការពិពណ៌នា..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{ paddingLeft: '38px', borderRadius: '12px' }}
                />
              </div>

              {/* Department Filter */}
              <div style={{ minWidth: '190px' }}>
                <select
                  className="form-select"
                  value={deptFilter}
                  onChange={(e) => setDeptFilter(e.target.value)}
                  style={{ borderRadius: '12px' }}
                >
                  <option value="ALL">គ្រប់ផ្នែកទាំងអស់ (All Departments)</option>
                  {DEFAULT_DEPARTMENTS.map(d => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Actions: Grid/Table switcher, Refresh */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ViewModeToggle mode={viewMode} onChange={setViewMode} />

              <button
                type="button"
                onClick={loadMeetings}
                className="btn btn-secondary"
                style={{ borderRadius: '12px' }}
                title="Refresh"
              >
                <RotateCw size={15} className={loading ? 'fa-spin' : ''} />
                <span>ផ្ទុកឡើងវិញ</span>
              </button>
            </div>
          </div>

          {/* Cards Grid Mode */}
          {viewMode === 'grid' && (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
                gap: '20px'
              }}
            >
              {loading ? (
                <div className="hrm-card" style={{ gridColumn: '1/-1', padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <RotateCw size={32} className="fa-spin" style={{ margin: '0 auto 16px auto', display: 'block', color: 'var(--primary)' }} />
                  <div>កំពុងទាញយកទិន្នន័យកិច្ចប្រជុំ...</div>
                </div>
              ) : filteredMeetings.length === 0 ? (
                <div className="hrm-card" style={{ gridColumn: '1/-1', padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Video size={48} style={{ margin: '0 auto 16px auto', display: 'block', opacity: 0.2 }} />
                  <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>មិនទាន់មានកិច្ចប្រជុំទេ</div>
                  <p style={{ fontSize: '13px', marginTop: '6px' }}>អ្នកអាចចុចលើ "បង្ហោះកិច្ចប្រជុំថ្មី" ដើម្បីបន្ថែមទិន្នន័យកិច្ចប្រជុំដំបូង</p>
                  <button onClick={() => setActiveTab('create')} className="btn btn-primary" style={{ marginTop: '12px' }}>
                    <Plus size={16} /> បង្ហោះកិច្ចប្រជុំថ្មីឥឡូវនេះ
                  </button>
                </div>
              ) : (
                filteredMeetings.map((m) => {
                  const coverRaw = m.photo_url || (Array.isArray(m.photos) && m.photos[0]) || (Array.isArray(m.related_photos) && m.related_photos[0]) || null;
                  const cover = coverRaw ? getFullMediaUrl(coverRaw) : null;
                  const photosCount = (Array.isArray(m.photos) ? m.photos.length : 0) || (Array.isArray(m.related_photos) ? m.related_photos.length : 0) || (cover ? 1 : 0);
                  const rawAudio = m.audio_url || m.mp3_url || m.audio_file_path || (m as any).audio_path || null;
                  const audio = rawAudio ? getFullMediaUrl(rawAudio) : null;
                  const isAudioPlaying = audio && currentlyPlayingAudio === audio;

                  return (
                    <div
                      key={m.id}
                      className="hrm-card hover-lift"
                      style={{
                        borderRadius: '18px',
                        overflow: 'hidden',
                        display: 'flex',
                        flexDirection: 'column',
                        border: '1px solid #e2e8f0',
                        transition: 'transform 0.2s ease, box-shadow 0.2s ease'
                      }}
                    >
                      {/* Card Cover Image */}
                      <div
                        onClick={() => setViewModalMeeting(m)}
                        style={{
                          width: '100%',
                          height: '170px',
                          background: 'linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%)',
                          position: 'relative',
                          cursor: 'pointer',
                          overflow: 'hidden',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}
                      >
                        {cover ? (
                          <img
                            src={cover}
                            alt={m.topic || m.title}
                            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                          />
                        ) : (
                          <div style={{ textAlign: 'center', color: 'rgba(255,255,255,0.75)' }}>
                            <Video size={42} style={{ marginBottom: '8px' }} />
                            <div style={{ fontSize: '13px', fontWeight: 600 }}>VVC Meetings</div>
                          </div>
                        )}

                        {/* Top Overlay Badges */}
                        <div style={{ position: 'absolute', top: '12px', left: '12px', right: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              background: 'rgba(15, 23, 42, 0.75)',
                              backdropFilter: 'blur(6px)',
                              color: '#fff',
                              padding: '4px 10px',
                              borderRadius: '999px',
                              fontSize: '11px',
                              fontWeight: 700
                            }}
                          >
                            {m.department || m.category || 'General'}
                          </span>

                          <span
                            style={{
                              background: 'rgba(15, 23, 42, 0.75)',
                              backdropFilter: 'blur(6px)',
                              color: '#fff',
                              padding: '4px 10px',
                              borderRadius: '999px',
                              fontSize: '11px',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            <Calendar size={12} />
                            {m.meeting_date || m.date || '—'}
                          </span>
                        </div>

                        {/* Bottom Overlay: Photos Count */}
                        {photosCount > 0 && (
                          <div
                            style={{
                              position: 'absolute',
                              bottom: '10px',
                              right: '12px',
                              background: 'rgba(0,0,0,0.65)',
                              backdropFilter: 'blur(4px)',
                              color: '#fff',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            <ImageIcon size={12} />
                            <span>{photosCount} រូបភាព</span>
                          </div>
                        )}
                      </div>

                      {/* Card Content */}
                      <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', flex: 1 }}>
                        <h3
                          onClick={() => setViewModalMeeting(m)}
                          style={{
                            fontSize: '16px',
                            fontWeight: 800,
                            color: 'var(--text-primary)',
                            margin: '0 0 10px 0',
                            lineHeight: 1.4,
                            cursor: 'pointer'
                          }}
                        >
                          {m.topic || m.title || 'គ្មានចំណងជើង'}
                        </h3>

                        <p
                          style={{
                            fontSize: '13px',
                            color: 'var(--text-secondary)',
                            lineHeight: 1.6,
                            margin: '0 0 16px 0',
                            display: '-webkit-box',
                            WebkitLineClamp: 3,
                            WebkitBoxOrient: 'vertical',
                            overflow: 'hidden',
                            flex: 1
                          }}
                        >
                          {m.description || m.summary || 'មិនមានការពិពណ៌នាលម្អិតទេ។'}
                        </p>

                        {/* Audio / Links Quick Bar */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
                          {audio ? (
                            <button
                              type="button"
                              onClick={() => handleToggleAudio(audio)}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '6px',
                                padding: '6px 12px',
                                borderRadius: '8px',
                                fontSize: '12px',
                                fontWeight: 700,
                                border: 'none',
                                cursor: 'pointer',
                                background: isAudioPlaying ? '#ef4444' : '#10b981',
                                color: '#fff',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              {isAudioPlaying ? <Pause size={13} /> : <Play size={13} />}
                              <span>{isAudioPlaying ? 'កំពុងចាក់សំឡេង...' : 'ស្តាប់សំឡេង Audio'}</span>
                            </button>
                          ) : (
                            <span style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                              <Volume2 size={13} style={{ opacity: 0.4 }} /> គ្មានសំឡេង
                            </span>
                          )}

                          {m.external_url && (
                            <a
                              href={m.external_url}
                              target="_blank"
                              rel="noreferrer"
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                padding: '6px 10px',
                                borderRadius: '8px',
                                fontSize: '12px',
                                fontWeight: 600,
                                background: '#f1f5f9',
                                color: '#334155',
                                textDecoration: 'none'
                              }}
                            >
                              <ExternalLink size={12} />
                              <span>Link</span>
                            </a>
                          )}
                        </div>

                        {/* Card Footer Actions */}
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            paddingTop: '14px',
                            borderTop: '1px solid #f1f5f9',
                            marginTop: 'auto',
                            gap: '6px',
                            flexWrap: 'wrap'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleOpenAiModal(m)}
                              style={{
                                borderRadius: '8px',
                                padding: '6px 12px',
                                fontSize: '12px',
                                fontWeight: 700,
                                border: 'none',
                                cursor: 'pointer',
                                background: (m.summary && m.summary.trim()) ? '#0d9488' : '#d97706',
                                color: '#fff',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              <Sparkles size={13} />
                              <span>{(m.summary && m.summary.trim()) ? 'មើលសង្ខេប AI' : 'AI សង្ខេប'}</span>
                            </button>

                            <button
                              type="button"
                              onClick={() => setViewModalMeeting(m)}
                              className="btn btn-secondary btn-sm"
                              style={{ borderRadius: '8px' }}
                            >
                              <Eye size={14} />
                              <span>មើលលម្អិត</span>
                            </button>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleOpenEdit(m)}
                              className="btn btn-secondary btn-sm"
                              style={{ borderRadius: '8px' }}
                              title="កែប្រែ"
                            >
                              <Edit3 size={14} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDelete(m.id)}
                              className="btn btn-danger btn-sm"
                              style={{ borderRadius: '8px' }}
                              title="លុប"
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* Table Mode */}
          {viewMode === 'table' && (
            <div className="hrm-card" style={{ padding: '0', overflow: 'hidden' }}>
              <div className="table-container">
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th style={{ width: '60px' }}>រូបភាព</th>
                      <th>ប្រធានបទកិច្ចប្រជុំ</th>
                      <th>ផ្នែក / សាខា</th>
                      <th>កាលបរិច្ឆេទ</th>
                      <th>សំឡេង & រូបភាព</th>
                      <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                          កំពុងទាញយកទិន្នន័យ...
                        </td>
                      </tr>
                    ) : filteredMeetings.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                          មិនមានទិន្នន័យកិច្ចប្រជុំឡើយ
                        </td>
                      </tr>
                    ) : (
                      filteredMeetings.map((m) => {
                        const coverRaw = m.photo_url || (Array.isArray(m.photos) && m.photos[0]) || (Array.isArray(m.related_photos) && m.related_photos[0]) || null;
                        const cover = coverRaw ? getFullMediaUrl(coverRaw) : null;
                        const rawAudio = m.audio_url || m.mp3_url || m.audio_file_path || (m as any).audio_path || null;
                        const audio = rawAudio ? getFullMediaUrl(rawAudio) : null;
                        const isAudioPlaying = audio && currentlyPlayingAudio === audio;

                        return (
                          <tr key={m.id}>
                            <td>
                              <div
                                onClick={() => setViewModalMeeting(m)}
                                style={{
                                  width: '44px',
                                  height: '44px',
                                  borderRadius: '10px',
                                  background: '#f1f5f9',
                                  overflow: 'hidden',
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  cursor: 'pointer'
                                }}
                              >
                                {cover ? (
                                  <img src={cover} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                                ) : (
                                  <Video size={20} style={{ color: '#94a3b8' }} />
                                )}
                              </div>
                            </td>
                            <td>
                              <div
                                onClick={() => setViewModalMeeting(m)}
                                style={{ fontWeight: 700, color: 'var(--text-primary)', cursor: 'pointer' }}
                              >
                                {m.topic || m.title}
                              </div>
                              <div style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '320px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: '2px' }}>
                                {m.description || m.summary || '—'}
                              </div>
                            </td>
                            <td>
                              <span className="badge badge-primary">
                                {m.department || m.category || 'General'}
                              </span>
                            </td>
                            <td style={{ fontSize: '13px', fontWeight: 600 }}>
                              {m.meeting_date || m.date || '—'}
                            </td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                {audio && (
                                  <button
                                    type="button"
                                    onClick={() => handleToggleAudio(audio)}
                                    style={{
                                      border: 'none',
                                      borderRadius: '6px',
                                      padding: '4px 8px',
                                      fontSize: '11px',
                                      fontWeight: 700,
                                      cursor: 'pointer',
                                      background: isAudioPlaying ? '#fee2e2' : '#dcfce7',
                                      color: isAudioPlaying ? '#dc2626' : '#16a34a',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px'
                                    }}
                                  >
                                    {isAudioPlaying ? <Pause size={12} /> : <Play size={12} />}
                                    <span>Audio</span>
                                  </button>
                                )}
                                {m.external_url && (
                                  <a href={m.external_url} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ padding: '3px 7px' }}>
                                    <ExternalLink size={12} />
                                  </a>
                                )}
                              </div>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                <button
                                  type="button"
                                  onClick={() => handleOpenAiModal(m)}
                                  style={{
                                    border: 'none',
                                    borderRadius: '6px',
                                    padding: '4px 8px',
                                    fontSize: '11px',
                                    fontWeight: 700,
                                    cursor: 'pointer',
                                    background: (m.summary && m.summary.trim()) ? '#ccfbf1' : '#fef3c7',
                                    color: (m.summary && m.summary.trim()) ? '#0f766e' : '#b45309',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                >
                                  <Sparkles size={12} />
                                  <span>{(m.summary && m.summary.trim()) ? 'មើលសង្ខេប AI' : 'AI សង្ខេប'}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setViewModalMeeting(m)}
                                  className="btn btn-secondary btn-sm"
                                  title="មើល"
                                >
                                  <Eye size={14} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleOpenEdit(m)}
                                  className="btn btn-secondary btn-sm"
                                  title="កែប្រែ"
                                >
                                  <Edit3 size={14} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDelete(m.id)}
                                  className="btn btn-danger btn-sm"
                                  title="លុប"
                                >
                                  <Trash2 size={14} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: POST NEW MEETING                                                   */}
      {/* ========================================================================= */}
      {activeTab === 'create' && (
        <div className="hrm-card" style={{ padding: '28px', maxWidth: '840px', margin: '0 auto', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid #f1f5f9', paddingBottom: '14px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Plus size={20} style={{ color: 'var(--primary)' }} />
              បង្ហោះកិច្ចប្រជុំថ្មី (Post New Meeting)
            </h3>
            <button
              type="button"
              onClick={() => setActiveTab('list')}
              className="btn btn-secondary btn-sm"
            >
              ត្រឡប់ទៅបញ្ជីកិច្ចប្រជុំ
            </button>
          </div>

          {submitSuccess && (
            <div
              style={{
                padding: '14px 20px',
                borderRadius: '12px',
                background: 'var(--success-light, #dcfce7)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: 'var(--success, #166534)',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                fontSize: '14px',
                fontWeight: 700,
                marginBottom: '20px'
              }}
            >
              <Check size={18} />
              <span>កិច្ចប្រជុំត្រូវបានបង្ហោះដោយជោគជ័យ!</span>
            </div>
          )}

          <form onSubmit={handleCreateSubmit}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Meeting Topic */}
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>
                  ប្រធានបទកិច្ចប្រជុំ (Meeting Topic / Title) *
                </label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="ឧ. កិច្ចប្រជុំប្រចាំខែ - វឌ្ឍនភាពការងារ & ផែនការលក់"
                  value={createForm.topic}
                  onChange={(e) => setCreateForm({ ...createForm, topic: e.target.value })}
                  required
                  style={{ fontSize: '15px', padding: '12px 14px' }}
                />
              </div>

              {/* Department & Meeting Date */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    ផ្នែក / សាខា (Department / Category) *
                  </label>
                  <select
                    className="form-select"
                    value={createForm.department}
                    onChange={(e) => setCreateForm({ ...createForm, department: e.target.value })}
                    style={{ padding: '12px 14px' }}
                  >
                    {DEFAULT_DEPARTMENTS.map(d => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    កាលបរិច្ឆេទប្រជុំ (Meeting Date) *
                  </label>
                  <input
                    type="date"
                    className="form-input"
                    value={createForm.date}
                    onChange={(e) => setCreateForm({ ...createForm, date: e.target.value })}
                    required
                    style={{ padding: '12px 14px' }}
                  />
                </div>
              </div>

              {/* Duration & External URL */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    រយៈពេល (Duration)
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="ឧ. 30 នាទី, 1 ម៉ោង"
                    value={createForm.duration}
                    onChange={(e) => setCreateForm({ ...createForm, duration: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    តំណភ្ជាប់ខាងក្រៅ (External URL / Meeting Link)
                  </label>
                  <input
                    type="url"
                    className="form-input"
                    placeholder="https://meet.google.com/..."
                    value={createForm.external_url}
                    onChange={(e) => setCreateForm({ ...createForm, external_url: e.target.value })}
                  />
                </div>
              </div>

              {/* Description / Summary */}
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>
                  ខ្លឹមសារ / កំណត់ហេតុកិច្ចប្រជុំ (Description / Meeting Notes)
                </label>
                <textarea
                  className="form-textarea"
                  rows={5}
                  placeholder="បញ្ចូលកំណត់ហេតុ កិច្ចការដែលត្រូវធ្វើ ឬសេចក្តីសង្ខេបកិច្ចប្រជុំ..."
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  style={{ lineHeight: 1.6 }}
                />
              </div>

              {/* Audio Upload Section */}
              <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '14px', border: '1px solid #e2e8f0' }}>
                <label className="form-label" style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <Volume2 size={16} style={{ color: 'var(--primary)' }} />
                  <span>សំឡេងកិច្ចប្រជុំ (Audio Upload / MP3)</span>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px', alignItems: 'center' }}>
                  <div>
                    <input
                      type="file"
                      accept="audio/*,.mp3,.wav,.m4a,.aac"
                      className="form-input"
                      onChange={(e) => handleAudioFileChange(e.target.files ? e.target.files[0] : null)}
                    />
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      គាំទ្រប្រភេទ MP3, WAV, M4A, AAC
                    </div>
                  </div>

                  <div>
                    <input
                      type="url"
                      className="form-input"
                      placeholder="ឬបញ្ចូល Audio URL ផ្ទាល់ (https://...)"
                      value={createForm.audio_url}
                      onChange={(e) => setCreateForm({ ...createForm, audio_url: e.target.value })}
                    />
                  </div>
                </div>

                {(audioFilePreviewUrl || createForm.audio_url) && (
                  <div style={{ marginTop: '12px' }}>
                    <audio controls style={{ width: '100%', height: '40px' }} src={audioFilePreviewUrl || createForm.audio_url}>
                      Your browser does not support audio.
                    </audio>
                  </div>
                )}
              </div>

              {/* Cover Photo & Related Photos */}
              <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '14px', border: '1px solid #e2e8f0' }}>
                <label className="form-label" style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <ImageIcon size={16} style={{ color: 'var(--primary)' }} />
                  <span>រូបភាពកិច្ចប្រជុំ (Cover Photo & Multiple Related Photos)</span>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
                  {/* Cover Photo */}
                  <div>
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                      រូបភាព Cover ចម្បង:
                    </label>
                    <input
                      type="file"
                      accept="image/*"
                      className="form-input"
                      onChange={(e) => handleCoverPhotoChange(e.target.files ? e.target.files[0] : null)}
                    />
                    {coverPhotoPreview && (
                      <div style={{ marginTop: '8px', position: 'relative', width: '120px', height: '80px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #cbd5e1' }}>
                        <img src={coverPhotoPreview} alt="Cover Preview" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                        <button
                          type="button"
                          onClick={() => handleCoverPhotoChange(null)}
                          style={{ position: 'absolute', top: '4px', right: '4px', background: 'rgba(0,0,0,0.6)', color: '#fff', border: 'none', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                        >
                          <X size={12} />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Multiple Photos */}
                  <div>
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                      រូបភាពបន្ថែម (Related Photos - Multiple):
                    </label>
                    <input
                      type="file"
                      accept="image/*"
                      multiple
                      className="form-input"
                      onChange={(e) => handleRelatedPhotosChange(e.target.files)}
                    />
                  </div>
                </div>

                {/* Previews of Related Photos */}
                {relatedPhotoPreviews.length > 0 && (
                  <div style={{ marginTop: '14px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      រូបភាពដែលបានជ្រើសរើស ({relatedPhotoPreviews.length}):
                    </div>
                    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                      {relatedPhotoPreviews.map((url, idx) => (
                        <div key={idx} style={{ position: 'relative', width: '90px', height: '70px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #cbd5e1' }}>
                          <img src={url} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                          <button
                            type="button"
                            onClick={() => removeRelatedPhoto(idx)}
                            style={{ position: 'absolute', top: '3px', right: '3px', background: 'rgba(0,0,0,0.65)', color: '#fff', border: 'none', borderRadius: '50%', width: '18px', height: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                          >
                            <X size={10} />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Submit Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '12px' }}>
                <button
                  type="button"
                  onClick={() => setActiveTab('list')}
                  className="btn btn-secondary"
                  disabled={submitting}
                >
                  បោះបង់
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="btn btn-primary"
                  style={{ minWidth: '180px', justifyContent: 'center' }}
                >
                  {submitting ? (
                    <>
                      <RotateCw size={16} className="fa-spin" />
                      <span>កំពុងបង្ហោះ...</span>
                    </>
                  ) : (
                    <>
                      <Plus size={16} />
                      <span>បង្ហោះកិច្ចប្រជុំ</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW DETAILS MODAL                                                        */}
      {/* ========================================================================= */}
      {viewModalMeeting && (
        <Modal
          isOpen={!!viewModalMeeting}
          onClose={() => setViewModalMeeting(null)}
          title="ព័ត៌មានលម្អិតកិច្ចប្រជុំ (Meeting Details)"
          maxWidth="760px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Header info */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginBottom: '10px' }}>
                <span className="badge badge-primary" style={{ fontSize: '12px', padding: '5px 12px' }}>
                  {viewModalMeeting.department || viewModalMeeting.category || 'General'}
                </span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Calendar size={14} />
                  {viewModalMeeting.meeting_date || viewModalMeeting.date || '—'}
                </span>
                {viewModalMeeting.duration && (
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <Clock size={14} />
                    {viewModalMeeting.duration}
                  </span>
                )}
              </div>

              <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, lineHeight: 1.4 }}>
                {viewModalMeeting.topic || viewModalMeeting.title}
              </h2>
            </div>

            {/* Description */}
            <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '14px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: '#334155', marginBottom: '8px' }}>
                <FileText size={15} style={{ display: 'inline', marginRight: '6px' }} />
                ខ្លឹមសារ / កំណត់ហេតុ
              </div>
              <div style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.75, whiteSpace: 'pre-wrap' }}>
                {viewModalMeeting.description || viewModalMeeting.summary || 'មិនមានកំណត់ត្រាលម្អិតទេ។'}
              </div>
            </div>

            {/* External URL Button */}
            {viewModalMeeting.external_url && (
              <div>
                <a
                  href={viewModalMeeting.external_url}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-secondary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
                >
                  <ExternalLink size={16} />
                  <span>បើកតំណភ្ជាប់កិច្ចប្រជុំ ({viewModalMeeting.external_url})</span>
                </a>
              </div>
            )}

            {/* Audio Recording Player */}
            {(() => {
              const viewAudioRaw = viewModalMeeting.audio_url || viewModalMeeting.mp3_url || viewModalMeeting.audio_file_path || (viewModalMeeting as any).audio_path;
              const viewAudio = viewAudioRaw ? getFullMediaUrl(viewAudioRaw) : null;
              if (!viewAudio) return null;
              return (
                <div style={{ background: '#eef2ff', padding: '16px', borderRadius: '14px', border: '1px solid #c7d2fe' }}>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#3730a3', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Volume2 size={16} />
                    <span>សំឡេងកិច្ចប្រជុំ (Meeting Audio Recording)</span>
                  </div>
                  <audio
                    controls
                    style={{ width: '100%' }}
                    src={viewAudio}
                  >
                    Your browser does not support audio.
                  </audio>
                </div>
              );
            })()}

            {/* Photo Gallery */}
            {(() => {
              const photos: string[] = [];
              if (viewModalMeeting.photo_url) {
                photos.push(getFullMediaUrl(viewModalMeeting.photo_url));
              }
              const related = Array.isArray(viewModalMeeting.photos) ? viewModalMeeting.photos : (Array.isArray(viewModalMeeting.related_photos) ? viewModalMeeting.related_photos : []);
              related.forEach(p => {
                if (p) {
                  const full = getFullMediaUrl(p);
                  if (!photos.includes(full)) photos.push(full);
                }
              });

              if (photos.length === 0) return null;

              return (
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#334155', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ImageIcon size={16} />
                    <span>រូបភាពពាក់ព័ន្ធ ({photos.length})</span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: '10px' }}>
                    {photos.map((src, i) => (
                      <div
                        key={i}
                        onClick={() => setLightboxImage(src)}
                        style={{
                          height: '100px',
                          borderRadius: '10px',
                          overflow: 'hidden',
                          border: '1px solid #e2e8f0',
                          cursor: 'pointer',
                          position: 'relative'
                        }}
                      >
                        <img src={src} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Footer Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px', borderTop: '1px solid #f1f5f9', paddingTop: '16px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => {
                  const m = viewModalMeeting;
                  setViewModalMeeting(null);
                  handleOpenAiModal(m);
                }}
                style={{
                  background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '10px',
                  padding: '8px 14px',
                  fontSize: '13px',
                  fontWeight: 700,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer'
                }}
              >
                <Sparkles size={15} />
                <span>AI កំណត់ហេតុ & សង្ខេប</span>
              </button>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => {
                    const m = viewModalMeeting;
                    setViewModalMeeting(null);
                    handleOpenEdit(m);
                  }}
                  className="btn btn-primary"
                >
                  <Edit3 size={15} />
                  <span>កែប្រែកិច្ចប្រជុំ</span>
                </button>
                <button
                  type="button"
                  onClick={() => setViewModalMeeting(null)}
                  className="btn btn-secondary"
                >
                  បិទ
                </button>
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* EDIT MEETING MODAL                                                        */}
      {/* ========================================================================= */}
      {editModalMeeting && (
        <Modal
          isOpen={!!editModalMeeting}
          onClose={() => setEditModalMeeting(null)}
          title="កែប្រែកិច្ចប្រជុំ (Edit Meeting)"
          maxWidth="700px"
        >
          <form onSubmit={handleEditSubmit}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>ប្រធានបទកិច្ចប្រជុំ *</label>
                <input
                  type="text"
                  className="form-input"
                  value={editForm.topic}
                  onChange={(e) => setEditForm({ ...editForm, topic: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>ផ្នែក / សាខា *</label>
                  <select
                    className="form-select"
                    value={editForm.department}
                    onChange={(e) => setEditForm({ ...editForm, department: e.target.value })}
                  >
                    {DEFAULT_DEPARTMENTS.map(d => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>កាលបរិច្ឆេទ *</label>
                  <input
                    type="date"
                    className="form-input"
                    value={editForm.date}
                    onChange={(e) => setEditForm({ ...editForm, date: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>រយៈពេល</label>
                  <input
                    type="text"
                    className="form-input"
                    value={editForm.duration}
                    onChange={(e) => setEditForm({ ...editForm, duration: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>តំណភ្ជាប់ខាងក្រៅ</label>
                  <input
                    type="url"
                    className="form-input"
                    value={editForm.external_url}
                    onChange={(e) => setEditForm({ ...editForm, external_url: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>ខ្លឹមសារ / កំណត់ហេតុ</label>
                <textarea
                  className="form-textarea"
                  rows={4}
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                />
              </div>

              {/* Audio & Photos edits */}
              <div style={{ background: '#f8fafc', padding: '14px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                <div className="form-group" style={{ marginBottom: '12px' }}>
                  <label className="form-label" style={{ fontWeight: 700 }}>ផ្លាស់ប្តូរសំឡេង (Audio File / URL)</label>
                  <input
                    type="file"
                    accept="audio/*"
                    className="form-input"
                    onChange={(e) => handleAudioFileChange(e.target.files ? e.target.files[0] : null, true)}
                  />
                  <input
                    type="url"
                    className="form-input"
                    placeholder="ឬបញ្ចូល Audio URL ផ្ទាល់"
                    value={editForm.audio_url}
                    onChange={(e) => setEditForm({ ...editForm, audio_url: e.target.value })}
                    style={{ marginTop: '6px' }}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>បន្ថែមរូបភាពថ្មី (Upload Photos)</label>
                  <input
                    type="file"
                    accept="image/*"
                    multiple
                    className="form-input"
                    onChange={(e) => handleRelatedPhotosChange(e.target.files, true)}
                  />
                </div>

                {/* Existing Photos in Edit Form */}
                {editForm.existing_photos.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                      រូបភាពចាស់ៗដែលមានស្រាប់ ({editForm.existing_photos.length}):
                    </label>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {editForm.existing_photos.map((src, i) => (
                        <div key={i} style={{ position: 'relative', width: '70px', height: '55px', borderRadius: '6px', overflow: 'hidden', border: '1px solid #cbd5e1' }}>
                          <img src={src} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                          <button
                            type="button"
                            onClick={() => removeExistingPhotoInEdit(src)}
                            style={{ position: 'absolute', top: '2px', right: '2px', background: 'rgba(239, 68, 68, 0.9)', color: '#fff', border: 'none', borderRadius: '50%', width: '16px', height: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                            title="Remove photo"
                          >
                            <X size={10} />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setEditModalMeeting(null)}
                  className="btn btn-secondary"
                  disabled={editSubmitting}
                >
                  បោះបង់
                </button>
                <button
                  type="submit"
                  disabled={editSubmitting}
                  className="btn btn-primary"
                >
                  {editSubmitting ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកែប្រែ'}
                </button>
              </div>
            </div>
          </form>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* IMAGE LIGHTBOX MODAL                                                      */}
      {/* ========================================================================= */}
      {lightboxImage && (
        <div
          onClick={() => setLightboxImage(null)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px'
          }}
        >
          <button
            onClick={() => setLightboxImage(null)}
            style={{
              position: 'absolute',
              top: '20px',
              right: '20px',
              background: 'rgba(255, 255, 255, 0.2)',
              color: '#fff',
              border: 'none',
              borderRadius: '50%',
              width: '40px',
              height: '40px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              fontSize: '20px'
            }}
          >
            <X size={24} />
          </button>
          <img
            src={lightboxImage}
            alt="Preview"
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: '90vw',
              maxHeight: '90vh',
              objectFit: 'contain',
              borderRadius: '12px',
              boxShadow: '0 20px 50px rgba(0,0,0,0.5)'
            }}
          />
        </div>
      )}

      {/* ========================================================================= */}
      {/* AI MEETING MINUTES & SUMMARY MODAL                                        */}
      {/* ========================================================================= */}
      {aiModalMeeting && (
        <Modal
          isOpen={!!aiModalMeeting}
          onClose={() => setAiModalMeeting(null)}
          title="AI កំណត់ហេតុ & សង្ខេបកិច្ចប្រជុំ (AI Minutes)"
          maxWidth="750px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Header with Meeting Topic */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px', background: 'rgba(245, 158, 11, 0.08)', borderRadius: '12px', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
              <div style={{ padding: '8px', background: '#f59e0b', borderRadius: '10px', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Sparkles size={20} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {aiModalMeeting.topic || aiModalMeeting.title}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', gap: '8px', marginTop: '2px' }}>
                  <span>{aiModalMeeting.department || aiModalMeeting.category || 'General'}</span>
                  <span>•</span>
                  <span>{aiModalMeeting.meeting_date || aiModalMeeting.date || '—'}</span>
                </div>
              </div>
            </div>

            {/* Audio Recording Player Bar (if available) */}
            {(() => {
              const rawAudio = aiModalMeeting.audio_url || aiModalMeeting.mp3_url || aiModalMeeting.audio_file_path || (aiModalMeeting as any).audio_path;
              const audioSrc = rawAudio ? getFullMediaUrl(rawAudio) : null;
              if (!audioSrc) return null;
              return (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    padding: '14px 16px',
                    background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.09) 0%, rgba(168, 85, 247, 0.06) 100%)',
                    borderRadius: '12px',
                    border: '1px solid rgba(99, 102, 241, 0.25)',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.03)'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '13px', fontWeight: 700, color: 'var(--primary)', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Volume2 size={16} style={{ color: aiModalAudioPlaying ? '#6366f1' : 'inherit' }} />
                      <span>សំឡេងកិច្ចប្រជុំ (Audio Recording) {aiModalMeeting.duration ? `— ${aiModalMeeting.duration}` : ''}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginRight: '4px' }}>ល្បឿន:</span>
                      {[1, 1.25, 1.5, 2].map((rate) => (
                        <button
                          key={rate}
                          type="button"
                          onClick={() => {
                            setAiModalPlaybackRate(rate);
                            if (aiModalAudioRef.current) aiModalAudioRef.current.playbackRate = rate;
                          }}
                          style={{
                            padding: '2px 7px',
                            borderRadius: '6px',
                            border: 'none',
                            fontSize: '11px',
                            fontWeight: 700,
                            cursor: 'pointer',
                            background: aiModalPlaybackRate === rate ? 'var(--primary)' : 'rgba(255,255,255,0.06)',
                            color: aiModalPlaybackRate === rate ? '#fff' : 'var(--text-muted)'
                          }}
                        >
                          {rate}x
                        </button>
                      ))}
                    </div>
                  </div>
                  <audio
                    ref={aiModalAudioRef}
                    controls
                    preload="metadata"
                    src={audioSrc}
                    onTimeUpdate={(e) => setAiModalAudioCurrentTime(e.currentTarget.currentTime)}
                    onLoadedMetadata={(e) => setAiModalAudioDuration(e.currentTarget.duration || 0)}
                    onPlay={() => setAiModalAudioPlaying(true)}
                    onPause={() => setAiModalAudioPlaying(false)}
                    style={{
                      width: '100%',
                      height: '38px',
                      borderRadius: '8px'
                    }}
                  >
                    Your browser does not support audio.
                  </audio>
                </div>
              );
            })()}

            {/* Tab Switcher */}
            <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
              <button
                type="button"
                onClick={() => setAiModalTab('summary')}
                style={{
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  padding: '10px',
                  borderRadius: '10px',
                  border: 'none',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  background: aiModalTab === 'summary' ? 'var(--primary)' : 'var(--bg-secondary)',
                  color: aiModalTab === 'summary' ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.2s ease'
                }}
              >
                <FileText size={16} />
                <span>សេចក្តីសង្ខេប (Summary)</span>
              </button>
              <button
                type="button"
                onClick={() => setAiModalTab('transcript')}
                style={{
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  padding: '10px',
                  borderRadius: '10px',
                  border: 'none',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  background: aiModalTab === 'transcript' ? 'var(--primary)' : 'var(--bg-secondary)',
                  color: aiModalTab === 'transcript' ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.2s ease'
                }}
              >
                <Volume2 size={16} />
                <span>អត្ថបទសន្ទនា (Transcript)</span>
              </button>
            </div>

            {/* Content Body */}
            <div style={{ minHeight: '260px', maxHeight: '420px', overflowY: 'auto', padding: '16px', borderRadius: '12px', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              {aiModalLoading ? (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '30px 16px',
                    textAlign: 'center',
                    gap: '18px',
                    background: 'linear-gradient(180deg, rgba(99, 102, 241, 0.04) 0%, rgba(168, 85, 247, 0.03) 100%)',
                    borderRadius: '14px',
                    border: '1px solid rgba(99, 102, 241, 0.15)'
                  }}
                >
                  {/* Glowing Pulse Icon */}
                  <div style={{ position: 'relative', width: '58px', height: '58px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div
                      style={{
                        position: 'absolute',
                        inset: 0,
                        borderRadius: '50%',
                        background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                        opacity: 0.3,
                        animation: 'pulse 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite'
                      }}
                    />
                    <div
                      style={{
                        width: '48px',
                        height: '48px',
                        borderRadius: '50%',
                        background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        boxShadow: '0 6px 16px rgba(99, 102, 241, 0.4)',
                        color: '#fff'
                      }}
                    >
                      <Sparkles size={24} className="fa-spin" style={{ animationDuration: '4s' }} />
                    </div>
                  </div>

                  {/* Stage Headline */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxWidth: '420px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)' }}>
                      AI កំពុងវិភាគ និងស្រង់ទិន្នន័យកិច្ចប្រជុំ
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--primary)', minHeight: '20px' }}>
                      {aiProgressStep}
                    </div>
                  </div>

                  {/* Modern Progress Bar */}
                  <div style={{ width: '100%', maxWidth: '440px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>
                      <span>វឌ្ឍនភាព (Progress)</span>
                      <span
                        style={{
                          background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                          color: '#fff',
                          padding: '2px 10px',
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontWeight: 800,
                          boxShadow: '0 2px 6px rgba(99, 102, 241, 0.25)'
                        }}
                      >
                        {Math.min(100, Math.max(0, aiProgress))}%
                      </span>
                    </div>

                    <div
                      style={{
                        width: '100%',
                        height: '11px',
                        borderRadius: '8px',
                        background: 'rgba(0, 0, 0, 0.08)',
                        overflow: 'hidden',
                        position: 'relative',
                        boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.1)'
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.min(100, Math.max(0, aiProgress))}%`,
                          height: '100%',
                          borderRadius: '8px',
                          background: 'linear-gradient(90deg, #6366f1 0%, #a855f7 50%, #ec4899 100%)',
                          transition: 'width 0.4s ease-out',
                          boxShadow: '0 0 12px rgba(168, 85, 247, 0.5)'
                        }}
                      />
                    </div>

                    {/* Metadata Footer */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      <span>⏱️ រយៈពេលដំណើរការ: {aiProgressElapsed} វិនាទី</span>
                      <span>⚡ Google Gemini & Whisper AI</span>
                    </div>
                  </div>
                </div>
              ) : aiModalError ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '220px', gap: '12px', textAlign: 'center', color: '#ef4444' }}>
                  <div style={{ fontSize: '14px', fontWeight: 700 }}>{aiModalError}</div>
                  <button
                    type="button"
                    onClick={() => handleOpenAiModal(aiModalMeeting, true)}
                    className="btn btn-primary btn-sm"
                    style={{ marginTop: '8px' }}
                  >
                    <RefreshCw size={14} /> ព្យាយាមម្តងទៀត
                  </button>
                </div>
              ) : (
                <div style={{ fontSize: '14px', lineHeight: 1.9, color: 'var(--text-primary)', userSelect: 'text', fontFamily: "'Kantumruy Pro', 'Inter', system-ui, sans-serif" }}>
                  {aiModalTab === 'summary' ? (
                    aiModalSummary ? renderKhmerFormattedText(aiModalSummary) : (
                      <div style={{ textAlign: 'center', padding: '30px 16px', color: 'var(--text-muted)' }}>
                        មិនទាន់មានសេចក្តីសង្ខេបនៅឡើយទេ។
                      </div>
                    )
                  ) : aiModalTranscript ? (
                    renderKaraokeTranscript(aiModalTranscript)
                  ) : (
                    <div style={{ textAlign: 'center', padding: '36px 16px', color: 'var(--text-muted)' }}>
                      <Volume2 size={36} style={{ margin: '0 auto 12px auto', opacity: 0.4, color: 'var(--primary)' }} />
                      <p style={{ marginBottom: '16px', fontSize: '14.5px', fontWeight: 600 }}>មិនទាន់មានអត្ថបទសន្ទនាការនិយាយពិត (Transcript) ពីសំឡេងប្រជុំនៅឡើយទេ។</p>
                      <button
                        type="button"
                        onClick={() => handleOpenAiModal(aiModalMeeting, true)}
                        className="btn btn-primary btn-sm"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '10px 20px', borderRadius: '10px', fontWeight: 700 }}
                      >
                        <RefreshCw size={15} /> ចុចត្រង់នេះដើម្បីឱ្យ AI ស្តាប់ និងទាញយក Transcript ពីសំឡេងឡើងវិញ
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer Actions */}
            {!aiModalLoading && !aiModalError && (aiModalSummary || aiModalTranscript) && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-color)', paddingTop: '14px', flexWrap: 'wrap', gap: '10px' }}>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={handleCopyAiContent}
                    className="btn btn-secondary btn-sm"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                  >
                    {copiedText ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
                    <span>{copiedText ? 'បានចម្លងរួចរាល់!' : 'ចម្លងអត្ថបទ'}</span>
                  </button>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => handleOpenAiModal(aiModalMeeting, true)}
                    className="btn btn-secondary btn-sm"
                    title="បង្កើតសេចក្តីសង្ខេបសារជាថ្មី"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#d97706' }}
                  >
                    <RefreshCw size={14} />
                    <span>បង្កើតសារជាថ្មី</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setAiModalMeeting(null)}
                    className="btn btn-primary btn-sm"
                  >
                    រួចរាល់
                  </button>
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
