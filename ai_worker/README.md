# VVC Meeting AI Worker

Local/VPS worker for meeting audio transcription and Khmer summarization.

## What It Does

- Downloads meeting audio from the PHP app
- Splits long audio into smaller chunks with `ffmpeg`
- Transcribes each chunk with `faster-whisper`
- Summarizes long transcripts hierarchically in Khmer with `Ollama`
- Returns `transcript + summary + structured JSON`

## Endpoints

- `GET /health`
- `POST /summarize-meeting`
- `POST /summarize-meeting-async`
- `GET /jobs/{job_id}`

## Request Body

```json
{
  "meeting_id": 123,
  "topic": "Weekly meeting",
  "department": "IT",
  "description": "Optional context",
  "audio_url": "https://app.vvc.asia/flutter/uploads/meetings/audio/file.m4a",
  "transcript_text": "",
  "language": "km"
}
```

## Response Shape

```json
{
  "success": true,
  "summary": "...",
  "analysis": {
    "headline": "...",
    "overview": "...",
    "key_points": [],
    "decisions": [],
    "action_items": [],
    "next_steps": [],
    "keywords": []
  },
  "transcript": "...",
  "transcript_provider": "local-worker",
  "transcript_model": "faster-whisper:large-v3",
  "summary_provider": "local-worker",
  "summary_model": "ollama:qwen3:8b"
}
```

## Windows Setup

1. Install Python 3.10+
2. Install FFmpeg and make sure `ffmpeg` works in `PATH`
3. Install Ollama: <https://ollama.com/download>
4. Pull a model:

```powershell
ollama pull qwen3:8b
```

5. Create virtual env and install packages:

```powershell
cd ai_worker
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

6. Copy `.env.example` values into your system environment or shell session
7. Start worker:

```powershell
uvicorn app:app --host 0.0.0.0 --port 8099
```

## Ubuntu VPS Setup

```bash
sudo apt update
sudo apt install -y ffmpeg python3 python3-venv python3-pip
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b
cd ai_worker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8099
```

## PHP App Integration

Set these values in the main project `.env`:

```env
MEETING_AI_WORKER_URL=http://YOUR-WORKER:8099
MEETING_AI_WORKER_TOKEN=change-this-token
MEETING_AI_WORKER_TIMEOUT=600
MEETING_AI_LOCAL_ONLY=1
```

If `MEETING_AI_LOCAL_ONLY=1`, `api.php` will use only the local worker for meeting summarization and will not fall back to Groq/OpenAI.

## Notes

- `qwen3:8b` is a good default for CPU-friendly Khmer summaries
- If your machine is stronger, try a larger Ollama model
- `large-v3` gives stronger transcription quality but uses more RAM/CPU
- For 4-5 hour recordings, prefer `WHISPER_MODEL=small` or `base` on CPU machines
- Long audio is now chunked automatically; adjust `AUDIO_CHUNK_MINUTES` and `SUMMARY_BATCH_MAX_CHARS` in `.env`
- If your audio files are very large, increase `MAX_DOWNLOAD_MB`
