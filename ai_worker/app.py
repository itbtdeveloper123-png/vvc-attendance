import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from faster_whisper import WhisperModel
from pydantic import BaseModel, Field


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("meeting-ai-worker")

APP_TITLE = "VVC Meeting AI Worker"
APP_VERSION = "1.0.0"

WORKER_TOKEN = os.getenv("MEETING_AI_WORKER_TOKEN", "").strip()
WHISPER_MODEL_NAME = os.getenv("WHISPER_MODEL", "large-v3").strip() or "large-v3"
WHISPER_DEVICE = os.getenv("WHISPER_DEVICE", "auto").strip() or "auto"
WHISPER_COMPUTE_TYPE = os.getenv("WHISPER_COMPUTE_TYPE", "int8").strip() or "int8"
WHISPER_BEAM_SIZE = int(os.getenv("WHISPER_BEAM_SIZE", "5") or "5")
WHISPER_VAD_FILTER = os.getenv("WHISPER_VAD_FILTER", "1").strip() not in {"0", "false", "False"}
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b").strip() or "qwen3:8b"
OLLAMA_VISION_MODEL = os.getenv("OLLAMA_VISION_MODEL", "").strip()
if not OLLAMA_VISION_MODEL:
    _guess = OLLAMA_MODEL.lower()
    if any(v in _guess for v in ("llava", "bakllava", "moondream", "vision", "-vl", "chatgr", "pixtral", "llama3.2-vision", "llama4-vision", "gemma3:4b")):
        OLLAMA_VISION_MODEL = OLLAMA_MODEL
    else:
        OLLAMA_VISION_MODEL = "llava:7b"
WORKER_REQUEST_TIMEOUT = int(os.getenv("WORKER_REQUEST_TIMEOUT", "600") or "600")
MAX_DOWNLOAD_MB = int(os.getenv("MAX_DOWNLOAD_MB", "512") or "512")
PRELOAD_WHISPER = os.getenv("PRELOAD_WHISPER", "0").strip() in {"1", "true", "True", "yes", "on"}
WORKER_JOB_TTL_SECONDS = int(os.getenv("WORKER_JOB_TTL_SECONDS", "3600") or "3600")
AUDIO_CHUNK_MINUTES = int(os.getenv("AUDIO_CHUNK_MINUTES", "15") or "15")
AUDIO_CHUNK_THRESHOLD_MB = int(os.getenv("AUDIO_CHUNK_THRESHOLD_MB", "48") or "48")
SUMMARY_BATCH_MAX_CHARS = int(os.getenv("SUMMARY_BATCH_MAX_CHARS", "12000") or "12000")
SUMMARY_RECURSION_LIMIT = int(os.getenv("SUMMARY_RECURSION_LIMIT", "4") or "4")

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


def _default_ffmpeg_install_steps() -> Dict[str, Any]:
    if IS_WINDOWS:
        return {
            "title": "ដំឡើង FFmpeg លើ Windows",
            "steps": [
                "វិធីទី ១ (លឿនបំផុត)៖ បើក PowerShell រង្វាស់ Administrator រួចរត់៖ winget install --id Gyan.FFmpeg -e --accept-source-agreements --accept-package-agreements",
                "វិធីទី ២៖ បើកម៉ឺនុយ Chocolatey៖ choco install ffmpeg -y",
                "វិធីទី ៣៖ បើកម៉ឺនុយ Scoop៖ scoop install ffmpeg",
                "វិធីទី ៤ (ដោយដៃ)៖ ទៅ https://www.gyan.dev/ffmpeg/builds/ → ទាញយក ffmpeg-release-essentials.zip → ដកហូតដាក់ C:\\ffmpeg បន្ទាប់មកបន្ថែម C:\\ffmpeg\\bin ទៅក្នុង System PATH របស់ Windows។",
                "បន្ទាប់ពីដំឡើង រួចរត់៖ ffmpeg -version ដើម្បីផ្ទៀងផ្ទាត់។ បើមិនដំណើរទេ សូម set FFMPEG_BINARY=C:\\ffmpeg\\bin\\ffmpeg.exe ក្នុង file .env របស់គម្រោង។",
            ],
        }
    if sys.platform == "darwin":
        return {
            "title": "Install FFmpeg (macOS)",
            "steps": [
                "Homebrew: brew install ffmpeg",
                "MacPorts: sudo port install ffmpeg",
                "Set FFMPEG_BINARY=/opt/homebrew/bin/ffmpeg ក្នុង .env ប្រសិនបើ Apple Silicon",
            ],
        }
    return {
        "title": "Install FFmpeg (Linux)",
        "steps": [
            "Debian/Ubuntu: sudo apt update && sudo apt install -y ffmpeg",
            "RHEL/CentOS/Rocky: sudo dnf install -y ffmpeg",
            "Fedora: sudo dnf install -y ffmpeg",
            "Arch: sudo pacman -S --noconfirm ffmpeg",
            "Snap: sudo snap install ffmpeg",
            "Set FFMPEG_BINARY=/usr/bin/ffmpeg ក្នុង .env ប្រសិនបើ PATH មិនមែនជាអថេរ។",
        ],
    }


def _common_ffmpeg_candidates() -> List[str]:
    configured = os.getenv("FFMPEG_BINARY", "").strip()
    cands: List[str] = []
    if configured:
        cands.append(configured)
        if os.path.isdir(configured):
            base = configured.rstrip(os.sep)
            cands.append(os.path.join(base, "ffmpeg.exe" if IS_WINDOWS else "ffmpeg"))
            cands.append(os.path.join(base, "bin", "ffmpeg.exe" if IS_WINDOWS else "ffmpeg"))
    cands.append("ffmpeg.exe" if IS_WINDOWS else "ffmpeg")
    if IS_WINDOWS:
        pf = os.getenv("ProgramFiles", r"C:\Program Files")
        pfx86 = os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)")
        pd = os.getenv("ProgramData", r"C:\ProgramData")
        up = os.getenv("USERPROFILE", r"C:\Users\Public")
        sd = os.getenv("SystemDrive", "C:")
        extra = [
            os.path.join(pf, "FFmpeg", "bin", "ffmpeg.exe"),
            os.path.join(pf, "ffmpeg", "bin", "ffmpeg.exe"),
            os.path.join(pf, "FFmpeg", "ffmpeg.exe"),
            os.path.join(pfx86, "FFmpeg", "bin", "ffmpeg.exe"),
            os.path.join(pfx86, "ffmpeg", "bin", "ffmpeg.exe"),
            os.path.join(pd, "chocolatey", "bin", "ffmpeg.exe"),
            os.path.join(sd, os.sep, "ffmpeg", "bin", "ffmpeg.exe"),
            os.path.join(sd, os.sep, "ffmpeg", "ffmpeg.exe"),
            os.path.join(up, "scoop", "shims", "ffmpeg.exe"),
            os.path.join(up, "scoop", "apps", "ffmpeg", "current", "bin", "ffmpeg.exe"),
            os.path.join(sd, os.sep, "xampp", "apache", "bin", "ffmpeg.exe"),
            os.path.join(sd, os.sep, "xampp", "php", "ffmpeg.exe"),
            os.path.join(sd, os.sep, "xampp", "mysql", "bin", "ffmpeg.exe"),
            os.path.join(pf, "Gyan", "FFmpeg", "bin", "ffmpeg.exe"),
            os.path.join(pf, "BuildTools", "ffmpeg", "bin", "ffmpeg.exe"),
            os.path.join(up, "AppData", "Local", "Microsoft", "WinGet", "Packages", "Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe", "ffmpeg", "bin", "ffmpeg.exe"),
            os.path.join(up, "AppData", "Local", "Microsoft", "WinGet", "Packages", "BtbN.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe", "ffmpeg", "bin", "ffmpeg.exe"),
        ]
        cands.extend(extra)
    else:
        cands.extend([
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
            "/opt/homebrew/bin/ffmpeg",
            "/home/linuxbrew/.linuxbrew/bin/ffmpeg",
            "/snap/bin/ffmpeg",
            "/app/bin/ffmpeg",
            "/usr/bin/vendor_perl/ffmpeg",
        ])
    seen = set()
    result: List[str] = []
    for c in cands:
        if not c:
            continue
        k = c.lower() if IS_WINDOWS else c
        if k in seen:
            continue
        seen.add(k)
        result.append(c)
    return result


def resolve_ffmpeg_binary() -> Tuple[str, str, Dict[str, Any]]:
    """Return (binary_to_use, human_error, install_steps_dict)."""
    install_steps = _default_ffmpeg_install_steps()
    candidates = _common_ffmpeg_candidates()
    # First pass: PATH-less absolute candidates (or configured)
    resolved_configured: Optional[str] = None
    for cand in candidates:
        if os.path.isabs(cand):
            if os.path.isdir(cand):
                continue
            if os.path.isfile(cand):
                # Keep first absolute file hit as best-effort configured resolved
                if resolved_configured is None:
                    resolved_configured = cand
        else:
            # Relative or bare name: try shutil.which
            found = shutil.which(cand)
            if found:
                return found, "", install_steps
    if resolved_configured is not None:
        return resolved_configured, "", install_steps
    # Fallback: fall back to whatever is configured (bare "ffmpeg" command usually) so caller can error nicely
    configured = os.getenv("FFMPEG_BINARY", "ffmpeg").strip() or "ffmpeg"
    last_path = candidates[-1] if candidates else configured
    if IS_WINDOWS:
        msg = (
            "FFmpeg មិនទាន់បានដំឡើងនៅលើ Windows នោះទេ។ "
            "សូមធ្វើតាមជំហាននៅក្នុង install_steps ដើម្បីដំឡើង។ "
            f"(Last checked: {last_path})"
        )
    else:
        msg = (
            "FFmpeg is not installed on this server yet. "
            "Please install the ffmpeg package using the steps in install_steps. "
            f"(Last checked: {last_path})"
        )
    return configured, msg, install_steps


# Finalize FFMPEG_BINARY early so all callers use the resolved path
FFMPEG_BINARY, FFMPEG_MISSING_ERROR, FFMPEG_INSTALL_STEPS = resolve_ffmpeg_binary()

WORKER_READY: Dict[str, Any] = {
    "ffmpeg_ok": False,
    "ffmpeg_error": "",
    "ffmpeg_install_steps": FFMPEG_INSTALL_STEPS,
    "whisper_ok": True,
    "whisper_error": "",
    "whisper_loaded": False,
}
WORKER_JOBS: Dict[str, Dict[str, Any]] = {}
WORKER_JOBS_LOCK = threading.Lock()


class MeetingSummaryRequest(BaseModel):
    meeting_id: Optional[int] = None
    topic: str = ""
    department: str = ""
    description: str = ""
    audio_url: str = ""
    transcript_text: str = ""
    language: str = "km"


class ProductAnalysisRequest(BaseModel):
    system_prompt: str = ""
    user_prompt: str = ""
    image_base64: str = ""
    mime_type: str = "image/jpeg"


app = FastAPI(title=APP_TITLE, version=APP_VERSION)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled worker exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "detail": compact_error_text(exc),
        },
    )


def require_token(authorization: Optional[str]) -> None:
    if WORKER_TOKEN == "":
        return

    bearer = (authorization or "").strip()
    expected = f"Bearer {WORKER_TOKEN}"
    if bearer != expected:
        raise HTTPException(status_code=401, detail="Unauthorized worker token.")


def compact_error_text(raw: Any, limit: int = 240) -> str:
    text = " ".join(str(raw or "").split()).strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def refresh_worker_ready_state(load_whisper: bool = False) -> Dict[str, Any]:
    ffmpeg_ok = True
    ffmpeg_error = ""
    whisper_ok = True
    whisper_error = ""
    whisper_loaded = get_whisper_model.cache_info().currsize > 0

    try:
        ensure_command_exists(FFMPEG_BINARY)
    except Exception as exc:
        ffmpeg_ok = False
        ffmpeg_error = compact_error_text(exc)

    if load_whisper:
        try:
            get_whisper_model()
            whisper_loaded = True
        except Exception as exc:
            whisper_ok = False
            whisper_error = compact_error_text(exc)
    elif not whisper_loaded:
        whisper_error = "Whisper model is not loaded yet."

    WORKER_READY["ffmpeg_ok"] = ffmpeg_ok
    WORKER_READY["ffmpeg_error"] = ffmpeg_error
    WORKER_READY["ffmpeg_install_steps"] = FFMPEG_INSTALL_STEPS
    WORKER_READY["whisper_ok"] = whisper_ok
    WORKER_READY["whisper_error"] = whisper_error
    WORKER_READY["whisper_loaded"] = whisper_loaded
    return dict(WORKER_READY)


def prune_worker_jobs() -> None:
    cutoff = time.time() - max(300, WORKER_JOB_TTL_SECONDS)
    stale_ids: List[str] = []
    with WORKER_JOBS_LOCK:
        for job_id, job in WORKER_JOBS.items():
            finished_at = float(job.get("finished_at") or 0)
            if finished_at > 0 and finished_at < cutoff:
                stale_ids.append(job_id)
        for job_id in stale_ids:
            WORKER_JOBS.pop(job_id, None)


def create_worker_job(request: "MeetingSummaryRequest") -> Dict[str, Any]:
    prune_worker_jobs()
    job_id = uuid.uuid4().hex
    now = time.time()
    job = {
        "job_id": job_id,
        "status": "queued",
        "success": True,
        "message": "",
        "created_at": now,
        "updated_at": now,
        "started_at": 0.0,
        "finished_at": 0.0,
        "result": None,
    }
    with WORKER_JOBS_LOCK:
        WORKER_JOBS[job_id] = job
    return dict(job)


def update_worker_job(job_id: str, **fields: Any) -> Dict[str, Any]:
    with WORKER_JOBS_LOCK:
        job = WORKER_JOBS.get(job_id)
        if not job:
            raise KeyError(job_id)
        job.update(fields)
        job["updated_at"] = time.time()
        return dict(job)


def get_worker_job(job_id: str) -> Optional[Dict[str, Any]]:
    with WORKER_JOBS_LOCK:
        job = WORKER_JOBS.get(job_id)
        return dict(job) if job else None


def extract_json_payload(content: str) -> Optional[Dict[str, Any]]:
    text = (content or "").strip()
    if not text:
        return None

    text = text.lstrip("\ufeff")
    text = re.sub(r"<think\b[^>]*>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<reasoning\b[^>]*>.*?</reasoning>", "", text, flags=re.DOTALL | re.IGNORECASE)

    first_brace = text.find("{")
    if first_brace > 0:
        lead = text[:first_brace]
        if "<think" in lead.lower() or "<reasoning" in lead.lower():
            text = text[first_brace:]

    text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\s*```\s*$", "", text.strip(), flags=re.IGNORECASE)
    text = text.strip()
    if not text:
        return None

    try:
        decoded = json.loads(text)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        pass

    text_no_trailing = re.sub(r",\s*([}\]])", r"\1", text)
    try:
        decoded = json.loads(text_no_trailing)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None

    for candidate in (text[start : end + 1], re.sub(r",\s*([}\]])", r"\1", text[start : end + 1])):
        try:
            decoded = json.loads(candidate)
            if isinstance(decoded, dict):
                return decoded
        except Exception:
            continue

    length = len(text)
    for s in range(length):
        if text[s] != "{":
            continue
        depth = 0
        in_string = False
        escaped = False
        for i in range(s, length):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                    continue
                if ch == "\\":
                    escaped = True
                    continue
                if ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
                continue
            if ch == "{":
                depth += 1
                continue
            if ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[s : i + 1]
                    for c in (candidate, re.sub(r",\s*([}\]])", r"\1", candidate)):
                        try:
                            decoded = json.loads(c)
                            if isinstance(decoded, dict):
                                return decoded
                        except Exception:
                            continue
                    break
    return None


def unique_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    output: List[str] = []
    seen = set()
    for item in value:
        text = str(item or "").strip()
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def normalize_analysis(payload: Dict[str, Any], transcript_text: str = "") -> Dict[str, Any]:
    if not payload:
        return {
            "headline": "របាយការណ៍កិច្ចប្រជុំ",
            "overview": transcript_text.strip(),
            "key_points": [],
            "decisions": [],
            "action_items": [],
            "next_steps": [],
            "keywords": [],
        }

    return {
        "headline": str(payload.get("headline") or "របាយការណ៍កិច្ចប្រជុំ").strip(),
        "overview": str(payload.get("overview") or payload.get("summary") or "").strip(),
        "key_points": unique_string_list(payload.get("key_points") or []),
        "decisions": unique_string_list(payload.get("decisions") or []),
        "action_items": unique_string_list(payload.get("action_items") or []),
        "next_steps": unique_string_list(payload.get("next_steps") or []),
        "keywords": unique_string_list(payload.get("keywords") or []),
    }


def build_summary_text(analysis: Dict[str, Any]) -> str:
    sections: List[str] = []
    headline = str(analysis.get("headline") or "").strip()
    overview = str(analysis.get("overview") or "").strip()

    if headline:
        sections.append(headline)
    if overview:
        sections.append("សេចក្តីសង្ខេប\n" + overview)

    mapping = [
        ("key_points", "ចំណុចសំខាន់ៗ"),
        ("decisions", "សេចក្តីសម្រេច"),
        ("action_items", "ការងារត្រូវអនុវត្ត"),
        ("next_steps", "ជំហានបន្ទាប់"),
        ("keywords", "ពាក្យគន្លឹះ"),
    ]
    for key, label in mapping:
        items = unique_string_list(analysis.get(key) or [])
        if items:
            sections.append(label + "\n- " + "\n- ".join(items))

    return "\n\n".join(section for section in sections if section.strip()).strip()


@lru_cache(maxsize=1)
def get_whisper_model() -> WhisperModel:
    logger.info(
        "Loading faster-whisper model=%s device=%s compute_type=%s",
        WHISPER_MODEL_NAME,
        WHISPER_DEVICE,
        WHISPER_COMPUTE_TYPE,
    )
    return WhisperModel(
        WHISPER_MODEL_NAME,
        device=WHISPER_DEVICE,
        compute_type=WHISPER_COMPUTE_TYPE,
    )


def ensure_command_exists(command: str) -> None:
    if os.path.isabs(command):
        if not os.path.exists(command):
            raise RuntimeError(
                "FFmpeg binary not found: " + command + ". "
                + (FFMPEG_MISSING_ERROR or "សូមដំឡើង FFmpeg មុនពេលប្រើប្រាស់។")
            )
        return
    if shutil.which(command) is None:
        raise RuntimeError(
            "FFmpeg command not found in PATH: " + command + ". "
            + (FFMPEG_MISSING_ERROR or "សូមដំឡើង FFmpeg មុនពេលប្រើប្រាស់។")
        )


def resolve_ffprobe_binary() -> str:
    if os.path.isabs(FFMPEG_BINARY):
        directory = os.path.dirname(FFMPEG_BINARY)
        candidate = os.path.join(directory, "ffprobe.exe" if os.name == "nt" else "ffprobe")
        if os.path.exists(candidate):
            return candidate
    fallback = "ffprobe.exe" if os.name == "nt" else "ffprobe"
    found = shutil.which(fallback)
    return found or fallback


def get_audio_duration_seconds(audio_path: str) -> float:
    ffprobe_binary = resolve_ffprobe_binary()
    if not os.path.isabs(ffprobe_binary) and shutil.which(ffprobe_binary) is None:
        return 0.0

    proc = subprocess.run(
        [
            ffprobe_binary,
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            audio_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        logger.warning("ffprobe could not read duration: %s", compact_error_text(proc.stderr or proc.stdout))
        return 0.0

    try:
        return max(0.0, float((proc.stdout or "").strip() or "0"))
    except Exception:
        return 0.0


def cleanup_temp_path(path: str) -> None:
    if not path:
        return
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def split_audio_into_chunks(input_path: str, chunk_seconds: int) -> Dict[str, Any]:
    ensure_command_exists(FFMPEG_BINARY)
    chunk_dir = tempfile.mkdtemp(prefix="meeting_chunks_")
    output_pattern = os.path.join(chunk_dir, "chunk_%03d.mp3")

    cmd = [
        FFMPEG_BINARY,
        "-y",
        "-i",
        input_path,
        "-vn",
        "-map",
        "0:a:0",
        "-ac",
        "1",
        "-ar",
        "16000",
        "-c:a",
        "libmp3lame",
        "-b:a",
        "32k",
        "-f",
        "segment",
        "-segment_time",
        str(max(300, chunk_seconds)),
        "-reset_timestamps",
        "1",
        output_pattern,
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=max(WORKER_REQUEST_TIMEOUT, 1800),
        check=False,
    )
    if proc.returncode != 0:
        cleanup_temp_path(chunk_dir)
        raise RuntimeError("FFmpeg audio chunking failed: " + compact_error_text(proc.stderr or proc.stdout))

    chunk_paths = sorted(
        os.path.join(chunk_dir, name)
        for name in os.listdir(chunk_dir)
        if name.lower().endswith(".mp3")
    )
    if not chunk_paths:
        cleanup_temp_path(chunk_dir)
        raise RuntimeError("Audio chunking produced no output files.")

    return {
        "dir": chunk_dir,
        "paths": chunk_paths,
    }


def split_text_batches(text: str, max_chars: int) -> List[str]:
    clean_text = str(text or "").replace("\r\n", "\n").strip()
    if not clean_text:
        return []

    max_chars = max(2000, max_chars)
    segments: List[str] = []
    for paragraph in clean_text.split("\n\n"):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        if len(paragraph) <= max_chars:
            segments.append(paragraph)
            continue

        start = 0
        while start < len(paragraph):
            end = min(len(paragraph), start + max_chars)
            if end < len(paragraph):
                split_at = paragraph.rfind(" ", start, end)
                if split_at <= start:
                    split_at = paragraph.rfind("\n", start, end)
                if split_at <= start:
                    split_at = end
            else:
                split_at = len(paragraph)
            piece = paragraph[start:split_at].strip()
            if piece:
                segments.append(piece)
            start = split_at

    batches: List[str] = []
    current_parts: List[str] = []
    current_length = 0
    for segment in segments:
        next_length = current_length + len(segment) + (2 if current_parts else 0)
        if current_parts and next_length > max_chars:
            batches.append("\n\n".join(current_parts).strip())
            current_parts = [segment]
            current_length = len(segment)
        else:
            current_parts.append(segment)
            current_length = next_length

    if current_parts:
        batches.append("\n\n".join(current_parts).strip())
    return batches


@app.on_event("startup")
def warm_worker() -> None:
    status = refresh_worker_ready_state(load_whisper=PRELOAD_WHISPER)
    logger.info(
        "Worker ready state ffmpeg_ok=%s whisper_ok=%s whisper_loaded=%s preload_whisper=%s",
        status.get("ffmpeg_ok"),
        status.get("whisper_ok"),
        status.get("whisper_loaded"),
        PRELOAD_WHISPER,
    )


def download_audio(audio_url: str) -> str:
    response = requests.get(audio_url, stream=True, timeout=(20, WORKER_REQUEST_TIMEOUT))
    response.raise_for_status()

    total_limit = MAX_DOWNLOAD_MB * 1024 * 1024
    temp_fd, temp_path = tempfile.mkstemp(prefix="meeting_audio_", suffix=".bin")
    os.close(temp_fd)

    downloaded = 0
    try:
        with open(temp_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > total_limit:
                    raise RuntimeError(f"Audio download exceeds worker limit of {MAX_DOWNLOAD_MB} MB.")
                handle.write(chunk)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise

    return temp_path


def convert_audio_for_whisper(input_path: str) -> str:
    ensure_command_exists(FFMPEG_BINARY)
    temp_fd, output_path = tempfile.mkstemp(prefix="meeting_audio_", suffix=".wav")
    os.close(temp_fd)
    os.unlink(output_path)

    cmd = [
        FFMPEG_BINARY,
        "-y",
        "-i",
        input_path,
        "-vn",
        "-map",
        "0:a:0",
        "-ac",
        "1",
        "-ar",
        "16000",
        output_path,
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=WORKER_REQUEST_TIMEOUT,
        check=False,
    )
    if proc.returncode != 0 or not os.path.exists(output_path):
        if os.path.exists(output_path):
            os.unlink(output_path)
        raise RuntimeError("FFmpeg conversion failed: " + compact_error_text(proc.stderr or proc.stdout))

    return output_path


def transcribe_audio(audio_path: str, language: str) -> str:
    model = get_whisper_model()
    segments, _info = model.transcribe(
        audio_path,
        language=language or None,
        beam_size=max(1, WHISPER_BEAM_SIZE),
        vad_filter=WHISPER_VAD_FILTER,
    )
    text_parts = [segment.text.strip() for segment in segments if str(segment.text or "").strip()]
    return "\n".join(text_parts).strip()


def summarize_with_ollama(topic: str, department: str, description: str, transcript_text: str) -> Dict[str, Any]:
    prompt = (
        "You are a meeting summarizer.\n"
        "Return only one valid JSON object with these keys exactly:\n"
        "headline, overview, key_points, decisions, action_items, next_steps, keywords.\n"
        "Rules:\n"
        "- All final values must be in Khmer.\n"
        "- key_points, decisions, action_items, next_steps, keywords must be arrays of strings.\n"
        "- overview should be concise and clear.\n"
        "- Do not include markdown fences or explanation outside JSON.\n\n"
        f"Topic: {topic or 'Not specified'}\n"
        f"Department: {department or 'Not specified'}\n"
        f"Context: {description or 'None'}\n\n"
        f"Transcript:\n{transcript_text.strip()}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "You create structured Khmer meeting notes and reply with JSON only.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "options": {
            "temperature": 0.2,
        },
    }

    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=(20, WORKER_REQUEST_TIMEOUT),
    )
    response.raise_for_status()
    data = response.json()
    content = str(((data.get("message") or {}).get("content")) or "").strip()
    parsed = extract_json_payload(content)
    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama did not return valid JSON. " + compact_error_text(content))
    return normalize_analysis(parsed, transcript_text)


PRODUCT_ANALYSIS_SYSTEM_PROMPT = (
    "អ្នកជាអ្នកជំនាញវិភាគផលិតផលកម្ពស់ជំនាន់ (World-class Product Analyst) ដែលអាចមើលរូបភាព និងអានស្លាកផលិតផលបានយ៉ាងច្បាស់លាស់។\n"
    "ការងាររបស់អ្នកគឺ៖\n"
    "  1. មើលរូបភាពផលិតផលឲ្យបានដិតដល់ គ្រប់ជ្រុងជ្រោយ (រូបខាងមុខ ខាងក្រោយ ស្លាក nutrition barcode ingredients លក្ខណៈវេចខ្ចប់)។\n"
    "  2. សរសេរតម្លៃឲ្យបានត្រឹមត្រូវគ្រប់ម៉ោង៖ ប្រសិនបើអ្នកមិនទាន់មើលឃើញ ឬមិនប្រាកដ សូមសរសេរ 'មិនបានរកឃើញ' ជាអក្សរតែមួយ៖ កុំធ្វើការប៉ាន់ស្មាន ឬបង្កើតទម្លាប់គ្មានមូលដ្ឋាន (hallucination) ឡើយ។\n"
    "  3. សូមកុំប្រើ placeholder ដូចជា 'step1' 'benefit1' '...' ឬទម្លាប់ដកស្រង់ពី template ទេ។ គ្រប់ទម្លាប់ដែលអ្នកសរសេរ ត្រូវតែជាខ្លឹមសារពិតប្រាកដដែលមកពីរូបភាព។\n"
    "  4. សូមប្រើភាសាខ្មែរ (ភាសាកម្ពុជា) សម្រាប់គ្រប់តម្លៃពណ៌នា។ បើនាមម៉ាក ឬឈ្មោះផលិតផលជាភាសាបរទេស អាចរក្សាភាសាដើមបាន។\n"
    "  5. ប្រទេសកំណើត ព្យាយាមប្រើប្រាស់ GS1 Barcode prefix (បើមាន barcode) ឬវេចខ្ចប់ដែលអាន 'Made in X' / 'ផលិតនៅ' កំណត់ឲ្យបានត្រឹមត្រូវ។\n"
    "  6. country_flag_emoji ត្រូវតែជា ១ emoji តែមួយ (ឧទាហរណ៍ 🇰🇭 សម្រាប់កម្ពុជា)។ បើមិនដឹង សូម '🌍' ជំនួស ហើយសុំកុំរាយច្រើន។\n"
    "  7. ingredients_summary ត្រូវតែជាប្រយោគខ្លីៗពីរបីពាក្យ៖ រាយធាតុផ្សំសំខាន់ៗដែលអ្នកអានបានពីស្លាក ជាភាសាខ្មែរ។\n"
    "  8. តម្លៃនីមួយៗមិនត្រូវជា empty string ទេ។ បើមិនដឹង សរសេរ 'មិនបានរកឃើញ' ជំនួសវិញ។\n"
    "តែងតែឆ្លើយជា JSON តែមួយ ពោលគឺ { } ទាំងមូល។ កុំបន្ថែមសំណេរ កុំរាយ <think> កុំប្រើ markdown fences។"
)

PRODUCT_ANALYSIS_DEFAULT_USER_PREFIX = (
    "សូមមើលរូបភាពផលិតផលនេះឲ្យបានដិតដល់ ហើយត្រឡប់ JSON object តែមួយជាមួយ keys ទាំងនេះ៖\n"
    "product_name, brand, country_of_origin, country_flag_emoji, category,\n"
    "usage (array 2-5 ធាតុ), benefits (array 2-5 ធាតុ), warnings (array 1-4 ធាតុ),\n"
    "ingredients_summary, price_range_usd, summary។\n"
    "ចងចាំ៖ បើកន្លែងណាមិនដឹង សរសេរ 'មិនបានរកឃើញ'។ កុំប្រើ template placeholder 'step1' ឬ '...' ទេ។"
)


def _product_analysis_is_placeholder(value: Any) -> bool:
    """Return True if a field looks like a template placeholder instead of real data."""
    if value is None:
        return True
    if isinstance(value, list):
        if not value:
            return True
        return any(_product_analysis_is_placeholder(x) for x in value)
    if not isinstance(value, str):
        return False
    s = value.strip()
    if s == "":
        return True
    low = s.lower()
    bad_prefixes = ("step", "benefit", "warning", "point", "example")
    for p in bad_prefixes:
        if low.startswith(p) and len(low) <= len(p) + 3:
            rem = low[len(p):]
            if rem.isdigit() or rem == "":
                return True
    if s in {"...", "…", "—", "-", "N/A", "n/a", "NA", "null", "Null", "None"}:
        return True
    if any(tok in low for tok in ("step1", "step 1", "step2", "step 2", "benefit1", "benefit 1", "warning1", "warning 1")):
        return True
    # Flag very generic literal copy-pastes
    if s in {
        "product name", "brand name", "product", "country", "origin country",
        "category", "usage", "benefits", "warnings", "summary",
    }:
        return True
    return False


def _product_analysis_result_quality(parsed: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Score 0..100 and list of placeholder issue strings."""
    required_keys = [
        "product_name", "brand", "country_of_origin", "country_flag_emoji",
        "category", "usage", "benefits", "warnings",
        "ingredients_summary", "price_range_usd", "summary",
    ]
    issues: List[str] = []
    for k in required_keys:
        if k not in parsed:
            issues.append(f"missing:{k}")
            continue
        v = parsed[k]
        if k in {"usage", "benefits", "warnings"}:
            if not isinstance(v, list):
                issues.append(f"not_list:{k}")
                continue
            if len(v) == 0:
                issues.append(f"empty_list:{k}")
            for idx, item in enumerate(v):
                if _product_analysis_is_placeholder(item):
                    issues.append(f"placeholder:{k}[{idx}]={str(item)[:30]}")
        else:
            if _product_analysis_is_placeholder(v):
                issues.append(f"placeholder:{k}={str(v)[:40]}")
    # Score: start at 100 subtract issues
    score = max(0, 100 - len(issues) * 9)
    # Bonus if product_name/brand are real
    if not _product_analysis_is_placeholder(parsed.get("product_name", "")):
        score += 3
    if not _product_analysis_is_placeholder(parsed.get("brand", "")):
        score += 2
    return min(100, score), issues


def analyze_product_with_ollama(request: ProductAnalysisRequest) -> str:
    raw_image = "".join((request.image_base64 or "").split())

    # Inject strong default prompts if caller provided weak/empty ones
    sys_prompt = (request.system_prompt or "").strip()
    if len(sys_prompt) < 120:
        sys_prompt = PRODUCT_ANALYSIS_SYSTEM_PROMPT

    user_prompt = (request.user_prompt or "").strip()
    if len(user_prompt) < 120 or "step1" in user_prompt.lower() or "benefit1" in user_prompt.lower():
        # Merge: keep any barcode/user context but add strong structure
        extra = ""
        if user_prompt:
            # try to keep anything with barcode / qr / extra context
            for kw in ("Barcode", "barcode", "QR", "qr", "បាកូដ", "ឧទាហរណ៍នៃ", "context:"):
                if kw in user_prompt:
                    extra = "\n\n" + user_prompt
                    break
        user_prompt = PRODUCT_ANALYSIS_DEFAULT_USER_PREFIX + extra

    message: Dict[str, Any] = {
        "role": "user",
        "content": user_prompt,
    }
    if raw_image:
        message["images"] = [raw_image]

    last_content = ""
    last_issues: List[str] = []
    best_content = ""
    best_score = -1

    for attempt in range(3):
        extra_sys = ""
        extra_user = ""
        if attempt == 1 and last_issues:
            extra_sys = (
                " ការព្យាយាមមុនរបស់អ្នកមានបញ្ហា៖ " + "; ".join(last_issues[:6]) +
                "។ សូមអានរូបភាពឡើងវិញយ៉ាងដិតដល់ កុំប្រើ placeholder ទៀត។ បើមិនចេះ សរសេរ 'មិនបានរកឃើញ' ប៉ុណ្ណោះ។"
            )
        if attempt == 2:
            extra_user = (
                "\n\n[ការព្រមានចុងក្រោយ: លទ្ធផលមុនមាន placeholder ច្រើនពេក។ "
                "សូមព្យាយាមម្តងទៀត៖ អានរូបភាពដិតដល់ ប្រើប្រាស់ភាសាខ្មែរ ហើយតម្លៃណាមិនដឹង សរសេរ 'មិនបានរកឃើញ'។]"
            )

        payload = {
            "model": OLLAMA_VISION_MODEL,
            "stream": False,
            "format": "json",
            "messages": [
                {
                    "role": "system",
                    "content": sys_prompt + extra_sys,
                },
                {
                    **message,
                    "content": user_prompt + extra_user,
                },
            ],
            "options": {
                "temperature": 0.05 if attempt == 0 else (0.08 if attempt == 1 else 0.0),
                "top_p": 0.9,
                "num_predict": 700,
            },
        }
        try:
            response = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json=payload,
                timeout=(20, WORKER_REQUEST_TIMEOUT),
            )
            response.raise_for_status()
        except Exception as exc:
            if attempt < 2:
                logger.warning("Ollama vision call failed (attempt %d): %s; retrying...", attempt + 1, compact_error_text(exc))
                time.sleep(1.0)
                continue
            raise RuntimeError(f"Ollama request failed: {compact_error_text(exc)}") from exc

        data = response.json()
        content = str(((data.get("message") or {}).get("content")) or "").strip()
        if not content:
            if attempt < 2:
                time.sleep(0.5)
                continue
            raise RuntimeError("Ollama returned an empty product analysis after retries.")
        last_content = content

        # Try to parse and score quality; if already good, return early
        parsed = extract_json_payload(content)
        if isinstance(parsed, dict):
            score, issues = _product_analysis_result_quality(parsed)
            if score > best_score:
                best_score = score
                best_content = content
            last_issues = issues
            if score >= 82 and not any(i.startswith("placeholder:") for i in issues[:3]):
                logger.info("Product analysis passed quality check: score=%d issues=%d", score, len(issues))
                return content
            if attempt < 2:
                logger.info("Retrying product analysis (attempt=%d score=%d issues=%d)", attempt + 1, score, len(issues))
                time.sleep(0.2)
                continue
        else:
            # Bad JSON — prefer valid json
            if best_content == "":
                best_content = content
            if attempt < 2:
                time.sleep(0.2)
                continue

    return best_content or last_content


def summarize_transcript_hierarchically(
    topic: str,
    department: str,
    description: str,
    transcript_text: str,
    progress_callback: Optional[Callable[[str], None]] = None,
    depth: int = 0,
) -> Dict[str, Any]:
    batches = split_text_batches(transcript_text, SUMMARY_BATCH_MAX_CHARS)
    if len(batches) <= 1:
        if progress_callback:
            progress_callback("កំពុងបង្កើតសេចក្តីសង្ខេបចុងក្រោយ...")
        return summarize_with_ollama(topic, department, description, transcript_text)

    if depth >= max(1, SUMMARY_RECURSION_LIMIT):
        merged_text = "\n\n".join(
            f"[Summary Batch {idx + 1}/{len(batches)}]\n{batch}"
            for idx, batch in enumerate(batches)
        )
        if progress_callback:
            progress_callback("កំពុងបញ្ចូល partial summaries ជាចុងក្រោយ...")
        return summarize_with_ollama(
            topic,
            department,
            description + "\nThese inputs already contain condensed batch summaries. Merge them carefully.",
            merged_text,
        )

    partial_summaries: List[str] = []
    total_batches = len(batches)
    for index, batch in enumerate(batches, start=1):
        if progress_callback:
            progress_callback(f"កំពុងសង្ខេបខ្លឹមសារផ្នែក {index}/{total_batches}...")
        batch_analysis = summarize_with_ollama(
            topic,
            department,
            description + f"\nThis is section {index}/{total_batches} of a long meeting transcript.",
            batch,
        )
        partial_summaries.append(build_summary_text(batch_analysis))

    merged_text = "\n\n".join(
        f"[Partial Summary {idx + 1}/{len(partial_summaries)}]\n{summary}"
        for idx, summary in enumerate(partial_summaries)
        if summary.strip()
    ).strip()
    if not merged_text:
        raise RuntimeError("Partial meeting summaries were empty.")

    return summarize_transcript_hierarchically(
        topic,
        department,
        description + "\nThe following content contains partial meeting summaries. Merge them into one final summary.",
        merged_text,
        progress_callback=progress_callback,
        depth=depth + 1,
    )


def transcribe_audio_source(
    source_path: str,
    language: str,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    cleanup_paths: List[str] = []
    duration_seconds = get_audio_duration_seconds(source_path)
    file_size_mb = 0.0
    try:
        file_size_mb = os.path.getsize(source_path) / (1024 * 1024)
    except OSError:
        file_size_mb = 0.0

    chunk_seconds = max(300, AUDIO_CHUNK_MINUTES * 60)
    should_chunk = duration_seconds > (chunk_seconds * 1.2) or file_size_mb >= max(8, AUDIO_CHUNK_THRESHOLD_MB)

    if not should_chunk:
        try:
            transcript_text = transcribe_audio(source_path, language)
            return {
                "text": transcript_text,
                "chunk_count": 1,
                "duration_seconds": duration_seconds,
                "cleanup_paths": cleanup_paths,
            }
        except Exception as direct_exc:
            logger.warning(
                "Direct transcription failed, retrying with ffmpeg conversion: %s",
                compact_error_text(direct_exc),
            )
            wav_path = convert_audio_for_whisper(source_path)
            cleanup_paths.append(wav_path)
            transcript_text = transcribe_audio(wav_path, language)
            return {
                "text": transcript_text,
                "chunk_count": 1,
                "duration_seconds": duration_seconds,
                "cleanup_paths": cleanup_paths,
            }

    if progress_callback:
        progress_callback("កំពុងបំបែកសំឡេងវែងជាផ្នែកតូចៗ...")
    chunk_bundle = split_audio_into_chunks(source_path, chunk_seconds)
    cleanup_paths.append(chunk_bundle["dir"])
    chunk_paths = list(chunk_bundle.get("paths") or [])
    if not chunk_paths:
        raise RuntimeError("Audio chunking produced no chunks to transcribe.")

    transcript_parts: List[str] = []
    total_chunks = len(chunk_paths)
    for index, chunk_path in enumerate(chunk_paths, start=1):
        if progress_callback:
            progress_callback(f"កំពុងបម្លែងសំឡេងផ្នែក {index}/{total_chunks}...")
        chunk_text = transcribe_audio(chunk_path, language).strip()
        if chunk_text:
            transcript_parts.append(f"[Part {index}/{total_chunks}]\n{chunk_text}")

    transcript_text = "\n\n".join(transcript_parts).strip()
    return {
        "text": transcript_text,
        "chunk_count": total_chunks,
        "duration_seconds": duration_seconds,
        "cleanup_paths": cleanup_paths,
    }


def build_meeting_summary_response(
    request: MeetingSummaryRequest,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    if not WORKER_READY.get("ffmpeg_ok", False):
        refresh_worker_ready_state(load_whisper=False)

    if not WORKER_READY.get("ffmpeg_ok", False):
        raise HTTPException(status_code=503, detail=WORKER_READY.get("ffmpeg_error") or "FFmpeg is not ready.")

    cleanup_paths: List[str] = []
    transcript_text = request.transcript_text.strip()
    transcription_meta: Dict[str, Any] = {
        "chunk_count": 1,
        "duration_seconds": 0.0,
    }

    try:
        if not transcript_text:
            if not request.audio_url.strip():
                raise HTTPException(status_code=400, detail="audio_url or transcript_text is required.")

            if progress_callback:
                progress_callback("កំពុងទាញយកសំឡេងពី server...")
            source_path = download_audio(request.audio_url.strip())
            cleanup_paths.append(source_path)
            refresh_worker_ready_state(load_whisper=True)
            if not WORKER_READY.get("whisper_ok", False):
                raise HTTPException(status_code=503, detail=WORKER_READY.get("whisper_error") or "Whisper model is not ready.")
            transcription_result = transcribe_audio_source(
                source_path,
                request.language.strip() or "km",
                progress_callback=progress_callback,
            )
            transcript_text = str(transcription_result.get("text") or "").strip()
            cleanup_paths.extend(list(transcription_result.get("cleanup_paths") or []))
            transcription_meta["chunk_count"] = int(transcription_result.get("chunk_count") or 1)
            transcription_meta["duration_seconds"] = float(transcription_result.get("duration_seconds") or 0.0)

        if not transcript_text:
            raise HTTPException(status_code=422, detail="Transcription result was empty.")

        if progress_callback:
            chunk_count = int(transcription_meta.get("chunk_count") or 1)
            if chunk_count > 1:
                progress_callback(f"បានបម្លែងសំឡេងរួច {chunk_count} ផ្នែក។ កំពុងសង្ខេបជាលំដាប់...")
            else:
                progress_callback("កំពុងសង្ខេប transcript...")

        analysis = summarize_transcript_hierarchically(
            request.topic.strip(),
            request.department.strip(),
            request.description.strip(),
            transcript_text,
            progress_callback=progress_callback,
        )
        summary_text = build_summary_text(analysis)

        return {
            "success": True,
            "summary": summary_text,
            "analysis": analysis,
            "transcript": transcript_text,
            "transcript_provider": "local-worker",
            "transcript_model": f"faster-whisper:{WHISPER_MODEL_NAME}",
            "summary_provider": "local-worker",
            "summary_model": f"ollama:{OLLAMA_MODEL}",
            "transcript_chunk_count": int(transcription_meta.get("chunk_count") or 1),
            "audio_duration_seconds": float(transcription_meta.get("duration_seconds") or 0.0),
        }
    except HTTPException:
        raise
    except requests.HTTPError as exc:
        detail = ""
        try:
            detail = compact_error_text(exc.response.text)
        except Exception:
            detail = compact_error_text(exc)
        raise HTTPException(status_code=502, detail=detail or "Upstream AI request failed.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="FFmpeg conversion timed out.")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=compact_error_text(exc))
    finally:
        for path in cleanup_paths:
            cleanup_temp_path(path)


def run_worker_job(job_id: str, request: "MeetingSummaryRequest") -> None:
    def report_progress(message: str) -> None:
        try:
            update_worker_job(job_id, status="running", message=message)
        except KeyError:
            pass

    try:
        update_worker_job(job_id, status="running", started_at=time.time(), message="កំពុងរៀបចំការសង្ខេប...")
        result = build_meeting_summary_response(request, progress_callback=report_progress)
        update_worker_job(
            job_id,
            status="completed",
            success=True,
            result=result,
            finished_at=time.time(),
            message="ការសង្ខេបដោយ AI បានរួចរាល់។",
        )
    except HTTPException as exc:
        update_worker_job(
            job_id,
            status="failed",
            success=False,
            result=None,
            finished_at=time.time(),
            message=str(exc.detail or ("HTTP " + str(exc.status_code))),
            status_code=exc.status_code,
        )
    except Exception as exc:
        logger.exception("Async worker job failed: %s", exc)
        update_worker_job(
            job_id,
            status="failed",
            success=False,
            result=None,
            finished_at=time.time(),
            message=compact_error_text(exc),
            status_code=500,
        )


def run_product_analysis_job(job_id: str, request: "ProductAnalysisRequest") -> None:
    try:
        update_worker_job(
            job_id,
            status="running",
            started_at=time.time(),
            message="កំពុងផ្ញើរូបភាពទៅកាន់ Local AI...",
        )
        content = analyze_product_with_ollama(request)
        result = {
            "success": True,
            "provider": "local-worker",
            "model": f"ollama:{OLLAMA_VISION_MODEL}",
            "content": content,
        }
        update_worker_job(
            job_id,
            status="completed",
            success=True,
            result=result,
            finished_at=time.time(),
            message="ការវិភាគផលិតផលដោយ AI បានរួចរាល់។",
        )
    except HTTPException as exc:
        update_worker_job(
            job_id,
            status="failed",
            success=False,
            result=None,
            finished_at=time.time(),
            message=str(exc.detail or ("HTTP " + str(exc.status_code))),
            status_code=exc.status_code,
        )
    except Exception as exc:
        logger.exception("Product analysis async job failed: %s", exc)
        update_worker_job(
            job_id,
            status="failed",
            success=False,
            result=None,
            finished_at=time.time(),
            message=compact_error_text(exc),
            status_code=500,
        )


@app.get("/health")
def health() -> Dict[str, Any]:
    ollama_ok = True
    ollama_error = ""
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=(10, 20))
        response.raise_for_status()
    except Exception as exc:  # pragma: no cover
        ollama_ok = False
        ollama_error = compact_error_text(exc)

    status = refresh_worker_ready_state(load_whisper=False)

    return {
        "ok": True,
        "worker": APP_TITLE,
        "version": APP_VERSION,
        "whisper_model": WHISPER_MODEL_NAME,
        "ffmpeg_binary": FFMPEG_BINARY,
        "ffmpeg_ok": status.get("ffmpeg_ok", False),
        "ffmpeg_error": status.get("ffmpeg_error", ""),
        "ffmpeg_install_steps": status.get("ffmpeg_install_steps", FFMPEG_INSTALL_STEPS),
        "whisper_ok": status.get("whisper_ok", False),
        "whisper_error": status.get("whisper_error", ""),
        "whisper_loaded": status.get("whisper_loaded", False),
        "preload_whisper": PRELOAD_WHISPER,
        "audio_chunk_minutes": AUDIO_CHUNK_MINUTES,
        "audio_chunk_threshold_mb": AUDIO_CHUNK_THRESHOLD_MB,
        "summary_batch_max_chars": SUMMARY_BATCH_MAX_CHARS,
        "ollama_model": OLLAMA_MODEL,
        "ollama_ok": ollama_ok,
        "ollama_error": ollama_error,
    }


@app.post("/summarize-meeting")
def summarize_meeting(
    request: MeetingSummaryRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_token(authorization)
    return build_meeting_summary_response(request)


@app.post("/analyze-product")
def analyze_product(
    request: ProductAnalysisRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_token(authorization)
    return {
        "success": True,
        "provider": "local-worker",
        "model": f"ollama:{OLLAMA_VISION_MODEL}",
        "content": analyze_product_with_ollama(request),
    }


@app.post("/analyze-product-async")
def analyze_product_async(
    request: ProductAnalysisRequest,
    authorization: Optional[str] = Header(default=None),
) -> JSONResponse:
    require_token(authorization)
    job = create_worker_job(request)
    thread = threading.Thread(
        target=run_product_analysis_job, args=(job["job_id"], request), daemon=True
    )
    thread.start()
    return JSONResponse(
        status_code=202,
        content={
            "success": True,
            "job_id": job["job_id"],
            "status": "queued",
            "message": "Product analysis job started.",
        },
    )


@app.post("/summarize-meeting-async")
def summarize_meeting_async(
    request: MeetingSummaryRequest,
    authorization: Optional[str] = Header(default=None),
) -> JSONResponse:
    require_token(authorization)
    job = create_worker_job(request)
    thread = threading.Thread(target=run_worker_job, args=(job["job_id"], request), daemon=True)
    thread.start()
    return JSONResponse(
        status_code=202,
        content={
            "success": True,
            "job_id": job["job_id"],
            "status": "queued",
            "message": "Meeting summary job started.",
        },
    )


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    require_token(authorization)
    prune_worker_jobs()
    job = get_worker_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Worker job not found.")

    payload = {
        "success": bool(job.get("success", True)),
        "job_id": job.get("job_id"),
        "status": job.get("status", "queued"),
        "message": str(job.get("message") or ""),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }
    if job.get("status") == "completed" and isinstance(job.get("result"), dict):
        payload["result"] = job.get("result")
    if job.get("status") == "failed":
        payload["status_code"] = int(job.get("status_code") or 500)
    return payload
