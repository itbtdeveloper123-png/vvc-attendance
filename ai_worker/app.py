import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional

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
FFMPEG_BINARY = os.getenv("FFMPEG_BINARY", "ffmpeg").strip() or "ffmpeg"
WORKER_REQUEST_TIMEOUT = int(os.getenv("WORKER_REQUEST_TIMEOUT", "600") or "600")
MAX_DOWNLOAD_MB = int(os.getenv("MAX_DOWNLOAD_MB", "512") or "512")
PRELOAD_WHISPER = os.getenv("PRELOAD_WHISPER", "0").strip() in {"1", "true", "True", "yes", "on"}
WORKER_JOB_TTL_SECONDS = int(os.getenv("WORKER_JOB_TTL_SECONDS", "3600") or "3600")
AUDIO_CHUNK_MINUTES = int(os.getenv("AUDIO_CHUNK_MINUTES", "15") or "15")
AUDIO_CHUNK_THRESHOLD_MB = int(os.getenv("AUDIO_CHUNK_THRESHOLD_MB", "48") or "48")
SUMMARY_BATCH_MAX_CHARS = int(os.getenv("SUMMARY_BATCH_MAX_CHARS", "12000") or "12000")
SUMMARY_RECURSION_LIMIT = int(os.getenv("SUMMARY_RECURSION_LIMIT", "4") or "4")

WORKER_READY: Dict[str, Any] = {
    "ffmpeg_ok": False,
    "ffmpeg_error": "",
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

    try:
        decoded = json.loads(text)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None

    candidate = text[start : end + 1]
    try:
        decoded = json.loads(candidate)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        return None
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
            raise RuntimeError(f"FFmpeg binary not found: {command}")
        return
    if shutil.which(command) is None:
        raise RuntimeError(f"FFmpeg command not found in PATH: {command}")


def resolve_ffprobe_binary() -> str:
    if os.path.isabs(FFMPEG_BINARY):
        directory = os.path.dirname(FFMPEG_BINARY)
        candidate = os.path.join(directory, "ffprobe.exe" if os.name == "nt" else "ffprobe")
        if os.path.exists(candidate):
            return candidate
    return "ffprobe.exe" if os.name == "nt" else "ffprobe"


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


def analyze_product_with_ollama(request: ProductAnalysisRequest) -> str:
    message: Dict[str, Any] = {
        "role": "user",
        "content": request.user_prompt.strip(),
    }
    clean_image = "".join((request.image_base64 or "").split())
    if clean_image:
        message["images"] = [clean_image]

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system",
                "content": request.system_prompt.strip()
                or "You analyze products and return valid JSON only.",
            },
            message,
        ],
        "options": {
            "temperature": 0.1,
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
    if not content:
        raise RuntimeError("Ollama returned an empty product analysis.")
    return content


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
        "model": f"ollama:{OLLAMA_MODEL}",
        "content": analyze_product_with_ollama(request),
    }


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
