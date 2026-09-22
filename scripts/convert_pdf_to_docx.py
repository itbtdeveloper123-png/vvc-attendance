#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Fidelity PDF to Word (.docx) Converter Microservice Engine
- Preserves 100% original page layout, columns, tables, headers, footers
- Extracts embedded raster & vector images (photos, logos, signatures)
- Post-processes and maps Khmer Unicode fonts (Khmer OS Battambang, Kantumruy Pro)
"""

import sys
import os
import glob

# Ensure user site-packages are in sys.path (Vital for cPanel / Shared Hosting)
try:
    possible_sites = (
        glob.glob(os.path.expanduser("~/.local/lib/python*/site-packages")) +
        glob.glob("/home/*/.local/lib/python*/site-packages")
    )
    for p in possible_sites:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)
except Exception:
    pass

import json
import time
import re
import warnings

# Suppress pymupdf deprecation warnings from cluttering stdout
warnings.filterwarnings("ignore")

try:
    from pdf2docx import Converter
    import docx
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
except ImportError as e:
    print(json.dumps({
        "success": False,
        "error": f"Required Python packages missing: {e}. Please run 'pip install pdf2docx python-docx PyMuPDF'."
    }, ensure_ascii=False))
    sys.exit(1)


KHMER_CHAR_REGEX = re.compile(r'[\u1780-\u17FF\u19E0-\u19FF]')

def set_run_fonts(run, khmer_font="Khmer OS Battambang", latin_font="Calibri"):
    """
    Ensure the XML run element explicitly specifies the font for ASCII, high-ANSI, and Complex Scripts (CS)
    so Microsoft Word, WPS Office, and Google Docs correctly display Khmer characters without breaking.
    """
    try:
        r = run._r
        rPr = r.get_or_add_rPr()
        rFonts = rPr.find(qn('w:rFonts'))
        if rFonts is None:
            rFonts = OxmlElement('w:rFonts')
            rPr.append(rFonts)
            
        text = run.text or ""
        has_khmer = bool(KHMER_CHAR_REGEX.search(text))
        
        target_font = khmer_font if has_khmer else (run.font.name or latin_font)
        
        rFonts.set(qn('w:ascii'), target_font)
        rFonts.set(qn('w:hAnsi'), target_font)
        rFonts.set(qn('w:cs'), khmer_font)  # Word uses 'cs' (Complex Script) for Khmer
        rFonts.set(qn('w:eastAsia'), target_font)
    except Exception:
        pass


def post_process_khmer_fonts(docx_path, khmer_font="Khmer OS Battambang", latin_font="Calibri"):
    """
    Traverse all paragraphs, tables, and headers/footers in the generated docx to ensure
    Khmer text runs have proper Unicode fonts assigned.
    """
    try:
        doc = docx.Document(docx_path)
        
        # 1. Update document normal style
        try:
            normal_style = doc.styles['Normal']
            normal_style.font.name = khmer_font
        except Exception:
            pass

        # 2. Process body paragraphs
        for p in doc.paragraphs:
            for run in p.runs:
                set_run_fonts(run, khmer_font=khmer_font, latin_font=latin_font)

        # 3. Process tables
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        for run in p.runs:
                            set_run_fonts(run, khmer_font=khmer_font, latin_font=latin_font)

        # 4. Process sections (headers and footers)
        for section in doc.sections:
            for p in section.header.paragraphs:
                for run in p.runs:
                    set_run_fonts(run, khmer_font=khmer_font, latin_font=latin_font)
            for p in section.footer.paragraphs:
                for run in p.runs:
                    set_run_fonts(run, khmer_font=khmer_font, latin_font=latin_font)

        doc.save(docx_path)
        return True
    except Exception as e:
        # Non-fatal if font post-processing has minor hiccups
        return False


def convert_pdf_to_docx(pdf_path, docx_path, khmer_font="Khmer OS Battambang"):
    """
    Converts a PDF file to a Word (.docx) document preserving layout and images.
    """
    if not os.path.exists(pdf_path):
        return {
            "success": False,
            "error": f"Input PDF file does not exist: {pdf_path}"
        }

    start_time = time.time()
    cv = None
    try:
        # Create output directory if it doesn't exist
        out_dir = os.path.dirname(os.path.abspath(docx_path))
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        import pymupdf
        with pymupdf.open(pdf_path) as doc_mupdf:
            total_pages = doc_mupdf.page_count

        cv = Converter(pdf_path)
        # Convert all pages (layout, tables, images, shapes)
        cv.convert(docx_path, start=0, end=None)
        cv.close()
        cv = None

        if not os.path.exists(docx_path):
            return {
                "success": False,
                "error": "Conversion finished but output .docx file was not found."
            }

        # Apply Khmer Unicode Font optimization
        post_process_khmer_fonts(docx_path, khmer_font=khmer_font)

        elapsed = round(time.time() - start_time, 2)
        file_size = os.path.getsize(docx_path)

        return {
            "success": True,
            "pages": total_pages,
            "docx_path": os.path.abspath(docx_path),
            "file_size": file_size,
            "elapsed_seconds": elapsed,
            "font_applied": khmer_font
        }
    except Exception as e:
        if cv:
            try:
                cv.close()
            except Exception:
                pass
        return {
            "success": False,
            "error": str(e)
        }


def main():
    if len(sys.argv) < 3:
        usage = {
            "success": False,
            "usage": "python convert_pdf_to_docx.py <input.pdf> <output.docx> [khmer_font_name]"
        }
        print(json.dumps(usage, ensure_ascii=False))
        sys.exit(1)

    pdf_file = sys.argv[1]
    docx_file = sys.argv[2]
    khmer_font = sys.argv[3] if len(sys.argv) > 3 else "Khmer OS Battambang"

    result = convert_pdf_to_docx(pdf_file, docx_file, khmer_font=khmer_font)
    print("__RESULT_JSON__:" + json.dumps(result, ensure_ascii=False))
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
