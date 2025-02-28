import os
import hashlib
import subprocess
import binascii
import json  # Import json for parsing metadata
from openpyxl import Workbook

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
ORIGINAL_FOLDER = r"C:\Users\althe\Downloads\File\File"  # <-- Change to your path
OUTPUT_EXCEL = "File_Analysis.xlsx"
EXIFTOOL_PATH = r"C:\Windows\System32\exiftool\exiftool.exe"  # <-- Adjust the path as necessary

# ---------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------

def compute_sha256(file_path):
    """Compute the SHA256 hash of the file in a memory-efficient manner."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_magic_number(file_path, num_bytes=16):
    """
    Read the first 'num_bytes' from the file to identify magic number.
    Returns (offset_hex, magic_hex, magic_ascii).
    """
    offset_hex = "0x0"  # Typically the file signature is at offset 0
    with open(file_path, "rb") as f:
        data = f.read(num_bytes)
    magic_hex = binascii.hexlify(data).upper().decode("utf-8")
    magic_ascii = ''.join([chr(x) if 32 <= x < 127 else '.' for x in data])
    return offset_hex, magic_hex, magic_ascii

def get_exif_metadata(file_path):
    """
    Use exiftool to extract metadata in JSON format and return a dictionary.
    """
    try:
        command = [EXIFTOOL_PATH, '-json', file_path]
        metadata_output = subprocess.check_output(command, universal_newlines=True)
        metadata_list = json.loads(metadata_output)
        return metadata_list[0] if metadata_list else {}
    except subprocess.CalledProcessError as e:
        return {"error": f"Command failed: {e.cmd}, exit status: {e.returncode}, output: {e.output}"}
    except Exception as e:
        return {"error": f"Metadata extraction failed: {str(e)}"}

def main():
    results = []
    original_files = os.listdir(ORIGINAL_FOLDER)
    original_files.sort()  # Optional: sort for consistent ordering

    for filename in original_files:
        original_path = os.path.join(ORIGINAL_FOLDER, filename)
        if not os.path.isfile(original_path):
            continue  # Skip directories

        file_sha = compute_sha256(original_path)
        offset_hex, magic_hex, magic_ascii = get_magic_number(original_path)
        metadata = get_exif_metadata(original_path)

        results.append({
            "filename": filename,
            "sha256": file_sha,
            "magic_offset": offset_hex,
            "magic_hex": magic_hex,
            "magic_ascii": magic_ascii,
            "metadata": metadata
        })

    create_excel(results)
    print(f"Finished! Excel file saved as: {OUTPUT_EXCEL}")

def create_excel(results):
    wb = Workbook()
    ws = wb.active
    ws.title = "Original File Analysis"

    if results:
        headers = ["Filename", "SHA256", "Magic Offset (Hex)", "Magic Bytes (Hex)", "Magic ASCII"] + list(results[0]['metadata'].keys())
        ws.append(headers)
        for row in results:
            data = [
                row["filename"],
                row["sha256"],
                row["magic_offset"],
                row["magic_hex"],
                row["magic_ascii"]
            ] + [row['metadata'].get(key, '') for key in headers[5:]]  # Append metadata dynamically
            ws.append(data)
    else:
        ws.append(["No results to display"])

    wb.save(OUTPUT_EXCEL)

if __name__ == "__main__":
    main()
