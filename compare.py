import os
import hashlib
import subprocess
import binascii
import json
from openpyxl import Workbook

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
ORIGINAL_FOLDER = r"C:\Users\althe\Downloads\File\File"   # Change to your path
RECOVERED_FOLDER = r"C:\Users\althe\Downloads\RecoveredFiles\Recovery_20250228_173330" # Change to your path
OUTPUT_EXCEL = "File_Header_Analysis.xlsx"
EXIFTOOL_PATH = r"C:\Windows\System32\exiftool\exiftool.exe"  # Adjust as necessary

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

def get_magic_number(file_path):
    """Extracts the magic number, its offset, and ASCII representation."""
    with open(file_path, "rb") as file:
        header = file.read(16)  # Read the first 16 bytes for the magic number
    magic_hex = binascii.hexlify(header).upper().decode("utf-8")
    magic_ascii = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in header])
    return "0x0", magic_hex, magic_ascii  # Magic number typically at offset 0

def get_metadata(file_path):
    """Uses ExifTool to extract file metadata."""
    try:
        result = subprocess.check_output([EXIFTOOL_PATH, '-json', file_path], universal_newlines=True)
        return json.loads(result)[0]  # Assuming one file's metadata is returned
    except Exception as e:
        return {"error": str(e)}

def analyze_files(folder_path):
    """Analyzes all files in a given folder, storing data in a dictionary indexed by SHA256."""
    files_data = {}
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            sha256 = compute_sha256(file_path)
            offset, magic_hex, magic_ascii = get_magic_number(file_path)
            metadata = get_metadata(file_path)
            files_data[sha256] = {
                "filename": filename,
                "sha256": sha256,
                "magic_offset": offset,
                "magic_hex": magic_hex,
                "magic_ascii": magic_ascii,
                "metadata": metadata
            }
    return files_data

def create_excel(original_files, recovered_files):
    """Creates an Excel file containing File Header / Magic Number details and SHA256 comparisons."""
    wb = Workbook()
    ws = wb.active
    ws.title = "File Header Analysis"

    # Headers
    headers = [
        "Filename (Original)", "Filename (Recovered)",
        "Original SHA256", "Recovered SHA256", "SHA256 Match",
        "Magic Offset", "Magic Hex", "Magic ASCII", "Magic Match",
        "Metadata Match"
    ]
    ws.append(headers)

    all_sha256s = set(original_files.keys()).union(recovered_files.keys())

    for sha256 in sorted(all_sha256s):
        orig_data = original_files.get(sha256, None)
        rec_data = recovered_files.get(sha256, None)

        orig_filename = orig_data["filename"] if orig_data else "Not Found"
        rec_filename = rec_data["filename"] if rec_data else "Not Found"
        sha256_match = "Match" if orig_data and rec_data else "No Match"
        
        magic_offset = orig_data["magic_offset"] if orig_data else rec_data["magic_offset"]
        magic_hex = orig_data["magic_hex"] if orig_data else rec_data["magic_hex"]
        magic_ascii = orig_data["magic_ascii"] if orig_data else rec_data["magic_ascii"]
        magic_match = "Match" if orig_data and rec_data and orig_data["magic_hex"] == rec_data["magic_hex"] else "Mismatch"

        metadata_match = "Match" if orig_data and rec_data and orig_data["metadata"] == rec_data["metadata"] else "Mismatch"

        ws.append([
            orig_filename, rec_filename,
            orig_data["sha256"] if orig_data else "N/A",
            rec_data["sha256"] if rec_data else "N/A",
            sha256_match,
            magic_offset, magic_hex, magic_ascii, magic_match,
            metadata_match
        ])

    wb.save(OUTPUT_EXCEL)
    print(f"Finished! Excel file saved as: {OUTPUT_EXCEL}")

def main():
    """Main function to analyze files and generate the XLSX report."""
    original_files_data = analyze_files(ORIGINAL_FOLDER)
    recovered_files_data = analyze_files(RECOVERED_FOLDER)

    create_excel(original_files_data, recovered_files_data)

if __name__ == "__main__":
    main()
