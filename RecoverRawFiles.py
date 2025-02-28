import hashlib
import os
import shutil
import zipfile
from datetime import datetime

# Constants for paths and magic numbers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_DIR = os.path.join(BASE_DIR, "File")
RECOVERY_DIR = os.path.join(BASE_DIR, "RecoveredFiles", f"Recovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

# Ensure recovery directory exists
os.makedirs(RECOVERY_DIR, exist_ok=True)

MAGIC_NUMBERS = {
    b'\xFF\xD8\xFF': 'jpg',
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
    b'\x42\x4D': 'bmp',
    b'\x49\x49\x2A\x00': 'tiff',
    b'\x4D\x4D\x00\x2A': 'tiff',
    b'\x25\x50\x44\x46': 'pdf',
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'ppt',
    b'\x50\x4B\x03\x04': 'zip',
    b'\x52\x61\x72\x21\x1A\x07\x00': 'rar',
    b'\x37\x7A\xBC\xAF\x27\x1C': '7z',
    b'\x1F\x8B\x08': 'gz',
    b'\x75\x73\x74\x61\x72': 'tar',
    b'\x4D\x5A': 'pe',  # Identifying PE files, not distinguishing EXE/DLL yet
    b'\x7F\x45\x4C\x46': 'elf',
    b'\x49\x44\x33': 'mp3',
    b'\xFF\xFB': 'mp3',
    b'\x00\x00\x00\x20\x66\x74\x79\x70\x69\x73\x6F\x6D': 'mp4',
    b'\x52\x49\x46\x46': 'avi',
    b'\x00\x00\x01\xBA': 'mpg',
    b'\x66\x74\x79\x70\x71\x74\x20': 'mov',
    b'\x57\x41\x56\x45': 'wav',
}

# Helper functions
def compute_sha256(filepath):
    """ Calculate SHA256 hash of the file. """
    hash_sha256 = hashlib.sha256()
    with open(filepath, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def check_zip_contents(filepath):
    """ Determine specific type of ZIP file (e.g., docx, xlsx, pptx), including handling for corrupted ZIPs. """
    try:
        with zipfile.ZipFile(filepath, 'r') as zipf:
            names = zipf.namelist()
            if any(name.startswith("word/") for name in names):
                return 'docx'
            elif any(name.startswith("xl/") for name in names):
                return 'xlsx'
            elif any(name.startswith("ppt/") for name in names):
                return 'pptx'
    except zipfile.BadZipFile:
        # Even if the ZIP is corrupted, we attempt to guess if it's likely an Office file based on typical file extensions
        with open(filepath, 'rb') as file:
            content = file.read()
            if b"word/" in content:
                return 'docx'
            elif b"xl/" in content:
                return 'xlsx'
            elif b"ppt/" in content:
                return 'pptx'
        return 'corrupt_zip'
    return 'zip'

def detect_file_type(filepath):
    """ Detect file type based on magic number. """
    with open(filepath, 'rb') as file:
        header = file.read(max(len(x) for x in MAGIC_NUMBERS))
        for magic, filetype in MAGIC_NUMBERS.items():
            if header.startswith(magic):
                if filetype == 'zip':
                    return check_zip_contents(filepath)
                elif filetype == 'pe':
                    return check_pe_type(filepath)
                return filetype
    return 'unknown'

def check_pe_type(filepath):
    """ Check if a file is a PE file (EXE or DLL). """
    with open(filepath, 'rb') as f:
        f.seek(0x3C)  # Offset for PE header location pointer
        pe_offset = int.from_bytes(f.read(4), 'little')
        f.seek(pe_offset)
        if f.read(4) == b'PE\x00\x00':
            f.seek(pe_offset + 4)
            machine_type = f.read(2)
            if machine_type in [b'\x4c\x01', b'\x64\x86']:  # Checks for common machine types (x86, x64)
                f.seek(pe_offset + 22)  # Offset for characteristics
                characteristics = int.from_bytes(f.read(2), 'little')
                if characteristics & 0x2000:
                    return 'dll'
                return 'exe'
    return 'unknown'

def recover_files():
    """ Process and recover files based on file type detection. """
    if not os.path.exists(FILE_DIR):
        print(f"Directory not found: {FILE_DIR}")
        return []

    recovered_files = []
    for root, dirs, files in os.walk(FILE_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            filetype = detect_file_type(filepath)
            dest_path = os.path.join(RECOVERY_DIR, f"{os.path.basename(file)}.{filetype}")
            shutil.copy2(filepath, dest_path)
            recovered_files.append(dest_path)
            print(f"Recovered: {file} as {filetype}")
    print(f"Recovery completed: {len(recovered_files)} files recovered to {RECOVERY_DIR}")
    return recovered_files

if __name__ == "__main__":
    recover_files()
