import os
import sys
import zipfile
import shutil

def fix_ipa(input_path, output_path=None):
    if not os.path.isfile(input_path):
        print(f"Error: File not found: {input_path}")
        return False

    if output_path is None:
        base, ext = os.path.splitext(input_path)
        output_path = f"{base}_fixed{ext}"

    print(f"Reading: {input_path}")
    print(f"Repackaging for Sideloadly compatibility -> {output_path}...")

    fixed_count = 0
    with zipfile.ZipFile(input_path, 'r') as zin:
        with zipfile.ZipFile(output_path, 'w') as zout:
            for item in zin.infolist():
                buffer = zin.read(item.filename)
                # Store all Info.plist uncompressed (ZIP_STORED) to fix Sideloadly 0.70+ bug
                if item.filename.endswith('Info.plist'):
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, buffer)
                    fixed_count += 1
                else:
                    zout.writestr(item, buffer)

    print(f"Successfully fixed {fixed_count} Info.plist entries (stored uncompressed)!")
    print(f"Output saved to: {output_path}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_ipa_sideloadly.py <path-to-ipa-file>")
        sys.exit(1)
    fix_ipa(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
