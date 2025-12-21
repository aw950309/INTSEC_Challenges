"""
Challenge 5.1 (Normal): Checking binaries
Write a short script that takes two directories as input.
For each files in one directory, check that there is another file of the same name in the other directory.
Compute a checksum for each files, and compare.

Author: Alex Wagner.
Version: 1.2.
Date: 2025-12-21.

Verified it is working with this, one file is supposed to be missing in the second directory:

python3 5.1.py "/Users/alexwagner/Downloads/Zootopia.2016.2160p.UHD.BluRay.x265-TERMiNAL copy"
"/Users/alexwagner/Downloads/Zzootopia.2016.2160p.UHD.BluRay.x265-TERMiNAL"

Output:
 [OK] .DS_Store
[MISSING] RARBG.txt not found in /Users/alexwagner/Downloads/Zzootopia.2016.2160p.UHD.BluRay.x265-TERMiNAL
[OK] Sample/bad_undersized.zootopia.2016.2160p.uhd.bluray.x265-terminal.sample.mkv
[OK] Sample/zootopia.2016.2160p.uhd.bluray.x265-terminal.sample.mkv
[OK] Zootopia.2016.2160p.UHD.BluRay.x265-TERMiNAL.mkv
[OK] zootopia.2016.2160p.uhd.bluray.x265-terminal.nfo


"""
#!/usr/bin/env python3
#python 5.1.py ~/test_dir1 ~/test_dir2   <-- Example usage
import os
import sys
import hashlib
import time

def compute_checksum(path: str, algo: str = "sha256") -> str:
    """Compute the checksum of a file."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def get_files_in_directory(directory: str) -> dict:
    """Return a dict of {relative_path: absolute_path} for all files recursively."""
    # I CHANGED TO  OS.WALK TO MAKE IT SO IT CAN CHEC SUBDIRECTORIES AS WELL.
    files = {}
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, directory)
            files[rel_path] = abs_path
    return files

#Helper function to compare directory.
def compare_file(rel_path: str, path1: str, path2: str) -> tuple[str, str]:
    """Compare checksums of a file in two directories."""
    c1 = compute_checksum(path1)
    c2 = compute_checksum(path2)

    if c1 == c2:
        return "OK", f"[OK] {rel_path}"
    else:
        return "MISMATCH", f"[MISMATCH] {rel_path}"


def compare_directories(files1: dict, files2: dict, dir1: str, dir2: str) -> list[tuple[str, str, str]]:
    """Compare files between two directories."""
    results = []

    for rel_path in sorted(files1.keys()):
        if rel_path not in files2:
            results.append((rel_path, "MISSING", f"[MISSING] {rel_path} not found in {dir2}"))
            continue
        status, message = compare_file(rel_path, files1[rel_path], files2[rel_path])
        results.append((rel_path, status, message))

    for rel_path in sorted(set(files2.keys()) - set(files1.keys())):
        results.append((rel_path, "MISSING", f"[MISSING] {rel_path} not found in {dir1}"))

    return results


def parse_arguments() -> tuple[str, str]:
    """Parse and validate command-line arguments."""
    if len(sys.argv) != 3:
        print("Usage: python 5.1.py <dir1> <dir2>")
        sys.exit(1)
    return sys.argv[1], sys.argv[2]


def main() -> None:
    # Step 1: Parse command-line arguments to get both directory paths.
    dir1, dir2 = parse_arguments()

    # Step 2: Get list of files from both directories.
    files1 = get_files_in_directory(dir1)
    files2 = get_files_in_directory(dir2)

    # Step 3: Compare files in both directories and get results.
    results = compare_directories(files1, files2, dir1, dir2)

    # Step 4: Print all results.
    for filename, status, message in results:
        print(message)


if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"\nProgram ran: {elapsed_time:.2f} seconds")