""""Challenge 3.3 (Normal): Benchmark hash computation speeds.

Computes 10,000 hashes with MD5, SHA-1, SHA-256, and Argon2id.
Calculates how many attempts could be made in a month.

Author: Alex Wagner
Version: 1.0.
Date: 2025-12-12.
"""
import hashlib
import os
import time
from Spinner import Spinner
from prettytable import PrettyTable


# Try to import Argon2. If not installed, do that...
try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("⚠️ argon2-cffi not installed. Run: pip install argon2-cffi")


NUM_HASHES = 10_000
SECONDS_PER_MONTH = 30 * 24 * 60 * 60  # ~2.6 million seconds
#Helper function.
def format_large_number(num):
    """Convert a large number to readable text like '6.99 trillion'.

    Makes the output easier to understand than scientific notation.
    """
    if num >= 1_000_000_000_000_000:  # Quadrillion.
        return f"{num / 1_000_000_000_000_000:.2f}  quadrillion"
    elif num >= 1_000_000_000_000:  # Trillion.
        return f"{num / 1_000_000_000_000:.2f} trillion"
    elif num >= 1_000_000_000:  # Billion.
        return f"{num / 1_000_000_000:.2f} billion"
    elif num >= 1_000_000:  # Million.
        return f"{num / 1_000_000:.2f} million"
    elif num >= 1_000:  # Thousand.
        return f"{num / 1_000:.2f} thousand"
    else:
        return f"{num:.0f}"

def format_time(seconds):
    """Format time dynamically - seconds for short, min:sec for long."""
    if seconds < 60:
        return f"{seconds:.4f}s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"

def benchmark_hash(name, hash_func, num_iterations=NUM_HASHES):
    """Benchmark a hash function and return hashes per second.

  Creates random data, hashes it many times, and measures how long it takes.
  Then calculates how many hashes you could do in a whole month.
  """
    # os.urandom(16) generates 16 random bytes. We make a list of them.
    random_data = [os.urandom(16) for _ in range(num_iterations)]

    spinner = Spinner(f"Benchmarking {name}") #This is so cool! It shows a spinner while benchmarking. See Spinner.py for implementation.
    spinner.start()
    # time.perf_counter() gives precise timing for benchmarks.
    start = time.perf_counter()
    for data in random_data:
        hash_func(data) # Hash each piece of random data.
    elapsed = time.perf_counter() - start

    # Calculate speed and extrapolate to a month.
    hashes_per_sec = num_iterations / elapsed
    per_month = hashes_per_sec * SECONDS_PER_MONTH

    spinner.stop() # Stop the spinner after benchmarking.
    # Format the per_month as readable text instead of scientific notation.
    per_month_text = format_large_number(per_month)

    time_text = format_time(elapsed)  # Dynamic formatting

    return [name, format_time(elapsed), f"{hashes_per_sec:,.0f}", format_large_number(per_month)]

def format_time(seconds):
    """Format time dynamically - seconds for short, min:sec for long."""
    if seconds < 60:
        return f"{seconds:.4f}s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"

def main():
    table = PrettyTable()
    table.field_names = ["Algorithm", "Time", "Speed (H/s)", "Per Month"]
    table.align["Algorithm"] = "l"
    table.align["Time"] = "r"
    table.align["Speed (H/s)"] = "r"
    table.align["Per Month"] = "r"

    print("🔬 Hash Benchmark (10,000 iterations)")

    results = []

    # Lambda creates a small inline function. d is the input data.
    # hashlib.md5(d).hexdigest() hashes d and returns the hex string.
    results.append(benchmark_hash("MD5", lambda d: hashlib.md5(d).hexdigest()))
    results.append(benchmark_hash("SHA-1", lambda d: hashlib.sha1(d).hexdigest()))
    results.append(benchmark_hash("SHA-256", lambda d: hashlib.sha256(d).hexdigest()))

    if ARGON2_AVAILABLE:
        ph = PasswordHasher() # Argon2 uses a hasher object.
        # Argon2 needs a string, so we decode bytes to string with latin-1.
        # Only 100 iterations because Argon2 is intentionally slow (security feature).
        results.append(benchmark_hash("Argon2id",
                    lambda d: ph.hash(d.decode('latin-1', errors='ignore')),
                    num_iterations=100)) # Argon2 is SLOW, use fewer iterations while testing with magic numbers.!
    for row in results:
        table.add_row(row)
    print(table)
    print("Note: No GPU used (CPU only)")

if __name__ == "__main__":
    main()