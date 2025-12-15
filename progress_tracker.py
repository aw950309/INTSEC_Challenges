import time
from Spinner import Spinner

class ProgressTracker:
    """Tracks and prints counting progress at timed intervals (1s, then every 10s)."""

    def __init__(self, total: int):
        self.start_time = time.time()
        self.next_print_time = 1.0
        self.total = total
        self.spinner = Spinner("")  # No message, just dots
        self.spinner.start()

    def update(self, i: int) -> None:
        elapsed = time.time() - self.start_time
        if elapsed >= self.next_print_time:
            self.spinner.stop()
            label = "second" if self.next_print_time == 1.0 else "seconds"
            print(f"{int(self.next_print_time)} {label}: {i+1}/{self.total} checked")
            if self.next_print_time == 1.0:
                self.next_print_time = 10.0
            else:
                self.next_print_time += 10.0
            self.spinner.start()

    def finish(self) -> float:
        """Returns total elapsed time and prints completion message."""
        self.spinner.stop()
        total_time = time.time() - self.start_time
        avg_speed = self.total / total_time if total_time > 0 else 0
        print(f"\nCompleted in {total_time:.2f} seconds ({avg_speed:.1f} iterations/sec)")
        return total_time




    # if i % 500 == 0:
    #     elapsed = time.time() - start_time
    #     speed = i / elapsed if elapsed > 0 else 0
    #     print(f"Progress: {i}/4096 checked | {elapsed:.1f}s elapsed")