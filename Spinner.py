import threading
import sys
import time

class Spinner:
    """Animated spinner that shows the program is working."""

    def __init__(self, message="Calculating"):
        self.message = message
        self.running = False
        self.thread = None

    def _animate(self):
        dots = 0
        max_dots = 20
        while self.running:
            # Build the display: message + dots + padding
            display = f"\r{self.message}{'.' * dots}{' ' * (max_dots - dots)}"
            sys.stdout.write(display)
            sys.stdout.flush()
            dots = (dots + 1) % (max_dots + 1)
            time.sleep(0.1)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        # Clear the spinner line
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        sys.stdout.flush()
