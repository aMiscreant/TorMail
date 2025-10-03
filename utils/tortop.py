import curses
import psutil
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Directory monitoring event handler
class DirectoryMonitor(FileSystemEventHandler):
    def __init__(self, stdscr, directories):
        self.stdscr = stdscr
        self.directories = directories
        self.activity = {directory: 0 for directory in directories}  # Track activity count per directory
        self.changes = {directory: [] for directory in directories}  # Track file changes per directory

    def on_any_event(self, event):
        if not event.is_directory:
            for directory in self.directories:
                if event.src_path.startswith(directory):
                    # Log the change type and file path
                    change_type = event.event_type  # 'modified', 'created', etc.
                    self.activity[directory] += 1
                    self.changes[directory].append(f"{change_type.capitalize()}: {event.src_path}")

def draw_graph(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    height, width = stdscr.getmaxyx()

    # Start color support
    curses.start_color()
    # Initialize color pairs
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Default color pair
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)  # Red color for high activity
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Yellow color for system stats
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Green for low activity
    curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Cyan for new file change types

    # Setup directory monitoring
    directories = [os.path.expanduser("~/.icebridge"), "/etc/tor", "~/.tormail_keys", "/var/log"]
    event_handler = DirectoryMonitor(stdscr, directories)
    observer = Observer()
    for directory in directories:
        observer.schedule(event_handler, directory, recursive=True)
    observer.start()

    try:
        while True:
            stdscr.clear()

            # Fetch system data (CPU usage, memory, disk)
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # Get available CPU, Memory, Disk information
            cpu_usage = f"CPU: {cpu_percent:.1f}%"
            memory_usage = f"RAM: {memory.percent:.1f}%"
            disk_usage = f"Disk: {disk.percent:.1f}%"

            # Draw the system resource usage like htop
            stdscr.addstr(0, 0, f"{cpu_usage:<20}", curses.color_pair(3))
            stdscr.addstr(1, 0, f"{memory_usage:<20}", curses.color_pair(3))
            stdscr.addstr(2, 0, f"{disk_usage:<20}", curses.color_pair(3))

            # Draw the CPU usage graph with dynamic colors
            bar_width = int(cpu_percent / 100 * width)
            if cpu_percent < 30:
                color_pair = curses.color_pair(4)  # Green for low CPU usage
            elif cpu_percent < 70:
                color_pair = curses.color_pair(3)  # Yellow for medium CPU usage
            else:
                color_pair = curses.color_pair(2)  # Red for high CPU usage
            stdscr.addstr(3, 0, "#" * bar_width, color_pair)

            # Display directory activity with real-time changes
            current_line = 5  # Start line for directory monitoring below resource stats
            for i, directory in enumerate(directories):
                # Determine if there's activity in the directory
                activity_count = event_handler.activity[directory]
                if activity_count > 10:
                    # High activity directory highlighted
                    color_pair = curses.color_pair(2)  # Red for high activity
                elif activity_count > 0:
                    # Normal activity, green
                    color_pair = curses.color_pair(4)  # Green for normal activity
                else:
                    # No activity, default color
                    color_pair = curses.color_pair(1)

                # Display directory and activity count in real-time
                stdscr.addstr(current_line, 0, f"{directory}: ", color_pair)
                stdscr.addstr(current_line, len(f"{directory}: "), f"{activity_count}", color_pair)
                current_line += 1

                # Display file changes in the directory
                changes = event_handler.changes[directory]
                if changes:
                    for change in changes[-5:]:  # Show only last 5 changes to prevent excessive output
                        change_type = change.split(":")[0]
                        if change_type == "Opened":
                            change_color = curses.color_pair(5)  # Cyan for opened files
                        else:
                            change_color = curses.color_pair(3)  # Yellow for other types of changes

                        stdscr.addstr(current_line, 0, f"  {change}", change_color)
                        current_line += 1

            stdscr.refresh()
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    curses.wrapper(draw_graph)
