from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable
from textual.reactive import reactive
from textual.containers import Vertical
from rich.table import Table
from time import sleep

class VolDashboard(App):
    CSS_PATH = None
    BINDINGS = [("q", "quit", "Quit App")]

    def __init__(self, executor, **kwargs):
        super().__init__(**kwargs)
        self.executor = executor
        self.table = None

    def compose(self) -> ComposeResult:
        yield Header()
        self.table = DataTable()
        yield self.table
        yield Footer()

    def on_mount(self):
        self.table.add_columns("Plugin", "Status", "Progress", "Memory (MB)", "CPU (%)")
        self.status_queue = self.executor.execute_with_status()
        self.set_interval(0.5, self.update_status)

    def update_status(self):
        while not self.status_queue.empty():
            status = self.status_queue.get_nowait()
            self.table.add_row(
                status.name,
                status.status,
                f"{status.progress:.0%}",
                f"{status.memory_used_mb:.2f}",
                f"{status.cpu_used_percent:.2f}"
            )

def run_dashboard(executor):
    VolDashboard(executor).run()
