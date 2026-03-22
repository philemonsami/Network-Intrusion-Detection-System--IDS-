from rich.console import Console
from rich.table import Table
from rich.live import Live
import time
from datetime import datetime

class Dashboard:
    def __init__(self):
        self.console = Console()
        self.events = []
        self.table = self._generate_table()

    def _generate_table(self):
        table = Table(show_header=True, header_style="bold magenta", title="Live IDS Events Feed")
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("Source IP", justify="left")
        table.add_column("Threat Type", justify="center")
        table.add_column("Severity", justify="center")
        
        for event in self.events[-15:]:
            dt = datetime.fromtimestamp(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            severity = event.get('severity', 'LOW')
            if severity == "CRITICAL":
                severity_str = f"[bold red]{severity}[/bold red]"
            elif severity == "HIGH":
                severity_str = f"[red]{severity}[/red]"
            elif severity == "MEDIUM":
                severity_str = f"[yellow]{severity}[/yellow]"
            else:
                severity_str = f"[cyan]{severity}[/cyan]"
                
            table.add_row(dt, str(event.get('src_ip')), str(event.get('threat_type')), severity_str)
            
        return table

    def add_event(self, event):
        self.events.append(event)
        
    def run(self):
        with Live(self._generate_table(), refresh_per_second=2, console=self.console) as live:
            try:
                while True:
                    live.update(self._generate_table())
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass
