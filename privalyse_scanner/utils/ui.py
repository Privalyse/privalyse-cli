"""
User Interface Utilities (Rich)
===============================
Handles all terminal output using the Rich library for a modern,
professional CLI experience.
"""

from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.syntax import Syntax
from rich import box

from ..models.finding import Finding

# Shared console instance
console = Console()

def print_banner():
    """Print the Privalyse banner"""
    title = Text("🔒 Privalyse Scanner", style="bold cyan")
    subtitle = Text("Privacy & GDPR Compliance Intelligence", style="italic white")
    
    console.print(Panel(
        Text.assemble(title, "\n", subtitle),
        box=box.ROUNDED,
        border_style="cyan",
        expand=False
    ))
    console.print()

def create_progress() -> Progress:
    """Create a standard progress bar"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )

def print_info(msg: str):
    console.print(f"[blue]ℹ️[/blue]  {msg}")

def print_success(msg: str):
    console.print(f"[green]✅[/green] {msg}")

def print_warning(msg: str):
    console.print(f"[yellow]⚠️[/yellow] {msg}")

def print_error(msg: str):
    console.print(f"[red]❌[/red] {msg}")

def print_findings_summary(findings: List[Finding], score_data: Dict[str, Any]):
    """Print a summary table of findings"""
    
    # Score Panel
    score = score_data.get('score', 0)
    status = score_data.get('status', 'unknown')
    
    color = "green"
    if score < 60: color = "red"
    elif score < 80: color = "yellow"
    
    score_text = Text(f"{score}/100", style=f"bold {color}")
    console.print(Panel(
        Text.assemble("Compliance Score: ", score_text, f" ({status})"),
        title="Scan Results",
        border_style=color
    ))
    
    # Findings Table
    table = Table(title="Findings Summary", box=box.SIMPLE)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Description")
    
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for f in findings:
        sev = str(f.severity).lower()
        if sev in counts:
            counts[sev] += 1
            
    table.add_row("[red]CRITICAL[/red]", str(counts['critical']), "Immediate action required")
    table.add_row("[orange1]HIGH[/orange1]", str(counts['high']), "Significant privacy risk")
    table.add_row("[yellow]MEDIUM[/yellow]", str(counts['medium']), "Compliance warning")
    table.add_row("[blue]LOW[/blue]", str(counts['low']), "Best practice suggestion")
    
    console.print(table)

def print_flow_tree(finding: Finding, graph: Any):
    """
    Visualize a data flow finding as a tree.
    This replaces the ASCII visualizer with Rich Tree.
    """
    if not finding.flow_path:
        return

    # Root: The Finding Rule
    severity_color = "red" if finding.severity in ["critical", "high"] else "yellow"
    root_label = Text(f"[{finding.severity.upper()}] {finding.rule}", style=f"bold {severity_color}")
    tree = Tree(root_label)
    
    # Build the path
    # flow_path is a list of node IDs or labels
    # We want to show: Source -> Transform -> Sink
    
    current_node = tree
    
    for i, step in enumerate(finding.flow_path):
        # Determine icon and style based on step type (heuristic)
        icon = "⬇️"
        style = "white"
        
        if i == 0:
            icon = "🟢" # Source
            style = "green"
        elif i == len(finding.flow_path) - 1:
            icon = "🔴" # Sink
            style = "red"
        else:
            icon = "🔄" # Transform
            style = "yellow"
            
        label = Text(f"{icon} {step}", style=style)
        current_node = current_node.add(label)
        
    console.print(tree)
    console.print()
