import typer
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.console import Console
from rich import print as rprint
from typing import Optional
import time

app = typer.Typer(help="Purple Scaffold - AI Red/Purple Team Framework")
console = Console()

@app.command("attack")
def run_attack(
    attack_type: str = typer.Argument("all", help="Attack type: all, mcp, advanced, recursive"),
    seed: int = typer.Option(42, help="Random seed for reproducibility"),
    model: str = typer.Option("anthropic.claude-3-5-sonnet-20241022-v2:0", help="Model ID to test against")
):
    """Run attacks with rich progress bars."""
    rprint(f"[bold blue]Starting {attack_type} attack suite with seed {seed}[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        # Main task
        main_task = progress.add_task(f"Running {attack_type.upper()} attacks...", total=100)

        # Simulate attack steps with realistic progress
        for i in range(100):
            time.sleep(0.03)  # Simulate work
            progress.advance(main_task, 1)
            
            if i % 20 == 0:
                progress.console.print(f"  → Completed step {i//10 + 1}/10")

    rprint("[bold green]✓ Attack suite completed successfully![/bold green]")

if __name__ == "__main__":
    app()
