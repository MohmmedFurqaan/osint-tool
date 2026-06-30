import typer
from dotenv import load_dotenv
from src.osint.commands.scan import app as scan_app

load_dotenv()

app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(scan_app, name="osint")

if __name__ == "__main__":
    # Flatten the command so we can just run `python main.py scan` directly
    # or `python main.py osint scan` depending on how typer merges them.
    # We will just run the scan_app directly for simplicity.
    scan_app()