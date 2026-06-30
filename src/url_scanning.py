import typer

cli = typer.Typer()

@cli.command()
def url_scan(url: str):
    """Scan the URL for OSINT information."""
    typer.echo(f"Scanning {url}")

if __name__ == "__main__":
    cli()