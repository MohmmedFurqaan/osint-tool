import typer
import asyncio
import os
import json
from src.osint.validators.url_validator import validate_and_normalize
from src.osint.core.scanner_manager import ScannerManager

app = typer.Typer(help="OSINT Scanner CLI commands")

@app.command("scan")
def scan_command(
    url: str = typer.Argument(..., help="URL or domain to scan"),
    report: bool = typer.Option(False, "--report", "-r", help="Generate JSON report")
):
    typer.secho("-" * 55, fg=typer.colors.CYAN)
    typer.secho("OSINT SCANNER (Async)", fg=typer.colors.CYAN, bold=True)
    typer.secho("-" * 55, fg=typer.colors.CYAN)
    
    try:
        target = validate_and_normalize(url)
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
        
    typer.secho(f"✔ valid URL: {target.url}", fg=typer.colors.GREEN)
    typer.echo(f"Domain name: {target.domain}")
    typer.echo("")
    
    # Run async manager
    manager = ScannerManager(target)
    
    with typer.progressbar(length=100, label="Running Async Reconnaissance...") as progress:
        # In a real app we might update progress differently, but this is a simple wrapper
        result = asyncio.run(manager.run_all())
        progress.update(100)
        
    typer.secho("\n[+] Reconnaissance Complete!\n", fg=typer.colors.GREEN, bold=True)
    
    whois_reg = result.whois_data.get('registrar', 'N/A')
    typer.echo(f"WHOIS Registrar: {whois_reg}")
    
    a_records = ', '.join(result.dns_data.get('A', []))
    typer.echo(f"DNS A Records: {a_records}")
    
    ssl_issuer = result.ssl_data.get('issuer', 'N/A')
    typer.echo(f"SSL Issuer: {ssl_issuer}")
    
    shodan = result.shodan_data
    if "error" in shodan:
        typer.secho(f"Shodan: {shodan['error']}", fg=typer.colors.YELLOW)
    else:
        typer.echo(f"Shodan IP: {shodan.get('ip', 'N/A')} | Ports: {shodan.get('ports', [])}")
        
    if result.risk_findings:
        typer.secho("\n[!] Risk Findings:", fg=typer.colors.RED, bold=True)
        for r in result.risk_findings:
            color = typer.colors.RED if r.severity.value == "High" else typer.colors.YELLOW
            typer.secho(f" - [{r.severity.value.upper()}] {r.title}: {r.description}", fg=color)
            
    if report:
        report_out = os.path.join(os.getcwd(), "data", "output", f"{target.domain}_info.json")
        os.makedirs(os.path.dirname(report_out), exist_ok=True)
        with open(report_out, 'w', encoding='utf-8') as f:
            # Pydantic v2 dump
            json.dump(result.model_dump_report(), f, indent=4)
        typer.secho(f"\n✔ Report generated successfully: {report_out}", fg=typer.colors.GREEN, bold=True)
