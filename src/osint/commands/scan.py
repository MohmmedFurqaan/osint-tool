import typer
import asyncio
import os
import json
from src.osint.validators.url_validator import validate_and_normalize
from src.osint.core.scanner_manager import ScannerManager

app = typer.Typer(help="OSINT Scanner CLI commands", add_completion=False)

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
    
    # WHOIS Info
    typer.secho("--- WHOIS Data ---", fg=typer.colors.CYAN, bold=True)
    whois_reg = result.whois_data.get('registrar', 'N/A')
    whois_created = result.whois_data.get('creation_date', 'N/A')
    whois_expires = result.whois_data.get('expiration_date', 'N/A')
    typer.echo(f"  Registrar: {whois_reg}")
    typer.echo(f"  Created:   {whois_created}")
    typer.echo(f"  Expires:   {whois_expires}")
    
    # DNS Info
    typer.secho("\n--- DNS Records ---", fg=typer.colors.CYAN, bold=True)
    a_records = ', '.join(result.dns_data.get('A', [])) or 'N/A'
    mx_records = ', '.join(result.dns_data.get('MX', [])) or 'N/A'
    txt_records = ', '.join(result.dns_data.get('TXT', [])) or 'N/A'
    typer.echo(f"  A Records:   {a_records}")
    typer.echo(f"  MX Records:  {mx_records}")
    typer.echo(f"  TXT Records: {txt_records}")
    
    # SSL Info
    typer.secho("\n--- SSL Certificate ---", fg=typer.colors.CYAN, bold=True)
    ssl_issuer = result.ssl_data.get('issuer', 'N/A')
    ssl_expires = result.ssl_data.get('expires', 'N/A')
    typer.echo(f"  Issuer:  {ssl_issuer}")
    typer.echo(f"  Expires: {ssl_expires}")
    
    # Headers & Tech
    typer.secho("\n--- HTTP Headers & Technology ---", fg=typer.colors.CYAN, bold=True)
    if "error" in result.headers_data:
        typer.secho(f"  Headers Error: {result.headers_data['error']}", fg=typer.colors.YELLOW)
    else:
        for k, v in result.headers_data.items():
            typer.echo(f"  {k}: {v}")
    techs = ', '.join(result.technology_data) or 'None detected'
    typer.echo(f"  Technologies: {techs}")
    
    # Shodan Info
    typer.secho("\n--- Shodan Data ---", fg=typer.colors.CYAN, bold=True)
    shodan = result.shodan_data
    if "error" in shodan:
        typer.secho(f"  Shodan Error: {shodan['error']}", fg=typer.colors.YELLOW)
    else:
        ports = shodan.get('ports', [])
        os_info = shodan.get('os', 'Unknown')
        org_info = shodan.get('org', 'Unknown')
        hostnames = ', '.join(shodan.get('hostnames', [])) or 'None'
        typer.echo(f"  IP:        {shodan.get('ip', 'N/A')}")
        typer.echo(f"  OS:        {os_info}")
        typer.echo(f"  Org:       {org_info}")
        typer.echo(f"  Hostnames: {hostnames}")
        typer.echo(f"  Ports:     {ports if ports else 'None detected'}")
        
    # Geolocation & ASN Info
    typer.secho("\n--- Geolocation & ASN ---", fg=typer.colors.CYAN, bold=True)
    geo = result.geo_data
    if "error" in geo:
        typer.secho(f"  Geo Error: {geo['error']}", fg=typer.colors.YELLOW)
    elif geo:
        typer.echo(f"  IP:      {geo.get('query', 'N/A')}")
        typer.echo(f"  Country: {geo.get('country', 'N/A')}")
        typer.echo(f"  City:    {geo.get('city', 'N/A')}")
        typer.echo(f"  ISP:     {geo.get('isp', 'N/A')}")
        typer.echo(f"  Org:     {geo.get('org', 'N/A')}")
        typer.echo(f"  ASN:     {geo.get('as', 'N/A')}")
    else:
        typer.echo("  No geolocation data found.")
        
    # Wayback Machine Info
    typer.secho("\n--- Wayback Machine ---", fg=typer.colors.CYAN, bold=True)
    wayback = result.wayback_data
    if "error" in wayback:
        typer.secho(f"  Wayback Error: {wayback['error']}", fg=typer.colors.YELLOW)
    elif wayback:
        first_seen = wayback.get('first_seen', 'N/A')
        if first_seen != 'N/A' and len(first_seen) >= 8:
            first_seen = f"{first_seen[:4]}-{first_seen[4:6]}-{first_seen[6:8]}"
        typer.echo(f"  First Archived: {first_seen}")
        typer.echo(f"  Archive URL:    {wayback.get('archive_url', 'N/A')}")
    else:
        typer.echo("  No Wayback Machine data found.")
        
    # Subdomains
    typer.secho("\n--- Subdomains (crt.sh) ---", fg=typer.colors.CYAN, bold=True)
    if result.subdomains:
        limit = min(15, len(result.subdomains))
        for sub in result.subdomains[:limit]:
            typer.echo(f"  - {sub}")
        if len(result.subdomains) > limit:
            typer.echo(f"  ... and {len(result.subdomains) - limit} more")
    else:
        typer.echo("  No subdomains found.")
        
    # API Endpoints
    typer.secho("\n--- Discovered API Endpoints ---", fg=typer.colors.CYAN, bold=True)
    if result.api_endpoints:
        limit = min(15, len(result.api_endpoints))
        for api in result.api_endpoints[:limit]:
            typer.echo(f"  - {api}")
        if len(result.api_endpoints) > limit:
            typer.echo(f"  ... and {len(result.api_endpoints) - limit} more")
    else:
        typer.echo("  No API endpoints found.")
        
    # Risk Findings
    if result.risk_findings:
        typer.secho("\n[!] Risk Findings:", fg=typer.colors.RED, bold=True)
        for r in result.risk_findings:
            color = typer.colors.RED if hasattr(r.severity, 'value') and r.severity.value == "High" else typer.colors.YELLOW
            severity_val = r.severity.value if hasattr(r.severity, 'value') else str(r.severity)
            typer.secho(f" - [{severity_val.upper()}] {r.title}: {r.description}", fg=color)
    else:
        typer.secho("\n[✔] No significant risks found.", fg=typer.colors.GREEN, bold=True)
            
    if report:
        report_out = os.path.join(os.getcwd(), "data", "output", f"{target.domain}_info.json")
        os.makedirs(os.path.dirname(report_out), exist_ok=True)
        with open(report_out, 'w', encoding='utf-8') as f:
            # Pydantic v2 dump
            json.dump(result.model_dump_report(), f, indent=4)
        typer.secho(f"\n✔ Report generated successfully: {report_out}", fg=typer.colors.GREEN, bold=True)
