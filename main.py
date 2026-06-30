import typer
import validators
from urllib.parse import urlparse
import time
import os
import json
import datetime
from src.recon import get_whois, get_dns, get_ssl, get_headers, get_shodan, generate_json

app = typer.Typer(add_completion=False, no_args_is_help=True)

@app.command()
def scan(url: str = typer.Argument(..., help="URL to scan"), report: bool = typer.Option(False, "--report", "-r", help="Generate JSON report")):
    typer.secho("-" * 55, fg=typer.colors.CYAN)
    typer.secho("OSINT SCANNER", fg=typer.colors.CYAN, bold=True)
    typer.secho("-" * 55, fg=typer.colors.CYAN)
    typer.echo("")
    
    if url.startswith("https:https:"):
        url = url.replace("https:https:", "https://")
    elif url.startswith("http:http:"):
        url = url.replace("http:http:", "http://")
    
    if url.startswith("https:") and not url.startswith("https://"):
        url = url.replace("https:", "https://", 1)
    elif url.startswith("http:") and not url.startswith("http://"):
        url = url.replace("http:", "http://", 1)
    
    if not url.startswith("http"):
        url = f"https://{url}"
    
    if not validators.url(url):
        typer.secho("Error: Invalid URL format", fg=typer.colors.RED)
        raise typer.Exit(1)
    
    typer.echo("")
    
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    scheme = parsed.scheme if parsed.scheme else "N/A"
    
    typer.secho("✔ valid URL", fg=typer.colors.GREEN)
    typer.secho("✔ performing lookup", fg=typer.colors.GREEN)
    typer.echo("")
    
    time.sleep(0.5)
    
    typer.secho("Gathered info", fg=typer.colors.BLUE, bold=True)
    typer.echo(f"Domain name: {domain}")
    typer.echo(f"Scheme: {scheme}")
    typer.echo("")
    
    report_out = os.path.join(os.getcwd(), "data", "output", f"{domain}_info.json")
    today_date = str(datetime.date.today())
    
    cached_data = None
    if os.path.exists(report_out):
        try:
            with open(report_out, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
                gen_date = existing_data.get("generated_at", "").split("T")[0]
                if gen_date == today_date:
                    cached_data = existing_data
        except Exception:
            pass

    if cached_data:
        typer.secho(f"[*] Found cached data for {domain} from today. Skipping API calls...", fg=typer.colors.MAGENTA)
        whois_data = cached_data.get("whois", {})
        dns_data = cached_data.get("dns", {})
        ssl_data = cached_data.get("ssl", {})
        headers_data = cached_data.get("headers", {})
        shodan_data = cached_data.get("shodan", {})
    else:
        with typer.progressbar(length=100, label="Running Reconnaissance...") as progress:
            progress.update(20)
            whois_data = get_whois(domain)
            progress.update(20)
            dns_data = get_dns(domain)
            progress.update(20)
            ssl_data = get_ssl(domain)
            progress.update(20)
            headers_data = get_headers(url)
            progress.update(20)
            shodan_data = get_shodan(domain)
            
    typer.secho("\n[+] Reconnaissance Complete!\n", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"WHOIS Registrar: {whois_data.get('registrar', 'N/A')}")
    typer.echo(f"DNS A Records: {', '.join(dns_data.get('A', []))}")
    typer.echo(f"SSL Issuer: {ssl_data.get('issuer', 'N/A')}")
    
    if "error" in shodan_data:
        typer.secho(f"Shodan: {shodan_data['error']}", fg=typer.colors.YELLOW)
    else:
        typer.echo(f"Shodan IP: {shodan_data.get('ip', 'N/A')} | OS: {shodan_data.get('os', 'N/A')} | Ports: {shodan_data.get('ports', [])}")
    
    typer.echo("")
    if report:
        data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "whois": whois_data,
            "dns": dns_data,
            "ssl": ssl_data,
            "headers": headers_data,
            "shodan": shodan_data
        }
        out_path = generate_json(domain, data, report_out)
        typer.secho(f"✔ Report generated successfully: {out_path}", fg=typer.colors.GREEN, bold=True)

if __name__ == "__main__":
    app()