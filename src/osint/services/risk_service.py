from src.osint.models.result import ScanResult
from src.osint.models.risk import RiskFinding, Severity

def analyze_risk(result: ScanResult) -> list[RiskFinding]:
    findings = []
    
    # 1. Check Security Headers
    headers = result.headers_data
    if "error" not in headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing = []
        if 'strict-transport-security' not in headers_lower:
            missing.append('HSTS')
        if 'x-frame-options' not in headers_lower and 'content-security-policy' not in headers_lower:
            missing.append('X-Frame-Options / CSP')
        if 'x-content-type-options' not in headers_lower:
            missing.append('X-Content-Type-Options')
            
        if missing:
            findings.append(RiskFinding(
                title="Missing Security Headers",
                description=f"The following security headers are missing: {', '.join(missing)}",
                severity=Severity.MEDIUM
            ))
            
    # 2. Check SPF
    dns = result.dns_data
    if "error" not in dns:
        txt_records = dns.get('TXT', [])
        has_spf = any('v=spf1' in r for r in txt_records)
        if not has_spf:
            findings.append(RiskFinding(
                title="Missing SPF Record",
                description="No SPF entry found in domain TXT records, increasing spoofing risk.",
                severity=Severity.MEDIUM
            ))

    # 3. Check Shodan Open Ports
    shodan = result.shodan_data
    if "error" not in shodan:
        ports = shodan.get('ports', [])
        risky_ports = {21, 23, 445, 3389}
        exposed = [p for p in ports if p in risky_ports]
        if exposed:
            findings.append(RiskFinding(
                title="Exposed Risky Services",
                description=f"Shodan reports potentially risky open ports: {exposed}",
                severity=Severity.HIGH
            ))
            
    return findings
