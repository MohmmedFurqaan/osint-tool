import asyncio
from src.osint.models.target import Target
from src.osint.models.result import ScanResult
from src.osint.services.whois_service import get_whois_async
from src.osint.services.dns_service import get_dns_async
from src.osint.services.ssl_service import get_ssl_async
from src.osint.services.header_service import get_headers_async
from src.osint.services.shodan_service import get_shodan_async
from src.osint.services.tech_service import detect_technologies
from src.osint.services.risk_service import analyze_risk

class ScannerManager:
    def __init__(self, target: Target):
        self.target = target

    async def run_all(self) -> ScanResult:
        # Run I/O bound scanners concurrently
        whois_task = get_whois_async(self.target.domain)
        dns_task = get_dns_async(self.target.domain)
        ssl_task = get_ssl_async(self.target.domain)
        headers_task = get_headers_async(self.target.url)
        shodan_task = get_shodan_async(self.target.domain)
        
        whois_res, dns_res, ssl_res, headers_res, shodan_res = await asyncio.gather(
            whois_task, dns_task, ssl_task, headers_task, shodan_task
        )
        
        # CPU bound / synchronous logic after fetching
        tech_res = detect_technologies(headers_res) if "error" not in headers_res else []
        
        result = ScanResult(
            target=self.target,
            whois_data=whois_res,
            dns_data=dns_res,
            ssl_data=ssl_res,
            headers_data=headers_res,
            technology_data=tech_res,
            shodan_data=shodan_res
        )
        
        # Risk assessment
        result.risk_findings = analyze_risk(result)
        
        return result
