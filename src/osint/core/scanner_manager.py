import asyncio
from src.osint.models.target import Target
from src.osint.models.result import ScanResult
from src.osint.services.whois_service import get_whois_async
from src.osint.services.dns_service import get_dns_async
from src.osint.services.ssl_service import get_ssl_async
from src.osint.services.header_service import get_headers_async
from src.osint.services.shodan_service import get_shodan_async
from src.osint.services.tech_service import detect_technologies_async
from src.osint.services.risk_service import analyze_risk
from src.osint.services.subdomain_service import get_subdomains_async
from src.osint.services.geo_service import get_geo_async
from src.osint.services.wayback_service import get_wayback_async
from src.osint.services.api_service import get_api_endpoints_async

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
        tech_task = detect_technologies_async(self.target.url)
        subdomain_task = get_subdomains_async(self.target.domain)
        geo_task = get_geo_async(self.target.domain)
        wayback_task = get_wayback_async(self.target.domain)
        api_task = get_api_endpoints_async(self.target.domain, self.target.url)
        
        whois_res, dns_res, ssl_res, headers_res, shodan_res, tech_res, sub_res, geo_res, wayback_res, api_res = await asyncio.gather(
            whois_task, dns_task, ssl_task, headers_task, shodan_task, tech_task, subdomain_task, geo_task, wayback_task, api_task
        )
        
        result = ScanResult(
            target=self.target,
            whois_data=whois_res,
            dns_data=dns_res,
            ssl_data=ssl_res,
            headers_data=headers_res,
            technology_data=tech_res,
            shodan_data=shodan_res,
            subdomains=sub_res,
            geo_data=geo_res,
            wayback_data=wayback_res,
            api_endpoints=api_res
        )
        
        # Risk assessment
        result.risk_findings = analyze_risk(result)
        
        return result
