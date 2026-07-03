from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from src.osint.models.target import Target
from src.osint.models.risk import RiskFinding

class ScanResult(BaseModel):
    target: Target
    generated_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    
    # We will use Dict[str, Any] for flexibility, though specific models can be defined later
    whois_data: Dict[str, Any] = Field(default_factory=dict)
    dns_data: Dict[str, Any] = Field(default_factory=dict)
    ssl_data: Dict[str, Any] = Field(default_factory=dict)
    headers_data: Dict[str, Any] = Field(default_factory=dict)
    technology_data: List[str] = Field(default_factory=list)
    shodan_data: Dict[str, Any] = Field(default_factory=dict)
    
    subdomains: List[str] = Field(default_factory=list)
    geo_data: Dict[str, Any] = Field(default_factory=dict)
    wayback_data: Dict[str, Any] = Field(default_factory=dict)
    api_endpoints: List[str] = Field(default_factory=list)
    
    risk_findings: List[RiskFinding] = Field(default_factory=list)
    
    def model_dump_report(self) -> dict:
        return self.model_dump()
