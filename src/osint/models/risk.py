from pydantic import BaseModel
from enum import Enum

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class RiskFinding(BaseModel):
    title: str
    description: str
    severity: Severity
