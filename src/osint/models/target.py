from pydantic import BaseModel, Field

class Target(BaseModel):
    raw_input: str = Field(..., description="The original user input")
    domain: str = Field(..., description="The normalized base domain name")
    scheme: str = Field(default="https", description="The URL scheme (http or https)")
    url: str = Field(..., description="The fully reconstructed valid URL")
