from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, IPvAnyAddress

class FlowRecord(BaseModel):
    """Represents a network flow evaluated by the Aegis engine.
    
    Used for telemetry, auditing, and feeding data to the C2/Dashboard.
    """
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    protocol: str = Field(default="TCP")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_malicious: bool = False
    action_taken: str = Field(pattern="^(ACCEPT|DROP)$")
    threat_score: Optional[float] = None
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "source_ip": "10.0.0.2",
                "destination_ip": "198.51.100.14",
                "action_taken": "DROP"
            }
        }
    }