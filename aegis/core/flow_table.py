import time
import structlog
from typing import Dict

logger = structlog.get_logger()

class FlowTable:
    """In-memory state manager for active network flows.
    
    Tracks established connection states to prevent redundant analysis 
    of already verified, safe connections (improving throughput).
    """

    def __init__(self, timeout_seconds: int = 300):
        """
        Args:
            timeout_seconds: How long to consider a flow active without re-evaluation.
        """
        self.timeout = timeout_seconds
        # Structure: {"source_ip->dest_ip": expiration_timestamp}
        self._active_flows: Dict[str, float] = {}

    def is_flow_active(self, source: str, destination: str) -> bool:
        """Checks if a flow is currently active and unexpired."""
        flow_id = f"{source}->{destination}"
        
        if flow_id in self._active_flows:
            if time.time() < self._active_flows[flow_id]:
                return True
            else:
                del self._active_flows[flow_id] # Clean up expired flow
                
        return False

    def register_flow(self, source: str, destination: str) -> None:
        """Registers a verified flow to bypass future deep inspections."""
        flow_id = f"{source}->{destination}"
        self._active_flows[flow_id] = time.time() + self.timeout
        logger.debug("flow_registered", flow_id=flow_id)