import asyncio
import structlog
from typing import Any
from netfilterqueue import NetfilterQueue
from scapy.all import IP

from aegis.modules.threat_intel import AsyncThreatIntel
from aegis.modules.policy_engine import PolicyEngine
from aegis.core.flow_table import FlowTable

logger = structlog.get_logger()

class AegisInterceptor:
    """High-performance network interception controller.
    
    Implements a multi-layered security pipeline:
    1. State tracking (FlowTable) for zero-latency bypass of known flows.
    2. Local firewall rules (PolicyEngine).
    3. External reputation analysis (AsyncThreatIntel).
    """

    def __init__(
        self, 
        queue_num: int, 
        threat_intel: AsyncThreatIntel,
        policy_engine: PolicyEngine,
        flow_table: FlowTable,
        loop: asyncio.AbstractEventLoop
    ):
        self.queue_num = queue_num
        self.threat_intel = threat_intel
        self.policy_engine = policy_engine
        self.flow_table = flow_table
        self._loop = loop
        self._nfqueue = NetfilterQueue()
        self.logger = logger.bind(component="interceptor", queue=self.queue_num)

    def _packet_handler(self, nfq_packet: Any) -> None:
        """Dispatches packets to the async loop, freeing the kernel queue."""
        self._loop.call_soon_threadsafe(
            lambda: self._loop.create_task(self.evaluate_flow(nfq_packet))
        )

    async def evaluate_flow(self, nfq_packet: Any) -> None:
        """Executes the asynchronous multi-layered security pipeline."""
        try:
            packet = IP(nfq_packet.get_payload())
            src_ip = packet.src
            dst_ip = packet.dst

            # Layer 1: Fast-Path / Flow State Verification
            if self.flow_table.is_flow_active(src_ip, dst_ip):
                nfq_packet.accept()
                return

            # Layer 2: Local Policy Engine
            is_policy_allowed = await self.policy_engine.evaluate(packet)
            if not is_policy_allowed:
                self.logger.warning("policy_violation", src=src_ip, dst=dst_ip, action="drop")
                nfq_packet.drop()
                return

            # Layer 3: Threat Intelligence (External Reputation)
            is_malicious = await self.threat_intel.is_malicious(dst_ip)
            if is_malicious:
                self.logger.warning("threat_detected", src=src_ip, dst=dst_ip, action="drop")
                nfq_packet.drop()
                return

            # Verdict: Safe Flow. Register state and forward packet.
            self.flow_table.register_flow(src_ip, dst_ip)
            nfq_packet.accept()

        except Exception as e:
            self.logger.error("pipeline_error", error=str(e))
            nfq_packet.accept()  # Fail-open design to maintain connectivity

    def start(self) -> None:
        """Binds to the NFQUEUE and blocks listening for traffic."""
        self.logger.info("interceptor_started")
        self._nfqueue.bind(self.queue_num, self._packet_handler)
        self._nfqueue.run()

    def stop(self) -> None:
        self.logger.info("interceptor_stopped")
        self._nfqueue.unbind()