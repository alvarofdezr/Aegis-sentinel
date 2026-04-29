import os
import asyncio
import threading
import structlog
from dotenv import load_dotenv

from aegis.core.interceptor import AegisInterceptor
from aegis.core.flow_table import FlowTable
from aegis.modules.policy_engine import PolicyEngine
from aegis.modules.threat_intel import AsyncThreatIntel
from aegis.common.logger import configure_logger

def start_async_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Executes the asyncio event loop in a background thread."""
    asyncio.set_event_loop(loop)
    loop.run_forever()

def run() -> None:
    """Aegis Sentinel main engine initialization."""
    # Load environment and configure structured logging
    load_dotenv()
    configure_logger()
    logger = structlog.get_logger()
    
    logger.info("aegis_booting", version="0.1.0-alpha")
    
    # 1. Configuration
    api_key = os.getenv("AEGIS_VT_API_KEY", "")
    queue_num = int(os.getenv("AEGIS_QUEUE_NUM", "1"))
    
    # 2. Threading & Async Setup
    async_loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(
        target=start_async_loop, 
        args=(async_loop,), 
        daemon=True,
        name="AegisAsyncLoopThread"
    )
    loop_thread.start()
    
    # 3. Module Initialization
    threat_intel = AsyncThreatIntel(api_key=api_key)
    policy_engine = PolicyEngine()
    flow_table = FlowTable(timeout_seconds=300)
    
    interceptor = AegisInterceptor(
        queue_num=queue_num, 
        threat_intel=threat_intel,
        policy_engine=policy_engine,
        flow_table=flow_table,
        loop=async_loop
    )
    
    try:
        # 4. Engine Start
        logger.info("aegis_active", mode="gateway_ips", queue=queue_num)
        interceptor.start()
    except KeyboardInterrupt:
        logger.info("aegis_shutdown_initiated", reason="user_interrupt")
    finally:
        # 5. Graceful Shutdown
        interceptor.stop()
        asyncio.run_coroutine_threadsafe(threat_intel.close(), async_loop)
        async_loop.call_soon_threadsafe(async_loop.stop)
        loop_thread.join(timeout=2.0)
        logger.info("aegis_shutdown_complete")

if __name__ == "__main__":
    run()