import logging
import asyncio
from typing import Set, Optional
import psutil
from sqlalchemy.orm import Session
from database.models import Alert, AlertType, AlertSeverity
from services.event_broker import EventBroker

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Background monitor for suspicious processes (RATs, etc.).
    Runs as asyncio tasks and creates alerts for suspicious activity.
    """
    
    RAT_PROCESSES = {
        "anydesk", "teamviewer", "ultraviewer", "rustdesk",
        "ammyy admin", "supremo", "screenconnect", "logmein",
        "radmin", "vnc", "tightvnc", "realvnc"
    }
    
    def __init__(self):
        self.monitoring = False
        self.monitor_task: Optional[asyncio.Task] = None
        self.db_session_factory = None
        self.event_broker: Optional[EventBroker] = None
        self.alerted_pids: Set[int] = set()  # Track already-alerted processes
    
    async def start(self, db_session_factory, event_broker):
        """
        Start the network monitor background task.
        
        Args:
            db_session_factory: SQLAlchemy sessionmaker
            event_broker: EventBroker for broadcasting alerts
        """
        if self.monitoring:
            logger.warning("Monitor already running")
            return
        
        self.db_session_factory = db_session_factory
        self.event_broker = event_broker
        self.monitoring = True
        self.alerted_pids.clear()
        
        logger.info("Starting network monitor...")
        self.monitor_task = asyncio.create_task(self._monitor_processes())
    
    async def stop(self):
        """Stop the network monitor background task"""
        if not self.monitoring:
            return
        
        logger.info("Stopping network monitor...")
        self.monitoring = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                logger.info("Monitor task cancelled")
    
    async def _monitor_processes(self):
        """
        Continuously monitor running processes for suspicious activity.
        Checks every 3 seconds.
        """
        while self.monitoring:
            try:
                await asyncio.sleep(3)
                
                try:
                    for proc in psutil.process_iter(['name', 'pid', 'exe', 'connections']):
                        try:
                            proc_name = proc.info['name'].lower()
                            proc_pid = proc.info['pid']
                            
                            # Check if process name contains any RAT keywords
                            is_suspicious = any(rat in proc_name for rat in self.RAT_PROCESSES)
                            
                            if is_suspicious and proc_pid not in self.alerted_pids:
                                # Mark as alerted to avoid duplicates
                                self.alerted_pids.add(proc_pid)
                                
                                # Check whitelist
                                db = self.db_session_factory()
                                try:
                                    from database.models import Whitelist
                                    
                                    whitelist_entry = db.query(Whitelist).filter(
                                        Whitelist.type == "process",
                                        Whitelist.value == proc_name
                                    ).first()
                                    
                                    if whitelist_entry:
                                        logger.info(f"Suspicious process {proc_name} is whitelisted")
                                        continue
                                    
                                    # Create alert
                                    alert = Alert(
                                        user_id=None,  # System alert
                                        type=AlertType.PROCESS,
                                        severity=AlertSeverity.CRITICAL,
                                        title=f"Suspicious process detected: {proc_name}",
                                        description=f"Detected known RAT/remote access tool: {proc_name} (PID: {proc_pid})",
                                        source=proc_name,
                                        score=1.0,
                                        model_used="PROCESS_MONITOR",
                                        resolved=False
                                    )
                                    
                                    db.add(alert)
                                    db.commit()
                                    
                                    logger.warning(f"Alert created for suspicious process: {proc_name}")
                                    
                                    # Broadcast WebSocket event
                                    if self.event_broker:
                                        from datetime import datetime
                                        event = {
                                            "event_type": "PROCESS_ALERT",
                                            "severity": "CRITICAL",
                                            "title": f"Suspicious process detected: {proc_name}",
                                            "description": f"PID: {proc_pid}",
                                            "source": proc_name,
                                            "score": 1.0,
                                            "timestamp": datetime.utcnow().isoformat()
                                        }
                                        await self.event_broker.broadcast(event)
                                
                                except Exception as e:
                                    logger.error(f"Error creating alert for process {proc_name}: {e}")
                                finally:
                                    db.close()
                        
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # Process exited or no access, skip
                            continue
                
                except Exception as e:
                    logger.error(f"Error during process monitoring: {e}")
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in monitor loop: {e}")
                await asyncio.sleep(1)
        
        logger.info("Network monitor stopped")
