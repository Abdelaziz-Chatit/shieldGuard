import logging
import json
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class EventBroker:
    """
    WebSocket event broker for broadcasting alerts and system events
    to all connected clients.
    """
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        """
        Register a new WebSocket connection.
        
        Args:
            websocket: WebSocket connection object
        """
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """
        Remove a WebSocket connection.
        
        Args:
            websocket: WebSocket connection object
        """
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, event: dict):
        """
        Broadcast an event to all connected clients.
        Silently removes disconnected clients.
        
        Args:
            event: Event data as dictionary (will be JSON-serialized)
        """
        disconnected = set()
        
        for connection in self.active_connections:
            try:
                await connection.send_json(event)
            except Exception as e:
                logger.debug(f"Error sending to client: {e}")
                disconnected.add(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            self.active_connections.discard(conn)
        
        if disconnected:
            logger.info(f"Removed {len(disconnected)} disconnected clients")
