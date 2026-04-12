"""
Incident Correlation Engine
---------------------------
Groups multiple alerts from the same source into high-level Incidents.
Uses a sliding time window to track active attack sessions.
"""

import time
import json
from typing import Dict, Optional, List
from loguru import logger
from monitor.db import get_db_connection

class Incident:
    """In-memory representation of an active incident."""
    def __init__(self, incident_id: int, src_ip: str, start_time: float, severity: str):
        self.id = incident_id
        self.src_ip = src_ip
        self.start_time = start_time
        self.last_seen = start_time
        self.severity = severity
        self.alert_count = 1
        self.is_active = True
        # Enrichment fields
        self.country = None
        self.countryCode = None
        self.city = None
        self.asn = None
        self.threat_level = None

class IncidentCorrelator:
    """
    Stateful correlator that groups alerts into incidents.
    Persists incident status to SQLite.
    """

    def __init__(self, inactivity_window: int = 180):
        self.inactivity_window = inactivity_window
        self.conn = get_db_connection()
        # memory: src_ip -> Incident object
        self.active_incidents: Dict[str, Incident] = {}
        
        # Pull recently active incidents from DB on startup to maintain state across restarts
        self._resume_active_incidents()

    def _resume_active_incidents(self):
        """Load 'active' incidents from the DB into memory."""
        try:
            cursor = self.conn.execute(
                "SELECT id, src_ip, start_time, end_time, max_severity FROM incidents WHERE status = 'active'"
            )
            for row in cursor.fetchall():
                iid, ip, start, end, sev = row
                inc = Incident(iid, ip, start, sev)
                inc.last_seen = end or start
                self.active_incidents[ip] = inc
            if self.active_incidents:
                logger.info(f"Correlator: Resumed {len(self.active_incidents)} active incidents from DB")
        except Exception as e:
            logger.error(f"Correlator: Failed to resume active incidents: {e}")

    def process_alert(self, alert: dict, intel: dict = None, now: float = None) -> int:
        """
        Groups an alert into an incident and returns the incident_id.
        """
        src_ip = alert.get("_src_ip", "unknown")
        severity = alert.get("severity", "low")
        if now is None:
            now = time.time()

        if src_ip in self.active_incidents:
            # Update existing incident
            incident = self.active_incidents[src_ip]
            incident.last_seen = now
            incident.alert_count += 1
            
            # Sync intel if not already set or changed
            if intel:
                incident.country = intel.get("country")
                incident.countryCode = intel.get("countryCode")
                incident.city = intel.get("city")
                incident.asn = intel.get("asn")
                incident.threat_level = intel.get("threat_level")

            # Escalate severity if needed
            sev_map = {"low": 0, "medium": 1, "high": 2}
            if sev_map.get(severity, 0) > sev_map.get(incident.severity, 0):
                incident.severity = severity

            self._update_incident_db(incident)
            return incident.id
        else:
            # Create new incident
            iid = self._create_incident_db(src_ip, now, severity, intel)
            incident = Incident(iid, src_ip, now, severity)
            if intel:
                incident.country = intel.get("country")
                incident.countryCode = intel.get("countryCode")
                incident.city = intel.get("city")
                incident.asn = intel.get("asn")
                incident.threat_level = intel.get("threat_level")
            self.active_incidents[src_ip] = incident
            return iid

    def _create_incident_db(self, src_ip: str, start_time: float, severity: str, intel: dict = None) -> int:
        """Inserts a new incident into the DB and returns its ID."""
        country = intel.get("country") if intel else None
        city = intel.get("city") if intel else None
        asn = intel.get("asn") if intel else None
        threat_level = intel.get("threat_level") if intel else None

        try:
            cursor = self.conn.execute(
                "INSERT INTO incidents (start_time, end_time, src_ip, alert_count, max_severity, status, country, city, asn, threat_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (start_time, start_time, src_ip, 1, severity, "active", country, city, asn, threat_level)
            )
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Correlator: DB create failed: {e}")
            return 0

    def _update_incident_db(self, inc: Incident):
        """Persists incident updates to the DB."""
        try:
            self.conn.execute(
                "UPDATE incidents SET end_time = ?, alert_count = ?, max_severity = ?, country = ?, city = ?, asn = ?, threat_level = ? WHERE id = ?",
                (inc.last_seen, inc.alert_count, inc.severity, inc.country, inc.city, inc.asn, inc.threat_level, inc.id)
            )
        except Exception as e:
            logger.error(f"Correlator: DB update failed: {e}")

    def evict_stale(self, now: float = None) -> List[int]:
        """
        Closes incidents that have exceeded the inactivity window.
        Returns a list of IDs of closed incidents.
        """
        if now is None:
            now = time.time()
        to_close = []
        
        for ip, inc in list(self.active_incidents.items()):
            if (now - inc.last_seen) > self.inactivity_window:
                to_close.append(inc)
                del self.active_incidents[ip]

        closed_ids = []
        for inc in to_close:
            try:
                self.conn.execute(
                    "UPDATE incidents SET status = 'closed', end_time = ? WHERE id = ?",
                    (inc.last_seen, inc.id)
                )
                closed_ids.append(inc.id)
                logger.info(f"Correlator: Closed incident #{inc.id} for {inc.src_ip} (timeout)")
            except Exception as e:
                logger.error(f"Correlator: DB close failed for #{inc.id}: {e}")
        
        return closed_ids
