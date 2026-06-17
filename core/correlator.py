"""
================================================================================
INCIDENT CORRELATOR — Alert-to-Incident Grouping
================================================================================
Purpose:
  Groups multiple alerts from the same source IP into higher-level "Incidents".
  An incident represents an active attack session (e.g., "SYN flood from 10.0.0.99").

Usage:
  correlator = IncidentCorrelator(inactivity_window=180)
  incident_id = correlator.process_alert(alert_dict, intel_dict)

Design:
  - C1: grouping is controlled by `group_by` (list of alert fields), default ["_src_ip"]
  - C2: at most `max_startup_incidents` resumed from SQLite on init (default 100)
  - C3: only alerts with severity >= `min_severity` create incidents
  - Incidents persist to SQLite (incidents table) with enrichment fields
  - evict_stale() closes incidents that exceed inactivity_window (default 180s)
  - Returns incident_id for DB linking; 0 if below min_severity threshold
================================================================================
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

    C1: grouping is controlled by `group_by` — a list of alert field names
        whose values are joined to form the incident key (default ["_src_ip"]).
        Example: group_by=["_src_ip", "dst_ip"] splits by pair.
    C2: at most `max_startup_incidents` are resumed from DB on init.
    C3: only alerts with severity >= `min_severity` create incidents.
    """

    SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

    def __init__(
        self,
        inactivity_window: int = 180,
        group_by: Optional[List[str]] = None,
        max_startup_incidents: int = 100,
        min_severity: str = "low",
    ):
        self.inactivity_window = inactivity_window
        self.group_by = group_by or ["_src_ip"]
        self.max_startup_incidents = max_startup_incidents
        self.min_severity = min_severity
        self.conn = get_db_connection()
        self.active_incidents: Dict[str, Incident] = {}

        self._resume_active_incidents()

    def _incident_key(self, alert: dict) -> str:
        parts = [str(alert.get(f, "unknown")) for f in self.group_by]
        return "|".join(parts)

    def _resume_active_incidents(self):
        """C2: load at most `max_startup_incidents` active incidents on startup."""
        try:
            cursor = self.conn.execute(
                "SELECT id, src_ip, start_time, end_time, max_severity "
                "FROM incidents WHERE status = 'active' "
                "ORDER BY start_time DESC LIMIT ?",
                (self.max_startup_incidents,)
            )
            for row in cursor.fetchall():
                iid, ip, start, end, sev = row
                inc = Incident(iid, ip, start, sev)
                inc.last_seen = end or start
                self.active_incidents[ip] = inc
            if self.active_incidents:
                logger.info(f"Correlator: Resumed {len(self.active_incidents)} active incidents from DB (limit={self.max_startup_incidents})")
        except Exception as e:
            logger.error(f"Correlator: Failed to resume active incidents: {e}")

    def process_alert(self, alert: dict, intel: dict = None, now: float = None) -> int:
        """
        Groups an alert into an incident and returns the incident_id.

        C3: returns 0 (no incident) if severity < min_severity.
        """
        severity = alert.get("severity", "low")
        if self.SEVERITY_ORDER.get(severity, -1) < self.SEVERITY_ORDER.get(self.min_severity, 0):
            return 0

        src_ip = alert.get("_src_ip", "unknown")
        key = self._incident_key(alert)

        if now is None:
            now = time.time()

        if key in self.active_incidents:
            incident = self.active_incidents[key]
            incident.last_seen = now
            incident.alert_count += 1

            if intel:
                incident.country = intel.get("country")
                incident.countryCode = intel.get("countryCode")
                incident.city = intel.get("city")
                incident.asn = intel.get("asn")
                incident.threat_level = intel.get("threat_level")

            if self.SEVERITY_ORDER.get(severity, 0) > self.SEVERITY_ORDER.get(incident.severity, 0):
                incident.severity = severity

            self._update_incident_db(incident)
            return incident.id
        else:
            iid = self._create_incident_db(src_ip, now, severity, intel)
            incident = Incident(iid, src_ip, now, severity)
            if intel:
                incident.country = intel.get("country")
                incident.countryCode = intel.get("countryCode")
                incident.city = intel.get("city")
                incident.asn = intel.get("asn")
                incident.threat_level = intel.get("threat_level")
            self.active_incidents[key] = incident
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
