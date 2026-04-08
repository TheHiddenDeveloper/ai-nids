import subprocess
import json
import ipaddress
import threading
from loguru import logger
from core.redis_client import get_redis_client

class FirewallEngine:
    """
    Subscribes to 'nids:commands' and executes system firewall actions.
    Should be run with sufficient privileges (sudo).
    """
    COMMAND_CHANNEL = "nids:commands"
    RESOURCE_PREFIX = "nids:blocked"

    def __init__(self):
        self.redis = get_redis_client()
        if not self.redis:
            logger.error("FirewallEngine: Redis is not available. Cannot start.")
            return

        # RFC1918 Private Ranges (Safety Filter)
        self.safe_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8")
        ]

    def _is_safe(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in self.safe_ranges:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    def run_command(self, cmd: list) -> bool:
        try:
            # We use sudo explicitly in the command to allow fine-grained controls
            # but ideally the whole process is run with sudo.
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"FirewallEngine: Executed {' '.join(cmd)}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"FirewallEngine: Command failed: {e.stderr}")
            return False

    def block_ip(self, ip: str):
        if not self._is_safe(ip):
            logger.warning(f"FirewallEngine: Blocking of private/local IP {ip} rejected for safety.")
            return False
        
        # -I (Insert) at the top of INPUT chain to override other rules
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        if self.run_command(cmd):
            self.redis.sadd(f"{self.RESOURCE_PREFIX}:ips", ip)
            return True
        return False

    def unblock_ip(self, ip: str):
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        if self.run_command(cmd):
            self.redis.srem(f"{self.RESOURCE_PREFIX}:ips", ip)
            return True
        return False

    def start(self):
        if not self.redis: return
        
        logger.info("FirewallEngine: Listening for commands on Redis...")
        pubsub = self.redis.pubsub()
        pubsub.subscribe(self.COMMAND_CHANNEL)
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                try:
                    data = json.loads(message['data'])
                    action = data.get("action")
                    ip = data.get("ip")
                    
                    if action == "block" and ip:
                        self.block_ip(ip)
                    elif action == "unblock" and ip:
                        self.unblock_ip(ip)
                    else:
                        logger.warning(f"FirewallEngine: Unknown action/missing IP: {data}")
                except Exception as e:
                    logger.error(f"FirewallEngine: Error processing message: {e}")

if __name__ == "__main__":
    engine = FirewallEngine()
    engine.start()
