import subprocess
import redis
import logging
import os
import requests
import time
import json
from typing import Dict, Any, List

WHITELIST_IPS = ["127.0.0.1", "localhost"]

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_BLOCK_PREFIX = "blocked:"
REDIS_BLOCK_DEFAULT_TTL = 3600


class ResponseDispatcher:
    """
    Executes automated response actions: block IP, isolate host, send alerts.
    Tracks all actions in Redis for audit and dashboard visibility.
    """

    def __init__(self):
        self.logger = logging.getLogger("response_dispatcher")

        try:
            self.redis = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True
            )
            self.redis.ping()
            self.logger.info("[ResponseDispatcher] Redis connected")
        except Exception as e:
            self.logger.warning(f"[ResponseDispatcher] Redis unavailable: {e}")
            self.redis = None

        try:
            import docker
            self.docker = docker.from_env()
            self.docker_available = True
            self.logger.info("[ResponseDispatcher] Docker connected")
        except Exception as e:
            self.logger.warning(f"[ResponseDispatcher] Docker unavailable: {e}")
            self.docker_available = False

    def block_ip(self, ip: str, duration_minutes: int = 60) -> Dict[str, Any]:
        """
        Block an IP address using iptables and Redis.
        
        Actions:
        1. iptables INPUT/OUTPUT DROP rules for the source IP
        2. Redis entry with TTL for distributed cache
        
        Args:
            ip: IP address to block
            duration_minutes: TTL in minutes (default 60)
        
        Returns:
            dict with success status and message
        """
        if ip in WHITELIST_IPS:
            self.logger.warning(f"[ResponseDispatcher] Attempted to block whitelisted IP: {ip}")
            return {"success": False, "message": "IP is whitelisted"}

        blocked_ips = []
        
        # Try iptables (may fail on non-Linux)
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
            )
            blocked_ips.append("iptables")
            self.logger.info(f"[ResponseDispatcher] Added iptables rules for {ip}")
        except Exception as e:
            self.logger.debug(f"[ResponseDispatcher] iptables failed (expected on non-Linux): {e}")

        # Store in Redis for tracking
        if self.redis:
            try:
                key = f"{REDIS_BLOCK_PREFIX}{ip}"
                self.redis.setex(key, duration_minutes * 60, "blocked")
                blocked_ips.append("redis")
                self.logger.info(f"[ResponseDispatcher] Set Redis block key {key} (TTL: {duration_minutes}m)")
            except Exception as e:
                self.logger.warning(f"[ResponseDispatcher] Redis block failed: {e}")

        message = f"Blocked {ip} using {', '.join(blocked_ips) if blocked_ips else 'tracking'}"
        self.logger.info(f"[ResponseDispatcher] {message}")

        return {"success": bool(blocked_ips), "message": message, "blocked_ip": ip}

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """
        Unblock a previously blocked IP.
        
        Removes iptables rules and Redis entry.
        
        Args:
            ip: IP address to unblock
        
        Returns:
            dict with success status
        """
        unblocked_methods = []
        
        # Try to remove iptables rules
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
            )
            unblocked_methods.append("iptables")
        except Exception:
            pass

        # Remove Redis entry
        if self.redis:
            try:
                self.redis.delete(f"{REDIS_BLOCK_PREFIX}{ip}")
                unblocked_methods.append("redis")
            except Exception as e:
                self.logger.warning(f"[ResponseDispatcher] Redis unblock failed: {e}")

        message = f"Unblocked {ip} (removed from {', '.join(unblocked_methods) if unblocked_methods else 'tracking'})"
        self.logger.info(f"[ResponseDispatcher] {message}")
        return {"success": True, "message": message, "unblocked_ip": ip}

    def isolate_host(self, ip: str) -> Dict[str, Any]:
        """
        Isolate a host by pausing its Docker container.
        
        Useful for quarantining compromised systems while preserving state.
        
        Args:
            ip: IP address of the host to isolate
        
        Returns:
            dict with isolation status
        """
        if not self.docker_available:
            return {"success": False, "message": "Docker not available", "ip": ip}

        try:
            containers = self.docker.containers.list()

            for container in containers:
                try:
                    nets = container.attrs["NetworkSettings"]["Networks"]

                    for net_name, net_cfg in nets.items():
                        if net_cfg.get("IPAddress") == ip:
                            container.pause()
                            message = f"Paused container {container.name} (IP: {ip})"
                            self.logger.warning(f"[ResponseDispatcher] {message}")
                            return {"success": True, "message": message, "container": container.name, "ip": ip}
                except (KeyError, AttributeError):
                    continue

        except Exception as e:
            self.logger.error(f"[ResponseDispatcher] Isolation failed: {e}")
            return {"success": False, "message": str(e), "ip": ip}

        message = f"No container found with IP {ip}"
        self.logger.warning(f"[ResponseDispatcher] {message}")
        return {"success": False, "message": message, "ip": ip}

    def send_slack_alert(self, message: str, severity: str) -> bool:
        """
        Send an alert to Slack webhook.
        
        Args:
            message: Alert message text
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        
        Returns:
            bool indicating success
        """
        webhook = os.environ.get("SLACK_WEBHOOK_URL")

        if not webhook:
            self.logger.debug("[ResponseDispatcher] No Slack webhook configured; skipping alert")
            return False

        colors = {
            "CRITICAL": "#E74C3C",
            "HIGH": "#E67E22",
            "MEDIUM": "#F1C40F",
            "LOW": "#3498DB",
        }

        payload = {
            "attachments": [
                {
                    "color": colors.get(severity, "#95A5A6"),
                    "title": f"🚨 [{severity}] CyberDefense Alert",
                    "text": message,
                    "footer": "CyberDefense Orchestrator",
                    "ts": int(time.time()),
                }
            ]
        }

        try:
            resp = requests.post(webhook, json=payload, timeout=5)
            resp.raise_for_status()
            self.logger.info(f"[ResponseDispatcher] Slack alert sent (severity={severity})")
            return True
        except Exception as e:
            self.logger.warning(f"[ResponseDispatcher] Slack alert failed: {e}")
            return False

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Get list of all currently blocked IPs from Redis.
        
        Returns:
            List of dicts with IP and remaining TTL
        """
        if not self.redis:
            return []

        try:
            keys = self.redis.keys(f"{REDIS_BLOCK_PREFIX}*")
            result = []

            for key in keys:
                ip = key.replace(REDIS_BLOCK_PREFIX, "")
                ttl = self.redis.ttl(key)

                result.append({"ip": ip, "ttl_seconds": ttl, "status": "blocked"})

            return sorted(result, key=lambda x: x["ttl_seconds"], reverse=True)
        except Exception as e:
            self.logger.error(f"[ResponseDispatcher] Failed to retrieve blocked IPs: {e}")
            return []

    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent response actions from Redis.
        
        Args:
            limit: Maximum number of records to return
        
        Returns:
            List of action records
        """
        if not self.redis:
            return []

        try:
            actions = self.redis.lrange("response:actions", 0, limit - 1)
            return [json.loads(a) for a in actions if a]
        except Exception as e:
            self.logger.error(f"[ResponseDispatcher] Failed to retrieve action history: {e}")
            return []

    def _log_action(self, action_type: str, target: str, result: Dict[str, Any]) -> None:
        """
        Log a response action to Redis for audit trail.
        
        Args:
            action_type: Type of action (block_ip, isolate_host, etc.)
            target: Target IP or hostname
            result: Result dict from the action
        """
        if not self.redis:
            return

        try:
            import time
            import json
            record = {
                "timestamp": int(time.time()),
                "action": action_type,
                "target": target,
                "success": result.get("success", False),
                "message": result.get("message", ""),
            }
            self.redis.lpush("response:actions", json.dumps(record))
            self.redis.ltrim("response:actions", 0, 999)  # Keep last 1000
        except Exception as e:
            self.logger.debug(f"[ResponseDispatcher] Failed to log action: {e}")

