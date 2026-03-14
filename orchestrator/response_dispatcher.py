import subprocess
import redis
import logging
import os
import requests

WHITELIST_IPS = ["127.0.0.1", "localhost"]

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_BLOCK_PREFIX = "blocked:"
REDIS_BLOCK_DEFAULT_TTL = 3600


class ResponseDispatcher:

    def __init__(self):

        self.logger = logging.getLogger("response_dispatcher")

        try:
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
            self.redis.ping()
        except Exception:
            self.redis = None
            self.logger.warning("Redis unavailable")

        try:
            import docker
            self.docker = docker.from_env()
            self.docker_available = True
        except Exception:
            self.docker_available = False

    def block_ip(self, ip: str, duration_minutes: int = 60):

        if ip in WHITELIST_IPS:
            return {"success": False, "message": "IP is whitelisted"}

        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )

            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True
            )
        except Exception as e:
            self.logger.warning(f"iptables failed: {e}")

        if self.redis:
            key = f"{REDIS_BLOCK_PREFIX}{ip}"
            self.redis.setex(key, duration_minutes * 60, "blocked")

        self.logger.info(f"[BLOCKED] {ip}")

        return {
            "success": True,
            "message": f"Blocked {ip}"
        }

    def unblock_ip(self, ip: str):

        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )

            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True
            )
        except Exception:
            pass

        if self.redis:
            self.redis.delete(f"{REDIS_BLOCK_PREFIX}{ip}")

        return {"success": True, "message": f"Unblocked {ip}"}

    def isolate_host(self, ip: str):

        if not self.docker_available:
            return {"success": False, "message": "Docker not available"}

        try:
            containers = self.docker.containers.list()

            for container in containers:

                nets = container.attrs["NetworkSettings"]["Networks"]

                for net_name, net_cfg in nets.items():

                    if net_cfg["IPAddress"] == ip:
                        container.pause()

                        return {
                            "success": True,
                            "message": f"Paused container {container.name}"
                        }

        except Exception as e:
            return {"success": False, "message": str(e)}

        return {"success": False, "message": "No container found"}

    def send_slack_alert(self, message: str, severity: str):

        webhook = os.environ.get("SLACK_WEBHOOK_URL")

        if not webhook:
            return

        colors = {
            "CRITICAL": "#E74C3C",
            "HIGH": "#E67E22",
            "MEDIUM": "#F1C40F",
            "LOW": "#3498DB"
        }

        payload = {
            "attachments": [
                {
                    "color": colors.get(severity, "#3498DB"),
                    "text": message
                }
            ]
        }

        try:
            requests.post(webhook, json=payload, timeout=2)
        except Exception:
            self.logger.warning("Slack alert failed")

    def get_blocked_ips(self):

        if not self.redis:
            return []

        keys = self.redis.keys(f"{REDIS_BLOCK_PREFIX}*")

        result = []

        for key in keys:

            ip = key.decode().replace(REDIS_BLOCK_PREFIX, "")

            ttl = self.redis.ttl(key)

            result.append({
                "ip": ip,
                "ttl_seconds": ttl
            })

        return result

