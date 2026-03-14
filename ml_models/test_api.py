import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def print_section(title):
    print("\n" + "="*40)
    print(title)
    print("="*40)

# -----------------------
# HEALTH CHECK
# -----------------------

print_section("API HEALTH CHECK")
try:
    health = requests.get(f"{BASE_URL}/health")
    print(json.dumps(health.json(), indent=2))
except requests.exceptions.ConnectionError:
    print("Failed to connect! Is the uvicorn server running?")
    exit()

# -----------------------
# DOS ATTACK SAMPLE
# -----------------------

dos_sample = {
    "features": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 100,
        "srv_count": 100,
        "serror_rate": 1,
        "srv_serror_rate": 1,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 1,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 1,
        "dst_host_srv_serror_rate": 1,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }
}

print_section("DOS ATTACK TEST")
dos_resp = requests.post(f"{BASE_URL}/predict", json=dos_sample)
print(json.dumps(dos_resp.json(), indent=2))

# -----------------------
# NORMAL TRAFFIC SAMPLE
# -----------------------

normal_sample = {
    "features": {
        "duration": 10,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 500,
        "dst_bytes": 2000,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 5,
        "srv_count": 5,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 20,
        "dst_host_srv_count": 20,
        "dst_host_same_srv_rate": 1,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 1,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }
}

print_section("NORMAL TRAFFIC TEST")
normal_resp = requests.post(f"{BASE_URL}/predict", json=normal_sample)
print(json.dumps(normal_resp.json(), indent=2))

# -----------------------
# MODEL STATS
# -----------------------

print_section("MODEL STATS")
stats = requests.get(f"{BASE_URL}/model_stats")
print(json.dumps(stats.json(), indent=2))