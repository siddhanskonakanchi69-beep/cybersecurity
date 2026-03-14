import requests
import json

BASE_URL = "http://127.0.0.1:8001"


def print_section(title):
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50)


# -----------------------
# 1. HEALTH CHECK
# -----------------------
print_section("HEALTH CHECK")
try:
    resp = requests.get(f"{BASE_URL}/health")
    print(json.dumps(resp.json(), indent=2))
except requests.exceptions.ConnectionError:
    print("Failed to connect! Is the uvicorn server running on port 8001?")
    print("Start it with: python -m ml_models.serve")
    exit()

# -----------------------
# 2. DOS ATTACK SAMPLE
# -----------------------
dos_sample = {
    "features": {
        "duration": 0,
        "src_bytes": 1032,
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
        "count": 511,
        "srv_count": 511,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
}

print_section("DOS ATTACK TEST")
resp = requests.post(f"{BASE_URL}/predict", json=dos_sample)
print(json.dumps(resp.json(), indent=2))

# -----------------------
# 3. NORMAL TRAFFIC SAMPLE
# -----------------------
normal_sample = {
    "features": {
        "duration": 2,
        "src_bytes": 215,
        "dst_bytes": 45053,
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
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 20,
        "dst_host_srv_count": 20,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.05,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
}

print_section("NORMAL TRAFFIC TEST")
resp = requests.post(f"{BASE_URL}/predict", json=normal_sample)
print(json.dumps(resp.json(), indent=2))

# -----------------------
# 4. MODEL STATS
# -----------------------
print_section("MODEL STATS")
resp = requests.get(f"{BASE_URL}/model_stats")
data = resp.json()
print(json.dumps(data, indent=2))

# Print top 10 features if available
if "random_forest" in data:
    rf_data = data["random_forest"]
    if "feature_importances" in rf_data:
        print("\n  Top 10 Feature Importances:")
        items = sorted(rf_data["feature_importances"].items(), key=lambda x: x[1], reverse=True)[:10]
        for i, (feat, score) in enumerate(items, 1):
            print(f"    {i:2d}. {feat:40s} {score:.4f}")
    elif "top_features" in rf_data:
        print("\n  Top 10 Feature Importances:")
        for i, entry in enumerate(rf_data["top_features"][:10], 1):
            print(f"    {i:2d}. {entry['feature']:40s} {entry['importance']:.4f}")