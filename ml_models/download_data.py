import os
import requests
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from tqdm import tqdm

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]


def download_file(url, path):
    if os.path.exists(path):
        print(f"  {os.path.basename(path)} already exists, skipping")
        return

    print(f"  Downloading {os.path.basename(path)}...")
    resp = requests.get(url, stream=True)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))

    with open(path, "wb") as f, tqdm(total=total, unit="B", unit_scale=True) as bar:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
            bar.update(len(chunk))

    print(f"  Saved -> {path}")


train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
test_path = os.path.join(DATA_DIR, "KDDTest+.txt")

print("=" * 50)
print("  STEP 1 - Downloading NSL-KDD dataset")
print("=" * 50)
download_file(TRAIN_URL, train_path)
download_file(TEST_URL, test_path)

print("\n" + "=" * 50)
print("  STEP 2 - Loading & inspecting data")
print("=" * 50)

train_df = pd.read_csv(train_path, names=COLUMNS)
test_df = pd.read_csv(test_path, names=COLUMNS)

print(f"\n  TRAIN shape: {train_df.shape}")
print(f"  TEST  shape: {test_df.shape}")

print("\n  TRAIN null counts:")
print(train_df.isnull().sum().to_string())

print("\n  TEST null counts:")
print(test_df.isnull().sum().to_string())

print("\n  TRAIN dtypes:")
print(train_df.dtypes.to_string())

print("\n  TRAIN label value_counts:")
print(train_df["label"].value_counts().to_string())

print("\n  TEST label value_counts:")
print(test_df["label"].value_counts().to_string())

# Binary label
train_df["label_binary"] = train_df["label"].apply(lambda x: 0 if x == "normal" else 1)
test_df["label_binary"] = test_df["label"].apply(lambda x: 0 if x == "normal" else 1)

# 5-class mapping
FIVE_CLASS_MAP = {}
FIVE_CLASS_MAP["normal"] = "normal"

for a in ["back", "land", "neptune", "pod", "smurf", "teardrop",
           "apache2", "udpstorm", "processtable", "worm"]:
    FIVE_CLASS_MAP[a] = "dos"

for a in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
    FIVE_CLASS_MAP[a] = "probe"

for a in ["guess_passwd", "ftp_write", "imap", "phf", "multihop",
           "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
           "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"]:
    FIVE_CLASS_MAP[a] = "r2l"

for a in ["buffer_overflow", "loadmodule", "perl", "rootkit",
           "sqlattack", "xterm", "ps"]:
    FIVE_CLASS_MAP[a] = "u2r"


def map_5class(label):
    return FIVE_CLASS_MAP.get(label, "dos")


train_df["label_5class"] = train_df["label"].apply(map_5class)
test_df["label_5class"] = test_df["label"].apply(map_5class)

print("\n  5-class distribution (TRAIN):")
print(train_df["label_5class"].value_counts().to_string())

print("\n  5-class distribution (TEST):")
print(test_df["label_5class"].value_counts().to_string())

# Save cleaned CSVs
train_clean_path = os.path.join(DATA_DIR, "train_clean.csv")
test_clean_path = os.path.join(DATA_DIR, "test_clean.csv")

train_df.to_csv(train_clean_path, index=False)
test_df.to_csv(test_clean_path, index=False)

print(f"\n  Saved -> {train_clean_path}")
print(f"  Saved -> {test_clean_path}")

# Bar chart of 5-class distribution
plt.figure(figsize=(10, 6))
train_df["label_5class"].value_counts().plot(kind="bar", color=["#2ecc71", "#e74c3c", "#f39c12", "#3498db", "#9b59b6"])
plt.title("5-Class Attack Distribution (Train Set)")
plt.ylabel("Count")
plt.xlabel("Attack Class")
plt.xticks(rotation=0)
plt.tight_layout()
chart_path = os.path.join(DATA_DIR, "attack_distribution.png")
plt.savefig(chart_path, dpi=120)
print(f"  Saved -> {chart_path}")

print("\n[OK] download_data.py complete!")