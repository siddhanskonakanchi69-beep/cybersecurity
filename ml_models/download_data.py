import os
import requests
import pandas as pd
import matplotlib.pyplot as plt

DATA_DIR = "ml_models/data"
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

os.makedirs(DATA_DIR, exist_ok=True)

train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
test_path = os.path.join(DATA_DIR, "KDDTest+.txt")

def download_file(url, path):
    if not os.path.exists(path):
        r = requests.get(url)
        r.raise_for_status()
        with open(path, "wb") as f:
            f.write(r.content)
        print(f"Downloaded {path}")
    else:
        print(f"{path} already exists")

download_file(TRAIN_URL, train_path)
download_file(TEST_URL, test_path)

columns = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate",
"label","difficulty_level"
]

train_df = pd.read_csv(train_path, names=columns)
test_df = pd.read_csv(test_path, names=columns)

print("\n=== TRAIN SHAPE ===")
print(train_df.shape)
print("\n=== TEST SHAPE ===")
print(test_df.shape)

print("\n=== LABEL DISTRIBUTION (TRAIN) ===")
print(train_df["label"].value_counts())

print("\n=== NULL COUNTS ===")
print(train_df.isnull().sum())

print("\n=== DTYPES ===")
print(train_df.dtypes)

plt.figure(figsize=(12,6))
train_df["label"].value_counts().plot(kind="bar")
plt.title("Attack Type Distribution")
plt.ylabel("Count")
plt.xlabel("Attack Type")
plt.tight_layout()
plt.savefig(os.path.join(DATA_DIR, "attack_distribution.png"))

binary_map = lambda x: 0 if x == "normal" else 1
train_df["binary_label"] = train_df["label"].apply(binary_map)
test_df["binary_label"] = test_df["label"].apply(binary_map)

dos = [
"back","land","neptune","pod","smurf","teardrop",
"mailbomb","apache2","processtable","udpstorm"
]

probe = [
"satan","ipsweep","nmap","portsweep","mscan","saint"
]

r2l = [
"ftp_write","guess_passwd","imap","multihop","phf",
"spy","warezclient","warezmaster","sendmail","named",
"snmpgetattack","snmpguess","xlock","xsnoop","worm"
]

u2r = [
"buffer_overflow","loadmodule","perl","rootkit",
"httptunnel","ps","sqlattack","xterm"
]

attack_family = {}

for a in dos:
    attack_family[a] = "dos"
for a in probe:
    attack_family[a] = "probe"
for a in r2l:
    attack_family[a] = "r2l"
for a in u2r:
    attack_family[a] = "u2r"

def map_attack(label):
    if label == "normal":
        return "normal"
    return attack_family.get(label, "unknown")

train_df["attack_class"] = train_df["label"].apply(map_attack)
test_df["attack_class"] = test_df["label"].apply(map_attack)

train_clean_path = os.path.join(DATA_DIR, "train_clean.csv")
test_clean_path = os.path.join(DATA_DIR, "test_clean.csv")

train_df.to_csv(train_clean_path, index=False)
test_df.to_csv(test_clean_path, index=False)

print("\nCleaned files saved:")
print(train_clean_path)
print(test_clean_path)