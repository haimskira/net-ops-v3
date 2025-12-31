# 🛡️ NetOps Portal - Palo Alto Automation & Monitoring

**NetOps Portal** is a comprehensive web-based platform designed to streamline operations for Palo Alto Networks Firewalls. It bridges the gap between end-users and network administrators by providing a self-service portal for rule requests, object management, and real-time traffic monitoring.

Built with **Python (Flask)**, **Docker**, and **SQLite**, it ensures persistence, security, and ease of deployment.

---

## 🚀 Key Features (Updated)

* **🔐 Hybrid Authentication:**
    * **Integrated LDAP/Active Directory:** Single Sign-On for corporate users with role-based access.
    * **Emergency Local Admin Fallback:** Break-glass access via `.env` credentials when LDAP/AD is unreachable.
* **⚡ Pro-Search Rule Workflow:**
    * **Instant Type-Ahead Search:** High-performance custom search for both IP Objects and Applications (filter instantly by Name or IP value).
    * **Intelligent Validation:** Automatic **Shadow Rule Checking** to detect duplicates or conflicts before rules are created.
    * **Clean Naming Engine:** Automatically generates rule names based on traffic flow (`Src_Dst_Svc`) while ensuring compliance with Palo Alto character restrictions.
* **📡 Smart Traffic Logs:**
    * **Live Syslog Listener:** Captures real-time UDP 514 traffic streams.
    * **Log-to-Rule Integration:** Right-click any log entry to instantly populate the rule request form.
    * **Reverse Object Lookup:** Automatically translates raw log IP addresses into known Firewall Object names for better readability.
* **🚀 Direct Commit:** Administrators can trigger and monitor Firewall Commits directly from the web interface.
* **🐳 Robust Dockerization:** Includes a production-ready `update.sh` script for seamless git updates and cache-clearing builds.

---

## 🛠️ Architecture

* **Backend:** Python Flask (Web Server + REST API).
* **Database:** SQLite (Stored persistently via Docker Volumes).
* **Background Tasks:** Threaded Syslog Listener for high-concurrency UDP processing.
* **Frontend:** TailwindCSS & Optimized Vanilla JS (custom live-search components).
* **Integration:** `pan-os-python` SDK for reliable firewall communication.

---

## ⚙️ Configuration (.env)

Create a `.env` file in the root directory. This file holds all secrets and configuration.

**⚠️ Important:** Never commit this file to Git!

```ini
# --- Firewall Settings ---
FW_IP=YOUR_FW_IP_HERE
PA_API_KEY="YOUR_LONG_API_KEY_HERE"

# --- Emergency Local Access (Break-Glass) ---
LOCAL_ADMIN_USER=admin
LOCAL_ADMIN_PASS=P@ssw0rd

# --- Web App Settings ---
FLASK_SECRET_KEY="SuperSecretKey!@#"
SYSLOG_PORT=514

# --- LDAP / Active Directory Settings ---
LDAP_SERVER=LDAP_SERVER_IP
LDAP_DOMAIN=DOMAIN.NAME
LDAP_BASE_DN="DC=DOMAIN,DC=NAME"
LDAP_ADMIN_GROUP="CN=netadmin,CN=Users,DC=DOMAIN,DC=NAME"
LDAP_USER_GROUP="CN=netlow,CN=Users,DC=DOMAIN,DC=NAME"

```
---

## 🚀 Installation & Deployment

### 1. Clone the Repository

```bash
git clone [https://github.com/haimskira/net-ops-v2.git](https://github.com/haimskira/net-ops-v2.git)
cd net-ops-v2

```

### 2. Prepare Data Directory

Create a directory to store the database persistently (so data survives restarts):

```bash
mkdir -p data

```

### 3. Setup Environment

Create your `.env` file (see Configuration section above) and paste your credentials.

### 4. Run with Docker

We have included a helper script to pull the latest changes, build, and run the container safely.

```bash
chmod +x docker/update.sh
./docker/update.sh

```

Alternatively, run manually via Docker Compose:

```bash
docker-compose -f docker/docker-compose.yml up -d --build

```

---

## 🔌 Palo Alto Configuration (For Live Logs)

To see **Live Traffic Logs**, you must configure your Palo Alto Firewall to send Syslogs to this server.

1. Go to **Device > Server Profiles > Syslog**.
2. Add a new server:
* **Name:** NetOps-Server
* **Server:** `<Your_Docker_Host_IP>`
* **Port:** `514`
* **Format:** BSD (Standard)
* **Transport:** UDP


3. Go to **Log Settings** and add this profile to "Traffic" logs.
4. **Commit** changes.

---

## 📂 Project Structure

```text
net-ops-v2/
├── app.py                 # Main application entry point
├── config.py              # Configuration loader
├── .env                   # Environment variables (GitIgnored)
├── data/                  # (Production) Persistent DB storage
├── docker/                # Docker configuration files
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   └── update.sh          # Deployment script
├── managers/              # Business logic (FW, Data, Models)
├── routes/                # Flask Blueprints (API endpoints)
└── templates/             # HTML Frontend

```

---

## 🛡️ Security Notes

* **Database:** In production (Docker), the `netops.db` is stored in the `./data` folder on the host machine. Ensure this folder is backed up regularly.
* **Git:** The `.gitignore` file is configured to exclude `*.db`, `.env`, and `data/` to prevent sensitive data leakage.

---

**Developed by NetOps Team & Gemini Pro ;) ** 🚀

---
