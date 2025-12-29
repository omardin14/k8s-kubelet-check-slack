# Kubernetes Kubelet Security Check with Slack Notifications

A complete Kubernetes solution that scans cluster nodes for kubelet security configuration issues and automatically sends formatted security reports to Slack.

![Status](https://img.shields.io/badge/status-ready-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📑 Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#-architecture)
- [Deployment Options](#-deployment-options)
- [Slack Setup](#-slack-app-setup)
- [What You'll Get](#-what-youll-get-in-slack)
- [Configuration](#-configuration)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Cleanup](#-cleanup)

---

## 🚀 Quick Start

### Prerequisites

- Docker installed
- Minikube running (for Kubernetes)
- Slack app configured with bot token
- Docker Hub account (for public deployment)
- **OpenAI API key** (optional - for AI-powered risk analysis)

### Configuration Setup

The application uses a `config.yaml` file for configuration.

1. **Copy the example config:**
```bash
cp config.yaml.example config.yaml
```

2. **Edit `config.yaml` with your values:**
```yaml
slack:
  bot_token: "xoxb-your-actual-token"
  channel: "#kubelet-check"

docker:
  username: "your-dockerhub-username"

openai:
  api_key: "sk-your-openai-key"  # Optional
  enabled: true
```

3. **Note:** `config.yaml` is in `.gitignore` and will NOT be committed

### Fastest Deployment

**1. Setup Configuration:**
```bash
# Create config file from example
make config

# Edit config.yaml with your secrets
# - slack.bot_token
# - docker.username  
# - openai.api_key (optional)
```

**2. Deploy:**
```bash
# Build and push to Docker Hub
make docker-login
make docker-build  # Uses docker.username from config.yaml

# Setup Kubernetes
make setup-minikube

# Deploy (uses secrets from config.yaml)
make helm-deploy
```

**3. Check Results:**
```bash
make logs
```

---

## ✨ Features

### 🔐 Kubelet Security Scanning
- Scans all cluster nodes for kubelet security configuration
- Checks if anonymous authentication is enabled (security risk)
- Checks if authorization mode is set to "AlwaysAllow" (security risk)
- Checks if readonly port is enabled (should be disabled/0)
- Tests kubelet port accessibility (default port 10250)
- Tests readonly port accessibility (port 10255)
- **Checks metrics endpoint security** - Verifies `/metrics` endpoint is not accessible without authentication
- **Version vulnerability scanning** - Checks kubelet version against known CVEs
- **Passed security checks reporting** - Shows which security measures are properly configured
- Identifies nodes with security misconfigurations
- Risk level assessment (CRITICAL/WARNING/HEALTHY)

### 🤖 AI-Powered Analysis (Optional)
- **OpenAI integration** for intelligent risk assessment
- Explains security risks and business impact
- Provides prioritized remediation recommendations
- Estimates fix time for each issue
- Identifies attack vectors and potential exploits

### 📊 Rich Reporting
- **Slack Messages**: Formatted reports with status, statistics, and recommendations
- **Color-Coded Status**: 🔴 Critical, ⚠️ Warning, ✅ Healthy
- **Security Checks Passed**: ✅ Highlights properly configured security measures
- **Node Details**: Full breakdown of issues per node with passed checks
- **Port Checks**: Detailed port accessibility information
- **Version Information**: Kubelet version and vulnerability status
- **HTML Reports**: Downloadable detailed HTML reports with interactive sections

### 🔒 Security
- Non-privileged containers
- Read-only filesystem where possible
- Minimal RBAC permissions (only what's needed)
- Secrets excluded from Docker images
- Kubernetes Secrets for sensitive data

---

## 🏗️ Architecture

The application consists of two containers running in a Kubernetes Job:

1. **Kubelet Scanner Container**: 
   - Scans cluster nodes for kubelet configuration
   - Tests kubelet port accessibility (default port 10250, readonly port 10255)
   - Checks metrics endpoint security
   - Extracts kubelet version and checks for known vulnerabilities
   - Identifies security issues and passed security checks
   - Writes results to shared volume
2. **Slack Notifier Container**: Monitors for scan results and sends formatted reports to Slack

```
┌─────────────────────────────────────────┐
│  Kubernetes Job                         │
│  ┌───────────────────────────────────┐  │
│  │  Kubelet Scanner Container         │  │
│  │  - Scans nodes                     │  │
│  │  - Tests kubelet ports             │  │
│  │  - Writes results to shared vol   │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Slack Notifier Container         │  │
│  │  - Monitors shared volume         │  │
│  │  - Sends to Slack                 │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Shared Volume (emptyDir)         │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 📦 Deployment Options

### Option 1: Helm (Recommended)

**One-time Job:**
```bash
make helm-deploy
```

**Scheduled CronJob:**
```bash
make helm-deploy-cron
# Or with custom schedule:
make helm-deploy-cron CRON_SCHEDULE="0 */6 * * *"  # Every 6 hours
```

### Option 2: kubectl/kustomize

**One-time Job:**
```bash
make deploy
```

**Scheduled CronJob:**
```bash
make deploy-cron
```

---

## 🔧 Slack App Setup

### Step 1: Create Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **"Create an App"** → **"From scratch"**
3. Name: `kubelet-check-slack`
4. Choose your workspace
5. Click **"Create App"**

### Step 2: Configure Bot Permissions

1. Go to **Features → OAuth & Permissions**
2. Scroll to **"Bot Token Scopes"** and add:
   ```
   - app_mentions:read
   - channels:join
   - channels:read       ← Required for file uploads!
   - chat:write
   - files:write
   ```
3. Click **"Install to Workspace"**
4. **Copy the Bot User OAuth Token** (starts with `xoxb-`)

### Step 3: Add Bot to Channel

```bash
# In your Slack channel (e.g., #kubelet-check)
/invite @kubelet-check-slack
```

### Step 4: Test

```bash
export SLACK_BOT_TOKEN=xoxb-your-token-here
make test
```

✅ **You should see test messages in your Slack channel!**

---

## 📊 What You'll Get in Slack

### 1. 📱 Formatted Slack Message

A rich message with:
- **Overall Status**: ✅ HEALTHY / ⚠️ WARNING / 🔴 CRITICAL
- **Summary Statistics**: Total nodes, nodes with issues, healthy nodes, critical issues count
- **Security Checks Passed**: ✅ Shows which security measures are properly configured
- **Critical Issues**: High-risk nodes highlighted
- **Node Breakdown**: Status for each node with risk level, issues count, and passed checks
- **Port Status**: Shows port accessibility and authentication requirements
- **Version Information**: Kubelet version and vulnerability status
- **Recommendations**: Actionable security improvements
- **AI Analysis**: (if enabled) Detailed risk assessment

---

## ⚙️ Configuration

### Primary Method: config.yaml (Recommended)

1. **Create config file:**
```bash
make config  # Creates config.yaml from config.yaml.example
```

2. **Edit config.yaml:**
```yaml
slack:
  bot_token: "xoxb-your-token-here"
  channel: "#kubelet-check"

docker:
  username: "your-dockerhub-username"

openai:
  api_key: "sk-your-key"  # Optional
  enabled: true
```

3. **Benefits:**
- All secrets in one file
- Version control excluded (`.gitignore`)
- Easy to manage

### Alternative: Environment Variables

You can still use environment variables (they work as fallback):
| Variable | Default | Description |
|----------|---------|-------------|
| `SLACK_BOT_TOKEN` | Required | Bot OAuth token |
| `SLACK_CHANNEL` | `#kubelet-check` | Target channel |
| `OPENAI_API_KEY` | Optional | For AI-powered security analysis |

### 🤖 AI Analysis Configuration

**Enable AI analysis:**

```bash
# Set OpenAI API key
export OPENAI_API_KEY="sk-..."

# Or set via Kubernetes secret
make openai-secret OPENAI_API_KEY=sk-your-key
```

**AI analysis provides:**
- ✅ Overall risk assessment with color-coded severity badges
- 🎯 Top 3-5 critical security concerns with business impact
- 💡 **WHY IT'S DANGEROUS** - Attack vectors and potential exploits
- 🔍 **EXPLANATION** - What attackers could do with these vulnerabilities
- 📋 Prioritized remediation roadmap with time estimates

**Disable AI analysis:**
- Simply omit the `OPENAI_API_KEY` environment variable
- The system will skip AI analysis gracefully
- All other features continue to work normally

---

## 🔐 Security

This application requires RBAC read permissions to scan cluster nodes. The following security measures are implemented:

### Security Measures

#### 1. Non-Privileged Container

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

**Benefits:**
- Container runs as non-root user (UID 1000)
- No privilege escalation allowed
- All Linux capabilities dropped
- Follows principle of least privilege

#### 2. Minimal RBAC Permissions

The scanner requires read permissions for node scanning:
- `nodes`: `get`, `list`

**Benefits:**
- No write permissions
- Cannot modify cluster state
- Read-only access to node information

#### 3. Secrets Management

- Secrets excluded from Docker image via `.dockerignore`
- Kubernetes Secrets for Slack token and OpenAI API key
- Environment variable injection at runtime
- `config.yaml` excluded from Git (`.gitignore`)

---

## 🐛 Troubleshooting

### Common Issues

**1. "channel_not_found" error**
```bash
# Invite bot to channel
/invite @kubelet-check-slack

# Verify token
curl -H "Authorization: Bearer xoxb-your-token" \
  https://slack.com/api/auth.test
```

**2. "missing_scope" error**
- Add required scopes in OAuth & Permissions
- Reinstall the app after adding scopes

**3. Job fails to start**
```bash
# Check minikube
minikube status
minikube start

# Verify image
minikube image ls | grep kubelet-check-slack

# Load image if missing
make build
```

**4. No notifications in Slack**
```bash
# Check notifier logs
kubectl logs job/kubelet-check-scan -n kubelet-check -c slack-notifier

# Verify secret
kubectl get secret slack-credentials -n kubelet-check -o yaml

# Test token
make test
```

**5. No nodes found or port checks fail**
```bash
# Verify RBAC permissions
kubectl auth can-i list nodes --as=system:serviceaccount:kubelet-check:kubelet-check-sa

# Check scanner logs
kubectl logs job/kubelet-check-scan -n kubelet-check -c kubelet-scanner

# Note: Port checks may fail if nodes are not accessible from the pod
# This is expected in some network configurations
```

### Debug Commands

```bash
# View all resources
kubectl get all -n kubelet-check

# Describe job
kubectl describe job kubelet-check-scan -n kubelet-check

# Check secret
kubectl get secret slack-credentials -n kubelet-check

# Test Slack locally
export SLACK_BOT_TOKEN=xoxb-your-token
make test
```

---

## 🧹 Cleanup

### Remove Deployment Resources

```bash
# Kubernetes deployment
make clean

# Helm deployment
make helm-clean

# Both
make clean && make helm-clean
```

### Complete Cleanup

```bash
# Remove all resources
make clean
make helm-clean

# Remove Docker images
docker rmi kubelet-check-slack:latest

# Remove namespace
kubectl delete namespace kubelet-check
```

---

## 📚 Project Structure

```
├── src/                          # Source code
│   ├── slack_app/                # Slack integration
│   │   ├── client.py            # Slack API client
│   │   ├── formatter.py         # Message formatting
│   │   └── notifier.py          # Notification logic
│   ├── kubelet_scanner/         # Kubelet scanning
│   │   ├── scanner.py           # Kubelet scanner
│   │   └── analyzer.py          # Result analysis
│   ├── utils/                    # Utilities
│   │   ├── config.py             # Configuration
│   │   └── logger.py             # Logging setup
│   ├── app.py                   # Main application
│   ├── main.py                  # Entry point
│   ├── requirements.txt         # Python dependencies
│   └── Dockerfile               # Container image
├── k8s/                          # Kubernetes manifests
│   ├── namespace.yaml            # Namespace definition
│   ├── rbac.yaml                # RBAC configuration
│   ├── kubelet-check-job.yaml   # Job definition
│   ├── kubelet-check-cronjob.yaml # CronJob definition
│   └── kustomization.yaml       # Kustomize config
├── helm/                         # Helm chart
│   └── kubelet-check-slack/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── Makefile                      # Project commands
└── README.md                     # This file
```

---

## 🛠️ Available Commands

See `make help` for all available commands, or check the Makefile.

**Key commands:**
- `make config` - Create config.yaml from example
- `make install` - Install Python dependencies
- `make test` - Test Slack connection locally
- `make build` - Build Docker image
- `make docker-build` - Build and push to Docker Hub
- `make helm-deploy` - Deploy using Helm
- `make logs` - View application logs
- `make status` - Check deployment status
- `make clean` - Clean up resources

---

## 📄 License

MIT License - See LICENSE file for details.

---

**Need help?** Check the [Troubleshooting](#-troubleshooting) section or open an issue on GitHub.

