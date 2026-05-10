[![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)](https://portswigger.net/burp)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)](https://github.com/VermaOps/SQLiHunter/releases)
[![Java](https://img.shields.io/badge/Java-21+-red)](https://www.oracle.com/java/)

# SQLiHunter: Automated SQL Injection Detection for Burp Suite

## 📋 Table of Contents
- [Overview](#overview)
- [Key Highlights](#key-highlights)
- [Deep Burp Suite Integration](#deep-burp-suite-integration)
  - [Multi-Tab Interface](#multi-tab-interface)
  - [Traffic Capture & Analysis](#traffic-capture--analysis)
  - [Smart Parameter Detection](#smart-parameter-detection)
  - [AI-Powered Reporting](#ai-powered-reporting)
- [SQL Injection Detection](#sql-injection-detection)
  - [Payload Types](#payload-types)
  - [Database Support](#database-support)
  - [Detection Methods](#detection-methods)
- [Configuration Options](#configuration-options)
- [SQLiHunter Visual Architecture](#sqlihunter-visual-architecture)
- [Installation Guide](#installation-guide)
  - [Prerequisites](#prerequisites)
  - [Method 1: Pre-compiled Installation](#method-1-pre-compiled-installation-recommended)
  - [Method 2: Custom Build Installation](#method-2-custom-build-installation)
- [Key Features](#key-features)
  - [Security & Privacy](#security--privacy)
  - [Productivity Tools](#productivity-tools)
  - [Performance](#performance)
  - [Advanced Features](#advanced-features)
- [Usage Workflow](#usage-workflow)
  - [Basic Scan](#basic-scan)
  - [Context Menu Operations](#context-menu-operations)
  - [Results Analysis](#results-analysis)
  - [AI Report Generation](#ai-report-generation)
- [Screenshots](#screenshots)
- [Support Development](#support-development)
- [Report Issues](#report-issues)
- [Community & Feedback](#community--feedback)

## Overview

**SQLiHunter** is a professional-grade Burp Suite extension that automates SQL injection vulnerability detection. Designed for penetration testers and bug bounty hunters, this tool intelligently injects payloads, analyzes responses, and delivers actionable findings with confidence scoring — all within Burp Suite's interface.

## Key Highlights

- **Comprehensive SQLi Detection** — Error-based, Boolean-based, Time-based, and Union-based
- **Multi-Database Support** — MySQL, PostgreSQL, MSSQL, Oracle, and Generic
- **Smart Parameter Extraction** — URL, Body, JSON (nested), XML, Headers, Cookies
- **AI-Powered Report Generation** — Professional bug bounty reports via Ollama/OpenAI/Claude
- **Real-time Traffic Monitoring** — Capture Proxy and Repeater traffic automatically
- **Smart Auto-Scan** — Automatically scan captured requests based on rules
- **HTTP Method Filtering** — GET, POST, PUT, PATCH, DELETE, OPTIONS
- **Context Menu Integration** — Right-click any request to scan instantly
- **Kill Switch** — Emergency stop for all scanning activities
- **Version Update Checking** — Automatic GitHub release monitoring
- **Exclusions** — Exclude specific files and parameters based on rules

## Deep Burp Suite Integration

### Multi-Tab Interface
SQLiHunter provides a complete workspace within Burp Suite:

- **SQLi Runner Tab**: Split-pane view with API Traffic (left) and Findings (right)
- **Settings Tab**: Comprehensive configuration panel for all scan parameters
- **API Traffic Panel**: Shows all captured HTTP requests with method filtering
- **Findings Panel**: Sortable table of discovered vulnerabilities with severity coloring
- **Detail Views**: Request/Response viewers with evidence highlighting

### Traffic Capture & Analysis
- **Proxy History Integration**: Automatically captures requests from Burp Proxy
- **Repeater Support**: Captures manual testing requests from Repeater tool and/or Burp Proxy
- **Scope Awareness**: Respects Burp's project scope settings
- **Path Filtering**: Exclude static files automatically (e.g. JS, CSS, images etc. based on applied rules)
- **Method Filtering**: Selective scanning by HTTP method (GET, POST, PUT, PATCH, DELETE)

### Smart Parameter Detection
- **URL Parameters**: Query string injection points
- **Body Parameters**: Form-encoded POST data
- **JSON Body**: Supports nested objects and arrays (e.g., `user.address.zip`)
- **XML Body**: Tag content and attribute injection
- **Headers**: Configurable interesting headers (Origin, X-Forwarded-For, etc.)
- **Cookies**: Cookie parameter injection
- **Hidden Parameter Discovery**: Tests common parameter names (desc, order, sort, etc.)

### AI-Powered Reporting
SQLiHunter integrates with multiple AI providers for professional report generation:

| Provider | Type | Privacy |
|----------|------|---------|
| **Ollama** | Local LLM | Complete privacy, no data leaves your machine |
| **OpenAI** | Cloud API | Requires API key |
| **Claude** | Cloud API | Requires API key |

**AI Features:**
- One-click report generation with finding evidence
- Bug bounty style vulnerability reports
- Professional remediation recommendations
- Persistent conversation history across sessions
- Multi-turn analysis and refinement

## SQL Injection Detection

### Payload Types

| Type | Description | Confidence |
|------|-------------|------------|
| **Error-Based** | Trigger database error messages | High (85%+) |
| **Boolean-Based** | Compare response differences | Medium-High (70%+) |
| **Time-Based** | Measure response delays | High (80%+) |
| **Union-Based** | Extract data via UNION queries | Medium (60%+) |
| **Custom** | User-defined payloads | Configurable |

### Database Support

| Database | Error Payloads | Time Payloads | Boolean Payloads | Union Payloads |
|----------|---------------|---------------|------------------|----------------|
| **MySQL** | EXTRACTVALUE, UPDATEXML, GTID_SUBSET | SLEEP() | AND/OR inference | @@version |
| **PostgreSQL** | CAST errors | PG_SLEEP() | CASE inference | version() |
| **MSSQL** | CONVERT errors | WAITFOR DELAY | CASE inference | @@VERSION |
| **Oracle** | CTXSYS.DRITHSX.SN | DBMS_LOCK.SLEEP | AND/OR inference | banner FROM v$version |
| **Generic** | Quote syntax | SLEEP attempt | AND/OR inference | UNION SELECT NULL |

### Detection Methods

**Error-Based Detection:**
- Matches 20+ SQL error signatures (case-insensitive)
- SQL context validation (checks for keywords like "line", "column", "near")
- False positive reduction for JSON API errors

**Boolean-Based Detection:**
- Status code comparison
- Response length differential (absolute + percentage)
- Keyword appearance/disappearance (welcome, error, success, etc.)

**Time-Based Detection:**
- Configurable sleep duration (3-30 seconds)
- Multiplier threshold vs baseline (0-20×)
- Confidence reduction for slow baselines (>3 seconds)

**Union-Based Detection:**
- Multi-column NULL enumeration (1-5 columns)
- Database version string extraction
- Version fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle)

## Configuration Options

### Scan Mode
| Setting | Description |
|---------|-------------|
| **Automated Mode** | Uses all enabled payload types with database-specific exploitation |
| **Custom Mode** | Only uses user-defined payloads (bypasses automated payloads) |

### Payload Types (Automated Mode)
- Error-Based (default: ON)
- Boolean-Based (default: ON)
- Time-Based (default: ON)
- Union-Based (default: OFF — noisier)

### Target Areas
- URL Parameters (default: ON)
- Body Parameters (default: ON)
- JSON Body (default: ON)
- XML Body (default: ON)
- HTTP Headers (default: OFF — can be noisy)
- Cookies (default: OFF)
- Hidden Parameter Discovery (default: ON)

### Rate Limiting
- Request Delay: 0-10000ms (default: 200ms)
- Request Timeout: 1000-60000ms (default: 10000ms)

### Detection Thresholds
- Minimum Confidence Score: 0-100 (default: 0 — shows all findings)
- Timing Ratio Threshold: 0-20× baseline (default: 0 — disabled)
- Sleep Duration: 3-30 seconds (default: 6 seconds)

### HTTP Method Filtering
- GET, POST, PUT, PATCH, DELETE (all default: ON)
- Exclude OPTIONS (default: ON)

### Traffic Sources
- Proxy History (default: ON)
- Scope Filter (default: ON)
- Repeater (default: ON)

### Exclusions
- Parameter names (csrf, token, __viewstate, _wpnonce)
- URL path patterns (static files: .js, .css, .png, etc.)
- Custom regex patterns supported

### AI Configuration
| Provider | Endpoint | Default Model |
|----------|----------|---------------|
| Ollama | http://localhost:11434 | qwen2.5-coder:7b |
| OpenAI | https://api.openai.com | gpt-3.5-turbo |
| Claude | https://api.anthropic.com | claude-3-haiku-20240307 |

## SQLiHunter Visual Architecture
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Burp Suite Professional                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Proxy     │  │  Repeater   │  │  Intruder   │  │   Extensions Tab    │ │
│  │  History    │  │             │  │             │  │   "SQLiRunner"      │ │
│  └──────┬──────┘  └──────┬──────┘  └─────────────┘  └──────────┬──────────┘ │
└─────────┼────────────────┼─────────────────────────────────────┼────────────┘
          │                │                                       │
          ▼                ▼                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SQLiHunter Extension v1.0.0                          │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         Traffic Capture Layer                         │  │
│  │  ┌─────────────────────┐      ┌─────────────────────────────────┐    │  │
│  │  │ ProxyResponseHigh-  │      │   RepeaterCaptureHandler        │    │  │
│  │  │ lighter             │      │   (HttpHandler)                  │    │  │
│  │  │ (ProxyResponse      │      │   - Filters Repeater traffic     │    │  │
│  │  │  Handler)           │      │   - Captures raw bytes           │    │  │
│  │  │ - Monitors Proxy    │      │   - Respects scope/path filters  │    │  │
│  │  │ - Highlights SQL    │      └───────────────┬─────────────────┘    │  │
│  │  │   errors            │                      │                       │  │
│  │  └─────────┬───────────┘                      │                       │  │
│  └────────────┼──────────────────────────────────┼───────────────────────┘  │
│               │                                  │                           │
│               └──────────────┬───────────────────┘                           │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ApiTrafficModel (Thread-safe Store)              │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  CopyOnWriteArrayList<ApiTrafficEntry>                          │  │  │
│  │  │  - id, host, method, url, statusCode, responseLength            │  │  │
│  │  │  - rawRequest (ByteArray), rawResponse (ByteArray)              │  │  │
│  │  │  - timestamp (HH:mm:ss)                                         │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│          ┌───────────────────────┼───────────────────────┐                  │
│          │                       │                       │                  │
│          ▼                       ▼                       ▼                  │
│  ┌───────────────┐      ┌────────────────┐      ┌────────────────┐         │
│  │ ApiTraffic    │      │  ScanEngine    │      │ ResultsModel   │         │
│  │ Panel (UI)    │      │  (Async)       │      │ (Thread-safe)  │         │
│  │               │      │                │      │                │         │
│  │ - JTable with │      │ ┌────────────┐ │      │ - CopyOnWrite- │         │
│  │   Traffic     │      │ │ Parameter  │ │      │   ArrayList    │         │
│  │ - Burp Native │◄─────│ │ Extractor  │ │      │ - Filter by    │         │
│  │   Editors     │      │ └─────┬──────┘ │      │   trafficId    │         │
│  │ - Method      │      │       │        │      │ - Listener     │         │
│  │   Filtering   │      │ ┌─────▼──────┐ │      │   pattern      │         │
│  │ - Auto-scan   │      │ │ Payload    │ │      └───────┬────────┘         │
│  │   trigger     │      │ │ Builder    │ │              │                  │
│  └───────────────┘      │ └─────┬──────┘ │              │                  │
│                         │       │        │              │                  │
│                         │ ┌─────▼──────┐ │              │                  │
│                         │ │ Request    │ │              │                  │
│                         │ │ Mutator    │ │              │                  │
│                         │ └─────┬──────┘ │              │                  │
│                         │       │        │              │                  │
│                         │ ┌─────▼──────┐ │              │                  │
│                         │ │ Response   │ │              │                  │
│                         │ │ Analyzer   │ │              │                  │
│                         │ └───────────┘ │              │                  │
│                         └───────┬────────┘              │                  │
│                                 │                       │                  │
│                                 ▼                       ▼                  │
│                         ┌────────────────────────────────────┐             │
│                         │         ScanFinding                │             │
│                         │  - url, method, paramName          │             │
│                         │  - payloadUsed, payloadType        │             │
│                         │  - confidenceScore (0-100)         │             │
│                         │  - severity (HIGH/MEDIUM/LOW/INFO) │             │
│                         │  - rawRequest/rawResponse          │             │
│                         │  - evidenceSummary                 │             │
│                         └────────────────────────────────────┘             │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                           UI Layer                                     │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐    │  │
│  │  │   ResultsPanel  │  │  SettingsPanel  │  │    MainTab          │    │  │
│  │  │                 │  │                 │  │                     │    │  │
│  │  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────────┐ │    │  │
│  │  │ │ Findings    │ │  │ │ AI Config   │ │  │ │ SQLi Runner     │ │    │  │
│  │  │ │ Table       │ │  │ │ - Provider  │ │  │ │ (SplitPane)     │ │    │  │
│  │  │ │ - Severity  │ │  │ │ - Endpoint  │ │  │ │ - Traffic       │ │    │  │
│  │  │ │   coloring  │ │  │ │ - API Key   │ │  │ │ - Findings      │ │    │  │
│  │  │ │ - Sorting   │ │  │ │ - Model     │ │  │ └─────────────────┘ │    │  │
│  │  │ └─────────────┘ │  │ │ - Test      │ │  │ ┌─────────────────┐ │    │  │
│  │  │ ┌─────────────┐ │  │ │   Connect   │ │  │ │ Settings Tab    │ │    │  │
│  │  │ │ Detail Tabs │ │  │ └─────────────┘ │  │ │ - Scan Config   │ │    │  │
│  │  │ │ - Evidence  │ │  │ ┌─────────────┐ │  │ │ - Exclusions    │ │    │  │
│  │  │ │ - Request   │ │  │ │ Scan Config │ │  │ │ - AI Settings   │ │    │  │
│  │  │ │ - Response  │ │  │ │ - Payloads  │ │  │ └─────────────────┘ │    │  │
│  │  │ │ - Ask AI    │ │  │ │ - Targets   │ │  │ ┌─────────────────┐ │    │  │
│  │  │ └─────────────┘ │  │ │ - Methods   │ │  │ │ Help Tab        │ │    │  │
│  │  └────────┬────────┘  │ └─────────────┘ │  │ └─────────────────┘ │    │  │
│  └───────────┼──────────────────────────────┘  └─────────────────────┘    │  │
│              │                                                            │  │
│              ▼                                                            │  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                          AI Provider Layer                            │  │
│  │                                                                        │  │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │  │
│  │  │  Ollama     │    │   OpenAI    │    │   Claude    │                │  │
│  │  │  Provider   │    │  Provider   │    │  Provider   │                │  │
│  │  │             │    │             │    │             │                │  │
│  │  │ - Local API │    │ - Cloud API │    │ - Cloud API │                │  │
│  │  │ - No API    │    │ - Bearer    │    │ - x-api-key │                │  │
│  │  │   key       │    │   token     │    │   header    │                │  │
│  │  │ - /api/     │    │ - /v1/chat/ │    │ - /v1/      │                │  │
│  │  │   generate  │    │   complet-  │    │   messages  │                │  │
│  │  │ - /api/tags │    │   ions      │    │             │                │  │
│  │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                │  │
│  └─────────┼──────────────────┼──────────────────┼───────────────────────┘  │
│            │                  │                  │                          │
└────────────┼──────────────────┼──────────────────┼──────────────────────────┘
             │                  │                  │
             ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Ollama HTTP API (localhost:11434)                        │
│                    OpenAI API (api.openai.com)                              │
│                    Claude API (api.anthropic.com)                           │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Large Language Model                                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Ollama: qwen2.5-coder:7b, llama2, mistral, etc.                     │  │
│  │  OpenAI: gpt-3.5-turbo, gpt-4, gpt-4o                                │  │
│  │  Claude: claude-3-haiku, claude-3-sonnet, claude-3-opus              │  │
│  │                                                                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  ✓ Professional vulnerability report generation                │  │  │
│  │  │  ✓ Bug bounty style write-ups                                   │  │  │
│  │  │  ✓ Remediation recommendations                                  │  │  │
│  │  │  ✓ Multi-turn analysis with context retention                   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘

## Installation Guide
### Prerequisites
- **Burp Suite**: Professional or Community Edition (2026+)
- **Java**: OpenJDK 21 or later
- **Ollama (Optional)**: For local AI reporting
  ```bash
  # Install Ollama from https://ollama.com
  ollama pull qwen2.5-coder:7b
  ollama serve
  ```
- **API Keys (Optional)**: For OpenAI or Claude integration. API keys are not stored anywhere persistantly for security reasons.

### Method 1: Pre-compiled Installation (Recommended)

1. **Download**: Get `SQLiHunter.jar` from the [Releases page](https://github.com/VermaOps/SQLiHunter/releases)

2. **Install in Burp**:
   ```
   Burp Suite → Extender → Extensions
   Click "Add" → Select the JAR file
   Ensure Java is selected as extension type
   ```

3. **Configure**: Go to "Settings" tab and adjust scan parameters

### Method 2: Custom Build Installation

```bash
# Clone repository
git clone https://github.com/VermaOps/SQLiHunter.git
cd SQLiHunter

# Edit the provided build script and run it
chmod +x build.sh
./build.sh
```

4. **Install**: Load the generated JAR from `target/` directory into Burp

## Key Features

### Security & Privacy
- **Local Processing**: Optional Ollama integration keeps data on your machine
- **Header Redaction**: Automatic redaction of sensitive headers before AI processing
- **Scope Respect**: Honors Burp's project scope settings
- **No Unauthorized Requests**: Scans only user-approved traffic

### Productivity Tools
- **Auto-Scan**: Automatically scan captured requests based on rules
- **Batch Scanning**: Right-click multiple requests for bulk analysis
- **Findings Filtering**: Filter by traffic entry to correlate findings
- **Report Export**: Copy findings to clipboard in professional format
- **AI Report Generation**: One-click professional vulnerability reports

### Performance
- **Multi-threaded Scanning**: Concurrent request processing (configurable)
- **Smart Baseline Cache**: Reuses baseline responses for efficiency
- **Configurable Delays**: Rate limiting to avoid overloading target domain
- **Kill Switch**: Emergency stop for all scanning activities immediately
- **Cancel Support**: Stop ongoing scans immediately

### Advanced Features
- **Database Fingerprinting**: Automatic DBMS detection via payload responses
- **JSON Path Injection**: Supports nested JSON parameters (e.g., `user.address.zip`)
- **XML Attribute Injection**: Tests XML attributes for injection
- **Hidden Parameter Discovery**: Automatically tests common parameter names
- **Update Checking**: Automatic GitHub release monitoring
- **Custom Payloads**: User-defined payloads for specific scenarios

## Usage Workflow

### Basic Scan
1. **Capture Traffic**: Browse target application normally
2. **View Traffic**: Check "SQLi Runner" tab to see captured requests
3. **Auto-Scan**: Requests are automatically scanned based on settings
4. **Review Findings**: Results appear in the Findings panel

### Context Menu Operations
1. **Right-Click Request**: Anywhere in Burp (Proxy, Repeater, Site Map)
2. **Select "SQLi Hunter" → "Scan This Request"**
3. **Monitor Progress**: Status indicator shows scanning activity
4. **View Results**: Findings appear in the SQLi Runner tab

### Results Analysis
1. **Select Finding**: Click any row in the Findings table
2. **Review Evidence**: View detection evidence in the detail panel
3. **Inspect Request/Response**: See exactly what was sent and received
4. **Filter by Traffic**: Click traffic entries to see related findings

### AI Report Generation
1. **Select Finding**: Click a finding in the Results table
2. **Switch to "Ask AI" Tab**: Access AI assistant
3. **Auto-Populated Prompt**: Evidence automatically inserted
4. **Click Send**: Generate professional vulnerability report
5. **Refine**: Continue conversation for detailed analysis

## Screenshots

| | | |
|:---:|:---:|:---:|
| *Main Dashboard* | *Traffic Analysis* | *Findings Table* |
| *Settings Panel* | *AI Report Generation* | *Evidence Details* |

## Support Development

If SQLiHunter helps your security testing, consider supporting the project:

**⭐ Star the Repository**: Show your support by starring the project on GitHub!

**Support Links**:
- 💰 **PayPal**: [PayPal](https://www.paypal.com/ncp/payment/7Y3836GETVF94)

Your support helps maintain the project, add new analyzers, and improve AI integration.

---

## Report Issues

Found a bug? Have a feature request?

- **Bug Reports**: Include Burp version, Java version, and reproduction steps
- **Feature Requests**: Describe use case and expected behavior
- **Security Issues**: Report privately via GitHub Security Advisory

**Issue Tracker**: [GitHub Issues](https://github.com/VermaOps/SQLiHunter/issues)

## Community & Feedback

Community feedback is welcome. SQLiHunter is designed for professional security testing — use responsibly and only on authorized targets.

---

<div align="center">

**Built with ❤️ by [VermaOps](https://github.com/VermaOps)**

[![GitHub Stars](https://img.shields.io/github/stars/VermaOps/SQLiHunter?style=social)](https://github.com/VermaOps/SQLiHunter/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/VermaOps/SQLiHunter)](https://github.com/VermaOps/SQLiHunter/issues)
[![GitHub Forks](https://img.shields.io/github/forks/VermaOps/SQLiHunter?style=social)](https://github.com/VermaOps/SQLiHunter/network/members)

**⭐ Star this repo if you find it useful!**

</div>
