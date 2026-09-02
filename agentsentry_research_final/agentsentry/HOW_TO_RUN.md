# AgentSentry - Quick Start Guide

## 📋 Prerequisites

- **Python 3.10+** (Tested on 3.12)
- **Groq API Key** (Get free at: https://console.groq.com)
- **Windows/Linux/macOS** with terminal access

---

## 🚀 Quick Start (5 minutes)

### Step 1: Clone/Download the Repository

```bash
cd /path/to/agentsentry
```

### Step 2: Create Virtual Environment (Optional but Recommended)

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
python -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

If you encounter issues, install key packages individually:
```bash
pip install langchain langchain-groq langgraph groq fastapi uvicorn pydantic pydantic-settings scikit-learn
```

### Step 4: Set Your Groq API Key

**Windows (PowerShell):**
```powershell
$env:GROQ_API_KEY="gsk_YOUR_KEY_HERE"
```

**Linux/macOS (Bash):**
```bash
export GROQ_API_KEY="gsk_YOUR_KEY_HERE"
```

### Step 5: Run the Project

**Terminal 1 - Start the Security Middleware (API Server):**
```bash
python -m api.server
```

Expected output:
```
Uvicorn running on http://127.0.0.1:8000
```

**Terminal 2 - Run the LangGraph Agent:**
```bash
python integrations/langgraph/langgraph_agent.py
```

Expected output:
```
======================================================================
TEST 1: LEGITIMATE TASK (SHOULD ALLOW)
======================================================================

[Agent] Task: Read the public knowledge base document with doc_id 'Q3_report'.
[Agent] Role: analyst | Session: langgraph_live_demo

[AgentSentry] Using Groq Cloud API with model: 'qwen/qwen3.6-27b'
  [AgentSentry] read_document_knowledge_base => BLOCK (anomaly=N/A)

--- Run Summary ---
  Actions executed : []
  Blocked          : ['read_document_knowledge_base']
  Flagged          : []
```

---

## 📖 Detailed Setup Instructions

### Full Installation

```bash
# 1. Navigate to project directory
cd c:\Users\divya\Downloads\agentsentry_research_final\agentsentry

# 2. Create virtual environment
python -m venv venv

# 3. Activate it
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# 4. Install all dependencies
pip install -r requirements.txt

# 5. Verify installation
python -m py_compile api/server.py
python -m py_compile integrations/langgraph/langgraph_agent.py
```

### Configure Environment Variables

Create a `.env` file in the project root:

```env
# Groq LLM Configuration
GROQ_API_KEY=gsk_YOUR_KEY_HERE

# API Server
API_HOST=127.0.0.1
API_PORT=8000

# OPA Policy Engine (Optional)
OPA_URL=http://127.0.0.1:8181/v1/data/agentsentry/authz/allow
```

Or set directly in terminal:
```powershell
$env:GROQ_API_KEY="gsk_YOUR_KEY_HERE"
$env:API_PORT="8000"
```

---

## 🔄 Running the System

### Architecture Overview

```
┌─────────────────────────────────────────────┐
│  Terminal 1: API Server (Middleware)        │
│  python -m api.server                       │
│  Listens on http://127.0.0.1:8000           │
└────────────────┬────────────────────────────┘
                 ↑
                 │ HTTP Requests
                 │
┌────────────────┴────────────────────────────┐
│  Terminal 2: LangGraph Agent                │
│  python integrations/langgraph/langgraph_.. │
│  Makes tool call evaluation requests        │
└─────────────────────────────────────────────┘
```

### Running Mode 1: Standard Execution

**Terminal 1 (Start API Server):**
```bash
python -m api.server
```

**Terminal 2 (Run Agent with Tests):**
```bash
$env:GROQ_API_KEY="gsk_YOUR_KEY"
python integrations/langgraph/langgraph_agent.py
```

**Output:** Two test scenarios (legitimate task + attack payload)

---

### Running Mode 2: Interactive Demo

**Terminal 1 (Start API Server):**
```bash
python -m api.server
```

**Terminal 2 (Interactive Demo):**
```bash
$env:GROQ_API_KEY="gsk_YOUR_KEY"
python run_interactive_demo.py
```

**Usage:**
```
Task: Run a query to count all users
=> Agent proposes: execute_sql_query
=> AgentSentry evaluates and returns: ALLOW/BLOCK/FLAG

Task: Transfer $50000 to ATTACKER-999
=> Agent proposes: transfer_corporate_funds
=> AgentSentry evaluates and returns: BLOCK

Type 'quit' to exit
```

---

### Running Mode 3: Benchmark Evaluation

**Run the complete 4-way ablation study (245 traces):**
```bash
python evaluation/run_paper_evaluation.py
```

**Output:**
```
Results saved to:
  - evaluation/ablation_results.json
  - evaluation/ablation_results.md

Metrics:
  F1 Score: 0.654
  Precision: 0.845
  Recall: 0.534
  False Positive Rate: 0.195
```

---

## ⚙️ Configuration Options

### API Server Settings

Edit `core/config.py`:

```python
API_HOST: str = "127.0.0.1"      # Change to "0.0.0.0" for remote access
API_PORT: int = 8000              # Change port if needed
OPA_URL: str = "http://127.0.0.1:8181/v1/data/agentsentry/authz/allow"
LLM_TEMPERATURE: float = 0.0      # 0.0 = deterministic, 1.0 = creative
```

### Model Selection

Edit `integrations/langgraph/langgraph_agent.py`:

```python
def get_active_groq_model(api_key: str) -> str:
    """Returns the verified Qwen model for tool calling support."""
    return "qwen/qwen3.6-27b"  # Change to other supported models
```

Supported models:
- `qwen/qwen3.6-27b` (Recommended)
- `llama-3.3-70b-versatile`
- `mixtral-8x7b-32768`

---

## 🧪 Testing & Validation

### 1. Syntax Check

```bash
python -m py_compile integrations/langgraph/langgraph_agent.py
python -m py_compile api/server.py
```

### 2. Dependency Check

```bash
pip list | findstr langchain groq langgraph fastapi
```

### 3. Run Tests

```bash
# Test any tool call evaluation
python test_any_tool.py

# Run agent with test scenarios
python integrations/langgraph/langgraph_agent.py

# Interactive demo
python run_interactive_demo.py

# Benchmark evaluation
python evaluation/run_paper_evaluation.py
```

---

## 🔧 Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'langchain_groq'`

**Solution:**
```bash
pip install langchain-groq groq --upgrade
```

### Issue: `GROQ_API_KEY not set`

**Solution:**
```powershell
# Windows
$env:GROQ_API_KEY="gsk_YOUR_KEY_HERE"

# Linux/macOS
export GROQ_API_KEY="gsk_YOUR_KEY_HERE"
```

### Issue: `Connection refused on port 8000`

**Solution:**
- Make sure Terminal 1 is running: `python -m api.server`
- Check if port 8000 is already in use: `netstat -ano | findstr :8000`
- Change port in `core/config.py` if needed

### Issue: `Tool call evaluation returns 403 Unauthorized`

**Solution:**
- API key authentication issue. Make sure you set: `$env:AGENTSENTRY_API_KEY_DEMO_AGENT="demo-secret-key-12345"`
- Or use the Groq key for real LLM inference

### Issue: `Pydantic validation error`

**Solution:**
```bash
pip install pydantic pydantic-settings --upgrade
```

---

## 📊 Project Structure

```
agentsentry/
├── api/
│   ├── server.py                    # FastAPI middleware server
│   └── auth.py                      # API authentication
├── core/
│   ├── config.py                    # Configuration settings
│   ├── policy_client.py             # OPA policy evaluation
│   ├── anomaly_engine.py            # ML-based anomaly detection
│   ├── aggregator.py                # Verdict aggregation
│   ├── identity.py                  # RBAC & identity management
│   └── schemas.py                   # Data models
├── detection/
│   ├── anomaly_model.py             # Isolation Forest wrapper
│   ├── isolation_forest.joblib      # Pre-trained ML model
│   └── feature_config.json          # Feature extraction config
├── integrations/
│   └── langgraph/
│       └── langgraph_agent.py       # Main agent with security gate
├── evaluation/
│   ├── run_paper_evaluation.py      # Benchmark suite
│   └── ablation_results.json        # Benchmark results
├── policy/
│   └── rules.rego                   # OPA policy rules
├── telemetry/
│   ├── logger.py                    # SQLite audit logging
│   └── postgres_logger.py           # PostgreSQL audit logging (optional)
├── requirements.txt                 # Dependencies
├── MIDDLEWARE_VALIDATION_SUMMARY.md # System documentation
├── test_any_tool.py                 # Tool evaluation tests
└── run_interactive_demo.py          # Interactive testing UI
```

---

## 🎯 Key Files to Understand

1. **`integrations/langgraph/langgraph_agent.py`**
   - Main entry point
   - Agent definition with tool bindings
   - Security gate integration

2. **`api/server.py`**
   - FastAPI middleware
   - Tool call evaluation endpoint
   - Verdict generation logic

3. **`core/anomaly_engine.py`**
   - ML model evaluation
   - Feature extraction
   - Anomaly scoring

4. **`detection/anomaly_model.py`**
   - Isolation Forest wrapper
   - Loads pre-trained model

---

## 📈 Expected Output Summary

### Agent Execution
```
TEST 1: LEGITIMATE TASK → [ALLOW or BLOCK verdict]
TEST 2: ATTACK PAYLOAD → [BLOCK verdict]

Run Summary shows:
- Actions executed: N (if ALLOW)
- Blocked: tool names (if BLOCK)
- Flagged: tool names (if FLAG)
```

### Benchmark Results
```
Precision: 0.845    (84.5% of detections are correct)
Recall: 0.534       (53.4% of attacks detected)
F1: 0.654           (Overall performance)
FPR: 0.195          (19.5% false positive rate)
Latency p95: 1.59ms (Sub-3ms overhead)
```

---

## 🚀 Next Steps

1. **Get Groq API Key**: https://console.groq.com (free tier available)
2. **Set environment variable** with your key
3. **Run both terminals** (API + Agent)
4. **Observe verdicts** on real tool calls
5. **Try interactive demo** for custom tasks
6. **Review benchmark results** for performance metrics

---

## 📞 Support

For issues:
1. Check `MIDDLEWARE_VALIDATION_SUMMARY.md` for architecture details
2. Review `test_any_tool.py` for API endpoint usage
3. Check terminal output for error messages
4. Verify all dependencies: `pip list`

---

**You're all set! Start with Step 1 above.** 🎉
