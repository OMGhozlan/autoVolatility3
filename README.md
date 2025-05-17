# ❄️ AutoVol – Automated Volatility 3 Framework

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Volatility 3](https://img.shields.io/badge/Volatility-3.x-success)](https://github.com/volatilityfoundation/volatility3)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-green)](https://hub.docker.com/)
[![Textual](https://img.shields.io/badge/Textual-TUI-red.svg)](https://github.com/Textualize/textual)

---

## 📌 Overview

Based on /Inspired by [carlospolop's autoVolatility](https://github.com/carlospolop/autoVolatility)
**AutoVol** is a modern Python 3-based memory forensics automation toolkit powered by **Volatility 3**.

It makes memory analysis faster, more interactive, and more forensic-friendly via:

✅ Plugin automation  
✅ JSON/HTML export  
✅ TUI Dashboard (Textual)  
✅ Rich logging with beautiful formatting  
✅ CPU + memory usage metrics per plugin  

---

## 💡 Key Features

- 🔍 Powered by **Volatility 3**
- 🧠 Supports powerful Volatility plugins
- ⚙️ Multi-threaded plugin execution
- 📤 Export in **JSON**, **HTML**, or **TXT**
- 📊 Built-in CPU + Memory usage tracking
- 👨‍💻 CLI and TUI modes
- 🐳 Fully Dockerized environment

---

## 📦 Requirements (for manual installation)

```bash
python 3.11+
pip install -r requirements.txt
```

**requirements.txt:**
```
textual
rich
pyfiglet
psutil
requests
```

---

## 📁 Project Structure

```
AutoVol/
├── autovol.py          # Main launcher (CLI)
├── executor.py         # Threaded plugin execution
├── dashboard.py        # Textual TUI dashboard
├── utils.py            # Utility libs and shared logic
├── requirements.txt    # Dependencies
├── Dockerfile          # Docker image
└── README.md           # This file
```

---

## 🖥️ Usage

### 🔧 Basic CLI

```bash
python autovol.py -f /path/to/image.raw -d ./output --all --format json
```

### 📊 With Textual TUI

```bash
python autovol.py -f /path/to/image.raw -d ./output --all --tui --format html
```

### 🔢 Custom Plugin Set

```bash
python autovol.py -f mem.raw -d ./out -c "windows.pslist,windows.malfind"
```

---

## 🐳 Docker Usage

### ⚙️ 1. Build the Docker Image

From the root directory:

```bash
docker build -t autovol .
```

---

### ▶️ 2. Run AutoVol (CLI Mode)

```bash
docker run --rm -it \
  -v $(pwd)/memdumps:/memdumps \
  -v $(pwd)/output:/output \
  autovol \
  python autovol.py -f /memdumps/image.raw -d /output --all --format json
```

---

### 🖥️ 3. Run AutoVol (Textual UI Mode)

```bash
docker run --rm -it \
  -v $(pwd)/memdumps:/memdumps \
  -v $(pwd)/output:/output \
  autovol \
  python autovol.py -f /memdumps/image.raw -d /output --tui --all
```

---

### 🧪 Sample Memory Dump Structure

```
memdumps/
└── profile-image1.raw
output/
└── will contain output/<plugin>/plugin.json
```

---

## ✨ Output Example

Each plugin output is saved like:

```
output/
└── windows.pslist/
    └── windows.pslist.json  # or .html or .txt
```

---

## 🔧 Developer/Contributor Guide

### 🧱 Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🧪 Run Locally

```bash
python autovol.py -f test.raw -d output --all --tui
```

---

## ✍️ Customization Tips

- 📀 Want web export? Add `Flask` or `FastAPI`
- 🧩 Want custom plugins? Extend `get_plugins()` in `utils.py`
- 📚 Want PDF reports? Convert HTML via `wkhtmltopdf`

---

## 🙋 FAQ

> 🟠 **Does this support Volatility 2.x?**  
🔻 No. AutoVol supports **Volatility 3 only** for modern plugin support & JSON/HTML exports.

> 🔵 **Can I specify how many threads?**  
✅ Yes: `--threads 4`

> 🔴 **Why should I use Textual mode?**  
It gives you a live dashboard with plugin status, memory/cpu usage, and rate of execution. Great for live ops/devs!

---

## 📜 License

MIT ©️ 2025

---

## 🌐 More Tools?

You may also like:
- [Volatility Foundation](https://www.volatilityfoundation.org/)
- [Textualize.io](https://www.textualize.io/)
- [Psutil GitHub](https://github.com/giampaolo/psutil)
