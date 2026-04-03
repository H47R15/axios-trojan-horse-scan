# 🛡️ Axios & plain-crypto-js Security Scanner (macOS)

A lightweight Bash script to scan your macOS system for **known malicious versions** of:

- `axios`
- `plain-crypto-js`

This tool helps detect exposure to the **Axios supply chain attack** by scanning both:
- declared dependencies (`package.json`)
- installed dependencies (`node_modules`)

---

## 🚨 What It Detects

### Malicious Axios Versions
- `1.14.1` 
- `0.30.4`
- `0.30.0`

### Malicious plain-crypto-js Version
- `4.2.1`

---

## 🔍 What the Script Does

The script recursively scans your system (by default):

- `$HOME`
- `/opt`
- `/usr/local`
- `/var`
- `/srv`

### It performs 4 checks:

1. **Declared dependencies**
   - Scans all `package.json` files
   - Detects if `axios` or `plain-crypto-js` are declared

2. **Declared malicious dependency**
   - Specifically checks for `plain-crypto-js` references

3. **Installed dependencies (real risk)**
   - Scans `node_modules/axios/package.json`
   - Shows the actual installed version

4. **Installed malicious dependency**
   - Scans `node_modules/plain-crypto-js/package.json`

---

## ✅ Output Meaning

| Status        | Meaning |
|---------------|--------|
| ✅ OK         | Safe version |
| 🚨 ALERT      | Known malicious version |
| ⚠️ UNKNOWN    | Could not determine version |

---

## ⚡ Requirements

- macOS (or Linux-compatible environment)
- [`jq`](https://stedolan.github.io/jq/) (for JSON parsing)

Install jq:
```bash
brew install jq
```

---

## 🪟 Windows Usage (Git Bash / WSL)

A Windows-compatible scanner is provided as `windows-scan.sh`.

> ℹ️ This script is designed to run in **Git Bash** or **WSL** (Windows Subsystem for Linux), not in `cmd.exe`.

### 🔧 Requirements

- Git Bash **or** WSL
- `python3` **or** `jq`

Install jq (Git Bash):
```bash
pacman -S jq
```

Install jq (WSL Ubuntu):
```bash
sudo apt update && sudo apt install -y jq
```

---

## 🚀 How to Run (Windows)

### 1. Open Git Bash or WSL

Navigate to your project:

```bash
cd /path/to/your/project
```

### 2. Make script executable

```bash
chmod +x windows-scan.sh
```

### 3. Run the scan

```bash
./windows-scan.sh
```

---

## 🔍 What It Checks on Windows

- Scans common Windows-mounted paths:
  - `/c/Users`
  - `/c/Projects`
  - `/mnt/c/Users` (WSL)
- Detects:
  - malicious `axios` versions
  - malicious `plain-crypto-js`
- Checks installed `node_modules`
- Looks for known RAT file:
  - `C:\\ProgramData\\wt.exe`
- Checks active connection to:
  - `142.11.206.73`

---

## ⚠️ Notes (Windows)

- Results from `package.json` = declared dependencies (not always installed)
- Results from `node_modules` = actual installed code (**more important**)
- Run with elevated privileges if needed for full filesystem access

---

## 💡 Tip

For deeper Windows inspection, a native **PowerShell scanner (.ps1)** can provide more accurate system-level detection.
