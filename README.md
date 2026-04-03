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
