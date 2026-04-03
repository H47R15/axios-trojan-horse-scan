#!/usr/bin/env bash
# ============================================================================
# AXIOS SUPPLY CHAIN ATTACK - FULL SYSTEM SCANNER
# Malicious versions: axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
# C2: sfrclak[.]com / 142.11.206.73:8000
# Attribution: UNC1069 (North Korea) - WAVESHAPER.V2 RAT
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FOUND_ISSUES=0
OS_TYPE="$(uname -s)"

AUTO_HARDEN=0
for arg in "$@"; do
    case "$arg" in
        --harden|--auto-harden)
            AUTO_HARDEN=1
            ;;
    esac
done

version_ge() {
    local v1="$1"
    local v2="$2"
    [[ "$(printf '%s\n%s\n' "$v2" "$v1" | sort -V | head -n1)" == "$v2" ]]
}

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  AXIOS SUPPLY CHAIN ATTACK - FULL SYSTEM SCANNER${NC}"
    echo -e "${CYAN}${BOLD}  CVE: axios@1.14.1 / 0.30.4 + plain-crypto-js${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "  OS detected: ${BOLD}${OS_TYPE}${NC}"
    echo -e "  Scan date:   ${BOLD}$(date)${NC}"
    if [[ $AUTO_HARDEN -eq 1 ]]; then
        echo -e "  Hardening:   ${BOLD}ENABLED${NC} (--harden)"
    else
        echo -e "  Hardening:   ${BOLD}disabled${NC} (use --harden to apply it)"
    fi
    echo ""
}

ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }
crit() { echo -e "  ${RED}🚨 $1${NC}"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }
info() { echo -e "  ${CYAN}ℹ️  $1${NC}"; }
section() { echo ""; echo -e "${BOLD}[$1]${NC}"; }

# ============================================================================
# 1. CHECK RAT ARTIFACTS ON DISK
# ============================================================================
check_rat_artifacts() {
    section "1/6 - RAT ARTIFACTS (malicious files on the system)"

    local rat_found=0

    # macOS RAT
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
            crit "macOS RAT FOUND: /Library/Caches/com.apple.act.mond"
            rat_found=1
        else
            ok "No macOS RAT found (/Library/Caches/com.apple.act.mond)"
        fi
        # Check LaunchDaemons/LaunchAgents for persistence
        for plist_dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
            if [[ -d "$plist_dir" ]]; then
                local suspicious
                suspicious=$(grep -rl "com.apple.act.mond\|sfrclak\|plain-crypto" "$plist_dir" 2>/dev/null || true)
                if [[ -n "$suspicious" ]]; then
                    crit "Suspicious persistence plist found: $suspicious"
                    rat_found=1
                fi
            fi
        done
    fi

    # Linux RAT
    if [[ "$OS_TYPE" == "Linux" ]]; then
        if [[ -f "/tmp/ld.py" ]]; then
            crit "Linux RAT FOUND: /tmp/ld.py"
            rat_found=1
        else
            ok "No Linux RAT found (/tmp/ld.py)"
        fi
        # Check crontab for persistence
        local cron_suspicious
        cron_suspicious=$(crontab -l 2>/dev/null | grep -i "ld\.py\|sfrclak\|plain-crypto" || true)
        if [[ -n "$cron_suspicious" ]]; then
            crit "Suspicious crontab entry: $cron_suspicious"
            rat_found=1
        fi
    fi

    # Windows (via WSL/Git Bash)
    if [[ -d "/mnt/c/ProgramData" ]]; then
        if [[ -f "/mnt/c/ProgramData/wt.exe" ]]; then
            crit "Windows RAT FOUND: C:\\ProgramData\\wt.exe"
            rat_found=1
        else
            ok "No Windows RAT found (C:\\ProgramData\\wt.exe)"
        fi
    fi

    if [[ $rat_found -eq 0 ]]; then
        ok "No RAT artifacts detected on the system"
    fi
}

# ============================================================================
# 2. SCAN ALL node_modules FOR plain-crypto-js
# ============================================================================
check_plain_crypto_js() {
    section "2/6 - SCAN plain-crypto-js (malicious dependency)"

    local search_dirs=("$HOME" "/opt" "/var" "/srv" "/tmp")
    local found_any=0

    info "Scanning filesystem for plain-crypto-js (this may take a while)..."

    for dir in "${search_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue
        while IFS= read -r found_path; do
            crit "plain-crypto-js FOUND: $found_path"
            found_any=1
        done < <(find "$dir" -maxdepth 10 -type d -name "plain-crypto-js" \
            -path "*/node_modules/*" 2>/dev/null || true)
    done

    if [[ $found_any -eq 0 ]]; then
        ok "No plain-crypto-js instances found"
    fi
}

# ============================================================================
# 3. SCAN ALL PROJECTS FOR BAD AXIOS VERSIONS
# ============================================================================
check_axios_versions() {
    section "3/6 - SCAN AXIOS VERSIONS (1.14.1 and 0.30.4 = malicious)"

    local search_dirs=("$HOME" "/opt" "/var" "/srv")
    local found_bad=0
    local found_total=0

    info "Searching package-lock.json, yarn.lock, pnpm-lock.yaml, and node_modules for axios..."

    for dir in "${search_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue

        # Check package-lock.json files
        while IFS= read -r lockfile; do
            local bad_versions
            bad_versions=$(grep -o '"axios"[^}]*"version"[^"]*"[^"]*"' "$lockfile" 2>/dev/null | \
                grep -E '"(1\.14\.1|0\.30\.4)"' || true)
            if [[ -n "$bad_versions" ]]; then
                crit "MALICIOUS VERSION found in: $lockfile"
                echo -e "       ${RED}$bad_versions${NC}"
                found_bad=1
            fi
            found_total=$((found_total + 1))
        done < <(find "$dir" -maxdepth 8 -name "package-lock.json" \
            -not -path "*/node_modules/*" 2>/dev/null || true)

        # Check yarn.lock files
        while IFS= read -r lockfile; do
            if grep -q 'axios@.*1\.14\.1\|axios@.*0\.30\.4' "$lockfile" 2>/dev/null; then
                crit "MALICIOUS VERSION found in: $lockfile"
                found_bad=1
            fi
            found_total=$((found_total + 1))
        done < <(find "$dir" -maxdepth 8 -name "yarn.lock" \
            -not -path "*/node_modules/*" 2>/dev/null || true)

        # Check pnpm-lock.yaml files
        while IFS= read -r lockfile; do
            if grep -q 'axios@1\.14\.1\|axios@0\.30\.4' "$lockfile" 2>/dev/null; then
                crit "MALICIOUS VERSION found in: $lockfile"
                found_bad=1
            fi
            found_total=$((found_total + 1))
        done < <(find "$dir" -maxdepth 8 -name "pnpm-lock.yaml" \
            -not -path "*/node_modules/*" 2>/dev/null || true)
    done

    # Check installed node_modules package.json files
    for dir in "${search_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue
        while IFS= read -r pkgjson; do
            local pkg_version
            pkg_version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkgjson" 2>/dev/null | head -n1 | sed -E 's/.*"([^"]+)"/\1/' || true)
            if [[ "$pkg_version" == "1.14.1" || "$pkg_version" == "0.30.4" ]]; then
                crit "MALICIOUS AXIOS installed in node_modules: $pkgjson (version $pkg_version)"
                found_bad=1
            fi
        done < <(find "$dir" -maxdepth 10 -path "*/node_modules/axios/package.json" 2>/dev/null || true)
    done

    info "Scanned $found_total lockfiles"

    if [[ $found_bad -eq 0 ]]; then
        ok "No malicious axios versions found in lockfiles"
    fi

    # Also check globally installed
    if command -v npm &>/dev/null; then
        local global_axios
        global_axios=$(npm list -g axios 2>/dev/null | grep "axios@" || true)
        if echo "$global_axios" | grep -qE '1\.14\.1|0\.30\.4'; then
            crit "MALICIOUS AXIOS installed GLOBALLY: $global_axios"
        elif [[ -n "$global_axios" ]]; then
            ok "Global axios OK: $global_axios"
        else
            ok "No axios installed globally"
        fi
    fi
}

# ============================================================================
# 4. CHECK NETWORK CONNECTIONS TO C2
# ============================================================================
check_c2_connections() {
    section "4/6 - C2 CONNECTIONS (sfrclak.com / 142.11.206.73)"

    # Check active connections
    local c2_found=0

    if command -v ss &>/dev/null; then
        local c2_conn
        c2_conn=$(ss -tunp 2>/dev/null | grep -i "142.11.206.73\|sfrclak" || true)
        if [[ -n "$c2_conn" ]]; then
            crit "ACTIVE C2 CONNECTION: $c2_conn"
            c2_found=1
        fi
    elif command -v netstat &>/dev/null; then
        local c2_conn
        c2_conn=$(netstat -an 2>/dev/null | grep "142.11.206.73" || true)
        if [[ -n "$c2_conn" ]]; then
            crit "ACTIVE C2 CONNECTION: $c2_conn"
            c2_found=1
        fi
    fi

    # Check DNS cache / hosts
    if command -v dscacheutil &>/dev/null; then
        local dns_hit
        dns_hit=$(dscacheutil -cachedump 2>/dev/null | grep "sfrclak" || true)
        if [[ -n "$dns_hit" ]]; then
            warn "sfrclak.com found in DNS cache"
            c2_found=1
        fi
    fi

    # Check /etc/hosts
    if grep -qi "sfrclak" /etc/hosts 2>/dev/null; then
        warn "sfrclak.com found in /etc/hosts"
        c2_found=1
    fi

    if [[ $c2_found -eq 0 ]]; then
        ok "No C2 connections detected"
    fi
}

# ============================================================================
# 5. CHECK RUNNING PROCESSES
# ============================================================================
check_processes() {
    section "5/6 - SUSPICIOUS PROCESSES"

    local proc_found=0

    # macOS RAT process
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        if pgrep -f "com.apple.act.mond" &>/dev/null; then
            crit "Active macOS RAT process: com.apple.act.mond"
            proc_found=1
        fi
    fi

    # Linux RAT process
    if pgrep -f "ld\.py" &>/dev/null 2>&1; then
        local ld_procs
        ld_procs=$(pgrep -af "ld\.py" 2>/dev/null || true)
        if echo "$ld_procs" | grep -q "/tmp/ld.py"; then
            crit "Active Linux RAT process: $ld_procs"
            proc_found=1
        fi
    fi

    # Any process connecting to C2
    if command -v lsof &>/dev/null; then
        local c2_procs
        c2_procs=$(lsof -i @142.11.206.73 2>/dev/null || true)
        if [[ -n "$c2_procs" ]]; then
            crit "Process with C2 connection: $c2_procs"
            proc_found=1
        fi
    fi

    if [[ $proc_found -eq 0 ]]; then
        ok "No suspicious processes detected"
    fi
}

apply_npm_hardening() {
    if ! command -v npm &>/dev/null; then
        info "npm not installed — skipping hardening"
        return
    fi

    section "npm HARDENING"

    local npm_ver
    npm_ver=$(npm --version 2>/dev/null || echo "0.0.0")

    if npm config set ignore-scripts true >/dev/null 2>&1; then
        ok "Set ignore-scripts = true"
    else
        warn "Could not set ignore-scripts = true automatically"
    fi

    if version_ge "$npm_ver" "11.10.0"; then
        if npm config set min-release-age 3 >/dev/null 2>&1; then
            ok "Set min-release-age = 3"
        else
            warn "npm supports min-release-age but I could not set it"
        fi
    else
        info "npm $npm_ver does not support min-release-age (requires npm >= 11.10.0)"
    fi
}

# ============================================================================
# 6. CHECK npm CONFIGURATION
# ============================================================================
check_npm_config() {
    section "6/6 - npm CONFIGURATION"

    if ! command -v npm &>/dev/null; then
        info "npm not installed — skipping"
        return
    fi

    local npm_ver
    npm_ver=$(npm --version 2>/dev/null || echo "?")
    info "npm version: $npm_ver"

    # Check ignore-scripts
    local ignore_scripts
    ignore_scripts=$(npm config get ignore-scripts 2>/dev/null || echo "unknown")
    if [[ "$ignore_scripts" == "true" ]]; then
        ok "ignore-scripts = true (postinstall scripts blocked)"
    else
        warn "ignore-scripts = false — postinstall scripts run automatically"
        info "To apply it now: $0 --harden"
    fi

    # Check min-release-age only on supported npm versions
    if version_ge "$npm_ver" "11.10.0"; then
        local min_age
        min_age=$(npm config get min-release-age 2>/dev/null || echo "not set")
        if [[ "$min_age" != "not set" && "$min_age" != "undefined" && "$min_age" != "0" ]]; then
            ok "min-release-age = $min_age days (quarantine active)"
        else
            warn "min-release-age not configured — no quarantine for newly published packages"
            info "To apply it now: $0 --harden"
        fi
    else
        info "npm $npm_ver does not support min-release-age (requires npm >= 11.10.0)"
    fi
}

# ============================================================================
# MAIN
# ============================================================================
banner
if [[ $AUTO_HARDEN -eq 1 ]]; then
    apply_npm_hardening
fi
check_rat_artifacts
check_plain_crypto_js
check_axios_versions
check_c2_connections
check_processes
check_npm_config

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
if [[ $FOUND_ISSUES -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ✅ CLEAN SYSTEM — no indicators of compromise found${NC}"
else
    echo -e "${RED}${BOLD}  🚨 FOUND $FOUND_ISSUES WARNINGS / ISSUES — READ BELOW${NC}"
    echo ""
    echo -e "${YELLOW}  NOTE:${NC} npm config warnings != compromise."
    echo -e "${RED}  IF you found a RAT, plain-crypto-js, malicious axios installed, or C2 connections:${NC}"
    echo -e "  1. Disconnect the machine from the network"
    echo -e "  2. DO NOT try to clean it — rebuild from scratch"
    echo -e "  3. Rotate ALL credentials:"
    echo -e "     - npm tokens"
    echo -e "     - AWS/GCP/Azure keys"
    echo -e "     - SSH keys"
    echo -e "     - .env files secrets"
    echo -e "     - Database passwords"
    echo -e "     - CI/CD secrets"
    echo -e "  4. Block traffic to sfrclak.com / 142.11.206.73"
    echo -e "${YELLOW}  IF you only have npm config warnings:${NC}"
    echo -e "  - enable hardening with: $0 --harden"
    echo -e "  - rerun the scan inside your project directories"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
