

#!/usr/bin/env bash
# =============================================================================
# AXIOS SUPPLY CHAIN ATTACK - WINDOWS SYSTEM SCANNER
# Malicious axios versions: 1.14.1, 0.30.4, 0.30.0
# Malicious plain-crypto-js version: 4.2.1
# C2: sfrclak[.]com / 142.11.206.73:8000
# =============================================================================

set -u
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BAD_AXIOS_VERSIONS=("1.14.1" "0.30.4" "0.30.0")
BAD_PLAIN_CRYPTO_VERSION="4.2.1"
FOUND_ISSUES=0

SEARCH_DIRS=()
for candidate in \
    "/c/Users" \
    "/c/Projects" \
    "/c/dev" \
    "/c/work" \
    "/c/src" \
    "/mnt/c/Users" \
    "/mnt/c/Projects" \
    "/mnt/c/dev" \
    "/mnt/c/work" \
    "/mnt/c/src"; do
    [[ -d "$candidate" ]] && SEARCH_DIRS+=("$candidate")
done

if [[ ${#SEARCH_DIRS[@]} -eq 0 ]]; then
    SEARCH_DIRS=(".")
fi

section() {
    echo ""
    echo -e "${BOLD}[ $1 ]${NC}"
}

ok() {
    echo -e "${GREEN}  ✅ $1${NC}"
}

warn() {
    echo -e "${YELLOW}  ⚠️  $1${NC}"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

crit() {
    echo -e "${RED}  🚨 $1${NC}"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

info() {
    echo -e "${CYAN}  ℹ️  $1${NC}"
}

version_in_bad_list() {
    local version="$1"
    local bad
    for bad in "${BAD_AXIOS_VERSIONS[@]}"; do
        [[ "$version" == "$bad" ]] && return 0
    done
    return 1
}

print_axios_status() {
    local version="$1"
    if version_in_bad_list "$version"; then
        crit "axios version $version"
    elif [[ -n "$version" && "$version" != "null" ]]; then
        ok "axios version $version"
    else
        warn "axios version unknown"
    fi
}

print_plain_crypto_status() {
    local version="$1"
    if [[ "$version" == "$BAD_PLAIN_CRYPTO_VERSION" ]]; then
        crit "plain-crypto-js version $version"
    elif [[ -n "$version" && "$version" != "null" ]]; then
        ok "plain-crypto-js version $version"
    else
        warn "plain-crypto-js version unknown"
    fi
}

read_json_field() {
    local file="$1"
    local query="$2"

    if command -v jq >/dev/null 2>&1; then
        jq -r "$query // empty" "$file" 2>/dev/null | head -n1
        return 0
    fi

    python3 - "$file" "$query" <<'PY' 2>/dev/null
import json, sys
path = sys.argv[1]
query = sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if query == '.version':
    value = data.get('version', '')
else:
    keys = [
        ('dependencies', 'axios'),
        ('devDependencies', 'axios'),
        ('optionalDependencies', 'axios'),
        ('peerDependencies', 'axios'),
        ('dependencies', 'plain-crypto-js'),
        ('devDependencies', 'plain-crypto-js'),
        ('optionalDependencies', 'plain-crypto-js'),
        ('peerDependencies', 'plain-crypto-js'),
    ]
    value = ''
    for section, dep in keys:
        section_data = data.get(section) or {}
        if dep in section_data:
            value = section_data[dep]
            break
print(value)
PY
}

banner() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} AXIOS SUPPLY CHAIN ATTACK - WINDOWS SYSTEM SCANNER${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo " OS target: Windows paths from Git Bash / WSL"
    echo " Scan date: $(date)"
    echo " Search roots: ${SEARCH_DIRS[*]}"
}

scan_declared_dependencies() {
    section "1/6 - Declared axios versions in package.json"

    local found=0
    local file dep_version

    for dir in "${SEARCH_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            dep_version="$(read_json_field "$file" '.dependencies.axios')"
            if [[ -z "$dep_version" ]]; then
                dep_version="$(python3 - "$file" <<'PY' 2>/dev/null
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
    sec = data.get(section) or {}
    if 'axios' in sec:
        print(sec['axios'])
        break
PY
)"
            fi
            [[ -n "$dep_version" ]] || continue
            found=1
            echo ""
            echo -e "${CYAN}$file${NC}"
            print_axios_status "$dep_version"
        done < <(find "$dir" \
            \( -path '*/node_modules/*' -o -path '*/.git/*' -o -path '*/AppData/Local/*' -o -path '*/AppData/Roaming/*' \) -prune \
            -o -name 'package.json' -type f -print 2>/dev/null)
    done

    [[ "$found" -eq 0 ]] && info "No package.json files declaring axios found"
}

scan_declared_plain_crypto() {
    section "2/6 - Declared plain-crypto-js versions in package.json"

    local found=0
    local file dep_version

    for dir in "${SEARCH_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            dep_version="$(python3 - "$file" <<'PY' 2>/dev/null
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
    sec = data.get(section) or {}
    if 'plain-crypto-js' in sec:
        print(sec['plain-crypto-js'])
        break
PY
)"
            [[ -n "$dep_version" ]] || continue
            found=1
            echo ""
            echo -e "${CYAN}$file${NC}"
            print_plain_crypto_status "$dep_version"
        done < <(find "$dir" \
            \( -path '*/node_modules/*' -o -path '*/.git/*' -o -path '*/AppData/Local/*' -o -path '*/AppData/Roaming/*' \) -prune \
            -o -name 'package.json' -type f -print 2>/dev/null)
    done

    [[ "$found" -eq 0 ]] && info "No package.json files declaring plain-crypto-js found"
}

scan_installed_axios() {
    section "3/6 - Installed axios versions in node_modules"

    local found=0
    local file version

    for dir in "${SEARCH_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            version="$(read_json_field "$file" '.version')"
            found=1
            echo ""
            echo -e "${CYAN}$file${NC}"
            print_axios_status "$version"
        done < <(find "$dir" -path '*/node_modules/axios/package.json' -type f 2>/dev/null)
    done

    [[ "$found" -eq 0 ]] && info "No installed axios copies found in node_modules"
}

scan_installed_plain_crypto() {
    section "4/6 - Installed plain-crypto-js versions in node_modules"

    local found=0
    local file version

    for dir in "${SEARCH_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            version="$(read_json_field "$file" '.version')"
            found=1
            echo ""
            echo -e "${CYAN}$file${NC}"
            print_plain_crypto_status "$version"
        done < <(find "$dir" -path '*/node_modules/plain-crypto-js/package.json' -type f 2>/dev/null)
    done

    [[ "$found" -eq 0 ]] && info "No installed plain-crypto-js copies found in node_modules"
}

scan_windows_rat_artifacts() {
    section "5/6 - Known RAT artifacts and C2 indicators"

    local found_any=0
    local win_root=""

    [[ -d "/c/ProgramData" ]] && win_root="/c"
    [[ -z "$win_root" && -d "/mnt/c/ProgramData" ]] && win_root="/mnt/c"

    if [[ -n "$win_root" ]]; then
        if [[ -f "$win_root/ProgramData/wt.exe" ]]; then
            crit "Known Windows RAT file found: $win_root/ProgramData/wt.exe"
            found_any=1
        else
            ok "No known Windows RAT file found at $win_root/ProgramData/wt.exe"
        fi
    else
        warn "Could not locate Windows C: drive mount (/c or /mnt/c)"
    fi

    if command -v powershell.exe >/dev/null 2>&1; then
        local net_out
        net_out="$(powershell.exe -NoProfile -Command "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { \$_.RemoteAddress -eq '142.11.206.73' } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table -HideTableHeaders" 2>/dev/null | tr -d '\r' || true)"
        if [[ -n "${net_out// /}" ]]; then
            crit "Active connection to 142.11.206.73 detected"
            echo "$net_out"
            found_any=1
        else
            ok "No active connection to 142.11.206.73 detected"
        fi
    else
        info "powershell.exe not available — skipping live TCP C2 check"
    fi

    if [[ "$found_any" -eq 0 ]]; then
        ok "No RAT artifacts or C2 indicators detected in Windows-specific checks"
    fi
}

scan_npm_config() {
    section "6/6 - npm configuration"

    if ! command -v npm >/dev/null 2>&1; then
        info "npm not installed — skipping"
        return
    fi

    local npm_ver ignore_scripts min_age
    npm_ver="$(npm --version 2>/dev/null || echo 'unknown')"
    info "npm version: $npm_ver"

    ignore_scripts="$(npm config get ignore-scripts 2>/dev/null || echo 'unknown')"
    if [[ "$ignore_scripts" == "true" ]]; then
        ok "ignore-scripts = true"
    else
        warn "ignore-scripts = false"
        info "Set it with: npm config set ignore-scripts true"
    fi

    min_age="$(npm config get min-release-age 2>/dev/null || echo 'unsupported')"
    if [[ "$min_age" == "unsupported" || "$min_age" == "undefined" || "$min_age" == "null" || "$min_age" == "0" ]]; then
        info "min-release-age not configured or not supported on this npm version"
    else
        ok "min-release-age = $min_age"
    fi
}

summary() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    if [[ "$FOUND_ISSUES" -eq 0 ]]; then
        echo -e "${GREEN}${BOLD} CLEAN SCAN — no known malicious versions or Windows indicators found${NC}"
    else
        echo -e "${YELLOW}${BOLD} Scan completed with $FOUND_ISSUES warning(s) / issue(s)${NC}"
        echo -e "${YELLOW} Review ALERT entries first. package.json hits are declared versions; node_modules hits are actual installed versions.${NC}"
    fi
    echo -e "${BOLD}============================================================${NC}"
    echo ""
}

main() {
    banner

    if ! command -v python3 >/dev/null 2>&1 && ! command -v jq >/dev/null 2>&1; then
        crit "This script requires jq or python3 to parse package.json files"
        summary
        exit 1
    fi

    scan_declared_dependencies
    scan_declared_plain_crypto
    scan_installed_axios
    scan_installed_plain_crypto
    scan_windows_rat_artifacts
    scan_npm_config
    summary
}

main "$@"
