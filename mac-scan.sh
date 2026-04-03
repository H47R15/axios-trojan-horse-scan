#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BAD_VERSIONS=("1.14.1" "0.30.4" "0.30.0")
BAD_PLAIN_CRYPTO_VERSION="4.2.1"

SEARCH_DIRS=(
  "$HOME"
  "/opt"
  "/usr/local"
  "/var"
  "/srv"
)

is_bad_version() {
  local version="$1"
  for bad in "${BAD_VERSIONS[@]}"; do
    if [[ "$version" == "$bad" ]]; then
      return 0
    fi
  done
  return 1
}

print_status() {
  local version="$1"
  if is_bad_version "$version"; then
    printf "  ${RED}🚨 ALERT${NC}  %s\n" "$version"
  elif [[ -n "$version" && "$version" != "null" ]]; then
    printf "  ${GREEN}✅ OK${NC}     %s\n" "$version"
  else
    printf "  ${YELLOW}⚠️  UNKNOWN${NC} %s\n" "$version"
  fi
}

print_plain_crypto_status() {
  local version="$1"
  if [[ "$version" == "$BAD_PLAIN_CRYPTO_VERSION" ]]; then
    printf "  ${RED}🚨 ALERT${NC}  %s\n" "$version"
  elif [[ -n "$version" && "$version" != "null" ]]; then
    printf "  ${GREEN}✅ OK${NC}     %s\n" "$version"
  else
    printf "  ${YELLOW}⚠️  UNKNOWN${NC} %s\n" "$version"
  fi
}

scan_known_rat_artifacts() {
  echo
  echo -e "${BOLD}[1/5] Known RAT artifact check${NC}"

  if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
    echo
    echo -e "${CYAN}/Library/Caches/com.apple.act.mond${NC}"
    printf "  ${RED}🚨 ALERT${NC}  Known RAT artifact found on disk\n"
  else
    ok "No known RAT artifact found at /Library/Caches/com.apple.act.mond"
  fi
}

scan_declared_dependencies() {
  echo
  echo -e "${BOLD}[2/5] Declared axios versions in package.json files${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      found=1

      local dep_version=""
      dep_version="$(jq -r '
        .dependencies.axios //
        .devDependencies.axios //
        .optionalDependencies.axios //
        .peerDependencies.axios //
        empty
      ' "$file" 2>/dev/null | head -n1 || true)"

      [[ -n "$dep_version" ]] || continue

      echo
      echo -e "${CYAN}$file${NC}"
      print_status "$dep_version"
    done < <(
      find "$dir" \
        \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/Library/*" -o -path "*/.Trash/*" \) -prune \
        -o -name "package.json" -type f -print 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No package.json files found in search paths."
  fi
}

scan_declared_plain_crypto_dependencies() {
  echo
  echo -e "${BOLD}[3/5] Declared plain-crypto-js versions in package.json files${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      local dep_version=""
      dep_version="$(jq -r '
        .dependencies["plain-crypto-js"] //
        .devDependencies["plain-crypto-js"] //
        .optionalDependencies["plain-crypto-js"] //
        .peerDependencies["plain-crypto-js"] //
        empty
      ' "$file" 2>/dev/null | head -n1 || true)"

      [[ -n "$dep_version" ]] || continue
      found=1

      echo
      echo -e "${CYAN}$file${NC}"
      print_plain_crypto_status "$dep_version"
    done < <(
      find "$dir" \
        \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/Library/*" -o -path "*/.Trash/*" \) -prune \
        -o -name "package.json" -type f -print 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No package.json files declaring plain-crypto-js found in search paths."
  fi
}

scan_installed_node_modules() {
  echo
  echo -e "${BOLD}[4/5] Installed axios versions in node_modules${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      found=1

      local version=""
      version="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"

      echo
      echo -e "${CYAN}$file${NC}"
      print_status "$version"
    done < <(
      find "$dir" \
        -path "*/node_modules/axios/package.json" \
        -type f 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No installed axios copies found in node_modules."
  fi
}

scan_installed_plain_crypto_node_modules() {
  echo
  echo -e "${BOLD}[5/5] Installed plain-crypto-js versions in node_modules${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      found=1

      local version=""
      version="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"

      echo
      echo -e "${CYAN}$file${NC}"
      print_plain_crypto_status "$version"
    done < <(
      find "$dir" \
        -path "*/node_modules/plain-crypto-js/package.json" \
        -type f 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No installed plain-crypto-js copies found in node_modules."
  fi
}

main() {
  echo
  echo -e "${BOLD}=====================================================${NC}"
  echo -e "${BOLD} AXIOS MAC SCANNER${NC}"
  echo -e "${BOLD}=====================================================${NC}"
  echo " Scans declared and installed axios and plain-crypto-js versions"
  echo " Bad axios versions: 1.14.1, 0.30.4, 0.30.0"
  echo " Bad plain-crypto-js version: 4.2.1"
  echo

  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}jq is required but not installed.${NC}"
    echo "Install it with: brew install jq"
    exit 1
  fi

  scan_known_rat_artifacts
  scan_declared_dependencies
  scan_declared_plain_crypto_dependencies
  scan_installed_node_modules
  scan_installed_plain_crypto_node_modules

  echo
  echo -e "${BOLD}Done.${NC}"
  echo
}

main "$@"        empty
      ' "$file" 2>/dev/null | head -n1 || true)"

      [[ -n "$dep_version" ]] || continue

      echo
      echo -e "${CYAN}$file${NC}"
      print_status "$dep_version"
    done < <(
      find "$dir" \
        \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/Library/*" -o -path "*/.Trash/*" \) -prune \
        -o -name "package.json" -type f -print 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No package.json files found in search paths."
  fi
}

scan_declared_plain_crypto_dependencies() {
  echo
  echo -e "${BOLD}[2/4] Declared plain-crypto-js versions in package.json files${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      local dep_version=""
      dep_version="$(jq -r '
        .dependencies["plain-crypto-js"] //
        .devDependencies["plain-crypto-js"] //
        .optionalDependencies["plain-crypto-js"] //
        .peerDependencies["plain-crypto-js"] //
        empty
      ' "$file" 2>/dev/null | head -n1 || true)"

      [[ -n "$dep_version" ]] || continue
      found=1

      echo
      echo -e "${CYAN}$file${NC}"
      print_plain_crypto_status "$dep_version"
    done < <(
      find "$dir" \
        \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/Library/*" -o -path "*/.Trash/*" \) -prune \
        -o -name "package.json" -type f -print 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No package.json files declaring plain-crypto-js found in search paths."
  fi
}

scan_installed_node_modules() {
  echo
  echo -e "${BOLD}[2/2] Installed axios versions in node_modules${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      found=1

      local version=""
      version="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"

      echo
      echo -e "${CYAN}$file${NC}"
      print_status "$version"
    done < <(
      find "$dir" \
        -path "*/node_modules/axios/package.json" \
        -type f 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No installed axios copies found in node_modules."
  fi
}

scan_installed_plain_crypto_node_modules() {
  echo
  echo -e "${BOLD}[4/4] Installed plain-crypto-js versions in node_modules${NC}"

  local found=0

  for dir in "${SEARCH_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r file; do
      found=1

      local version=""
      version="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"

      echo
      echo -e "${CYAN}$file${NC}"
      print_plain_crypto_status "$version"
    done < <(
      find "$dir" \
        -path "*/node_modules/plain-crypto-js/package.json" \
        -type f 2>/dev/null
    )
  done

  if [[ "$found" -eq 0 ]]; then
    echo "  No installed plain-crypto-js copies found in node_modules."
  fi
}

main() {
  echo
  echo -e "${BOLD}=====================================================${NC}"
  echo -e "${BOLD} AXIOS MAC SCANNER${NC}"
  echo -e "${BOLD}=====================================================${NC}"
  echo " Scans declared and installed axios and plain-crypto-js versions"
  echo " Bad axios versions: 1.14.1, 0.30.4, 0.30.0"
  echo " Bad plain-crypto-js version: 4.2.1"
  echo

  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}jq is required but not installed.${NC}"
    echo "Install it with: brew install jq"
    exit 1
  fi

  scan_declared_dependencies
  scan_declared_plain_crypto_dependencies
  scan_installed_node_modules
  scan_installed_plain_crypto_node_modules

  echo
  echo -e "${BOLD}Done.${NC}"
  echo
}

main "$@"
