#!/usr/bin/env bash
# samsung-fw.sh — repo-local, production-grade, fully automatic Samsung firmware script
# EXAMPLES:
#   ./samsung-fw.sh --model SM-S928B --region THL --identity 355655434305341 --flash-keep
#   ./samsung-fw.sh --model SM-S928B --region THL --identity R5CXXXXXXX --flash-wipe
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# ---- Repo-local layout ----
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${REPO_DIR}/bin"
VENV_DIR="${REPO_DIR}/.venv"
VENDOR_DIR="${REPO_DIR}/vendor"
SAMLOADER_DIR="${VENDOR_DIR}/samloader3"
FW_DIR="${REPO_DIR}/firmware"
LOG_DIR="${REPO_DIR}/logs"

# ---- Sources you requested ----
ODIN_URL="https://github.com/volcom0x/OdinV4/releases/download/v1.0/odin.zip"
SAMLOADER_SSH="git@github.com:volcom0x/samloader3.git"
SAMLOADER_HTTPS="https://github.com/volcom0x/samloader3.git"

# ---- CLI args ----
MODEL=""; REGION=""; IDENTITY=""; VERSION=""
FLASH_MODE=""         # keep|wipe
DEVICE=""             # odin4 -d path
KEEP_FILES="0"
NO_CACHE="1"
FALLBACK_EUX="0"

say(){ printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
die(){ printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
mask_id(){ local s="${1:-}"; local d="${s//[^0-9]/}"; [[ ${#d} -ge 6 ]] && echo "${d:0:3}***${d: -2}" || echo "***"; }

usage(){
  cat <<USAGE
Usage:
  $0 --model SM-XXXX --region XXX --identity 15DIGITS_OR_SN --flash-keep|--flash-wipe [options]

Required:
  --model     e.g., SM-S928B
  --region    e.g., THL or EUX
  --identity  IMEI (15 digits) or Serial (S/N)

One of:
  --flash-keep  Use HOME_CSC (no wipe)
  --flash-wipe  Use CSC (factory reset)

Optional:
  --version      Force a specific version string (AP/CSC/CP/BL path). If omitted, auto-discover via FUS.
  --device       Explicit odin4 device path (see: sudo bin/odin4 -l)
  --keep-files   Retain firmware artifacts after a successful flash (default: delete)
  --no-cache     Force fresh download from FUS (default: on)
  --fallback-eux Retry with EUX if initial model/region/identity is rejected by FUS
USAGE
}

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) MODEL="${2:-}"; shift 2;;
    --region) REGION="${2:-}"; shift 2;;
    --identity) IDENTITY="${2:-}"; shift 2;;
    --version) VERSION="${2:-}"; shift 2;;
    --flash-keep) FLASH_MODE="keep"; shift;;
    --flash-wipe) FLASH_MODE="wipe"; shift;;
    --device) DEVICE="${2:-}"; shift 2;;
    --keep-files) KEEP_FILES="1"; shift;;
    --no-cache) NO_CACHE="1"; shift;;
    --fallback-eux) FALLBACK_EUX="1"; shift;;
    --help|-h) usage; exit 0;;
    *) die "Unknown arg: $1 (see --help)";;
  esac
done

[[ -z "$MODEL" || -z "$REGION" || -z "$IDENTITY" ]] && { usage; exit 1; }
[[ "$FLASH_MODE" != "keep" && "$FLASH_MODE" != "wipe" ]] && die "Choose exactly one: --flash-keep OR --flash-wipe"

# ---- Pre-flight ----
need python3; need git; need unzip; need curl
mkdir -p "${BIN_DIR}" "${VENDOR_DIR}" "${FW_DIR}" "${LOG_DIR}"
free_gb() { df -Pk "${FW_DIR}" | awk 'NR==2{printf "%.0f", ($4*1024)/(1024*1024*1024)}'; }
[[ "$(free_gb)" -lt 20 ]] && warn "Low free space at ${FW_DIR} (<20 GiB). Firmware can be ~18–20 GiB."

# cleanup for temp files
TMPFILES=()
cleanup(){ for f in "${TMPFILES[@]:-}"; do [[ -e "$f" ]] && rm -f "$f" || true; done; }
trap cleanup EXIT

# ---- venv (PEP-668 safe) ----
if [[ ! -d "${VENV_DIR}" ]]; then
  say "Creating repo-local virtualenv: ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"
python -m pip --disable-pip-version-check -q install --upgrade pip setuptools wheel

# ---- samloader3 (SSH → HTTPS), then install ----
if [[ ! -d "${SAMLOADER_DIR}" ]]; then
  say "Cloning samloader3 via SSH… (${SAMLOADER_SSH})"
  set +e
  git clone --depth=1 "${SAMLOADER_SSH}" "${SAMLOADER_DIR}" 2>/dev/null
  RC=$?; set -e
  if [[ $RC -ne 0 ]]; then
    warn "SSH clone failed; falling back to HTTPS."
    git clone --depth=1 "${SAMLOADER_HTTPS}" "${SAMLOADER_DIR}"
  fi
fi
say "Installing samloader3 + runtime deps…"
python -m pip -q install -e "${SAMLOADER_DIR}" requests rich typer cryptography pycryptodome

# ---- Odin4 (Linux CLI) ----
ODIN4="${BIN_DIR}/odin4"
if [[ ! -x "${ODIN4}" ]]; then
  say "Downloading Odin4 from release…"
  ZIP="$(mktemp -t odin4-XXXXXX.zip)"; TMPFILES+=("$ZIP")
  curl -fsSL "${ODIN_URL}" -o "${ZIP}" || die "Failed to download Odin4 zip."
  unzip -o "${ZIP}" odin4 -d "${BIN_DIR}" >/dev/null
  chmod +x "${ODIN4}"
fi

# ---- Helpers ----
log_file(){ local pfx="$1"; date +"${LOG_DIR}/${pfx}-%Y%m%d-%H%M%S.log"; }
have_glob(){ compgen -G "$1" >/dev/null 2>&1; }  # true if pattern matches any files
first_match(){ compgen -G "$1" | head -n1; }     # prints first match or empty

# Normalize weird ZIP names (handles "*.zip." and "*.zip.*", but ignores "*.zip.enc4")
normalize_zip_names(){
  shopt -s nullglob
  # case 1: "*.zip."  → "*.zip"
  for f in "${FW_DIR}"/*.zip.; do
    mv -f -- "$f" "${f%.}" || true
  done
  # case 2: "*.zip.*" (but not .enc4) → strip trailing extra extension after .zip
  for f in "${FW_DIR}"/*.zip.*; do
    [[ "$f" == *.zip.enc4 ]] && continue
    mv -f -- "$f" "${f%.*}" || true
  done
  shopt -u nullglob
}

# Extract the newest firmware archive with bsdtar if present (ZIP64-safe), else unzip
extract_firmware_zip(){
  shopt -s nullglob
  local candidates=( "${FW_DIR}"/*.zip "${FW_DIR}"/*.zip.* "${FW_DIR}"/*.zip. )
  # Re-check after normalization
  if ((${#candidates[@]}==0)); then
    normalize_zip_names
    candidates=( "${FW_DIR}"/*.zip "${FW_DIR}"/*.zip.* "${FW_DIR}"/*.zip. )
  fi
  # pick newest by mtime
  local zipf=""
  if ((${#candidates[@]}>0)); then
    zipf="$(ls -1t "${candidates[@]}" 2>/dev/null | head -n1 || true)"
  fi
  shopt -u nullglob
  [[ -n "$zipf" ]] || return 0

  say "Extracting firmware archive → Odin files…"
  if command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$zipf" -C "${FW_DIR}"
  else
    unzip -o "$zipf" -d "${FW_DIR}" >/dev/null
  fi
}

sl3_shell(){
  local model="$1" region="$2" identity="$3"; shift 3
  local script=""; for c in "$@"; do script+="${c}\n"; done; script+="exit\n"
  local masked; masked="$(mask_id "$identity")"
  local LOG; LOG="$(log_file samloader3)"
  say "Talking to FUS as ${model}/${region} (id:${masked})…"
  set +e
  local out
  out="$({ python -m samloader3 -M "${model}" -R "${region}" -I "${identity}" <<< "$(echo -e "$script")"; } 2>&1)"
  local rc=$?; set -e
  out="${out//${identity}/${masked}}"
  printf "%s\n" "$out" > "${LOG}"
  [[ $rc -ne 0 ]] && echo "::samloader3_error::" && echo "$out" && return 1
  echo "$out"
  return 0
}

discover_version(){
  # samloader3 `list -l -q` prints latest version string in AP/CSC/CP/BL form
  local out; out="$(sl3_shell "$MODEL" "$REGION" "$IDENTITY" "list -l -q")" || return 1
  grep -Eo '[A-Z0-9]{5,}/[A-Z0-9]{5,}/[A-Z0-9]{5,}/[A-Z0-9]{5,}' <<< "$out" | head -n1
}

download_and_decrypt(){
  local version="$1"; local nocache="$2"
  local cmd='download -o "'"${FW_DIR}"'"'
  [[ "$nocache" == "1" ]] && cmd+=' --no-cache'
  cmd+=' --decrypt "'${version}'"'
  sl3_shell "$MODEL" "$REGION" "$IDENTITY" "$cmd"
}

explicit_decrypt_if_needed(){
  # If only enc4 exists, decrypt explicitly: decrypt -v "$version" "/path/firmware.zip.enc4"
  local version="$1"
  if have_glob "${FW_DIR}/*.zip.enc4"; then
    local enc4; enc4="$(first_match "${FW_DIR}/*.zip.enc4")"
    say "Explicit decrypting enc4 → ZIP via samloader3…"
    sl3_shell "$MODEL" "$REGION" "$IDENTITY" "decrypt -v \"${version}\" \"${enc4}\"" >/dev/null || return 1
  fi
  return 0
}

finalize_odin_files(){
  normalize_zip_names
  extract_firmware_zip

  # sanity: ensure .tar.md5 exist
  local ok=1
  have_glob "${FW_DIR}/BL_*.tar.md5" || ok=0
  have_glob "${FW_DIR}/AP_*.tar.md5" || ok=0
  have_glob "${FW_DIR}/CP_*.tar.md5" || ok=0
  if [[ "$FLASH_MODE" == "keep" ]]; then
    have_glob "${FW_DIR}/HOME_CSC_*.tar.md5" || ok=0
  else
    have_glob "${FW_DIR}/CSC_*.tar.md5" || ok=0
  fi
  if [[ $ok -ne 1 ]]; then
    ls -lah "${FW_DIR}" || true
    die "Odin files not present after decrypt. See latest log in ${LOG_DIR} (samloader3-*.log)."
  fi
}

# ---- Version resolution ----
if [[ -z "${VERSION}" ]]; then
  VERSION="$(discover_version)" || {
    if [[ "${FALLBACK_EUX}" == "1" ]]; then
      warn "FUS refused ${MODEL}/${REGION}; retrying with EUX…"
      REGION="EUX"
      VERSION="$(discover_version)" || die "Could not discover version via FUS (even EUX)."
    else
      die "Could not discover version via FUS. Use --fallback-eux or provide --version."
    fi
  }
  say "Latest version: ${VERSION}"
else
  say "Using provided version: ${VERSION}"
fi

# ---- Download & decrypt ----
say "Downloading & decrypting to ${FW_DIR} …"
download_and_decrypt "${VERSION}" "${NO_CACHE}" >/dev/null || {
  if [[ "${FALLBACK_EUX}" == "1" && "${REGION}" != "EUX" ]]; then
    warn "Retrying with EUX…"
    REGION="EUX"
    download_and_decrypt "${VERSION}" "${NO_CACHE}" >/dev/null || die "FUS download failed (also EUX)."
  else
    die "FUS download failed."
  fi
}

# If .tar.md5 still absent, try explicit decrypt then finalize
explicit_decrypt_if_needed "${VERSION}" || true
finalize_odin_files

# ---- Resolve paths SAFELY (no array indexing) ----
BL_FILE="$(first_match "${FW_DIR}/BL_*.tar.md5" || true)"; [[ -n "${BL_FILE}" ]] || die "BL file missing"
AP_FILE="$(first_match "${FW_DIR}/AP_*.tar.md5" || true)"; [[ -n "${AP_FILE}" ]] || die "AP file missing"
CP_FILE="$(first_match "${FW_DIR}/CP_*.tar.md5" || true)"; [[ -n "${CP_FILE}" ]] || die "CP file missing"
if [[ "$FLASH_MODE" == "keep" ]]; then
  CSC_FILE="$(first_match "${FW_DIR}/HOME_CSC_*.tar.md5" || true)"; [[ -n "${CSC_FILE}" ]] || die "HOME_CSC file missing"
else
  CSC_FILE="$(first_match "${FW_DIR}/CSC_*.tar.md5" || true)"; [[ -n "${CSC_FILE}" ]] || die "CSC file missing"
fi

# Bootloader binary hint (U#) to discourage BL downgrades; Odin4 blocks anyway with SW REV CHECK FAIL.
if [[ -n "${AP_FILE}" ]]; then
  if BLHINT="$(grep -Eo '[US][0-9]' <<< "$(basename "${AP_FILE}")" | head -n1)"; then
    say "Bootloader binary hint: ${BLHINT/ /} — do NOT attempt BL downgrades."
  fi
fi

# USB driver quirk mitigation (Linux)
sudo rmmod cdc_acm >/dev/null 2>&1 || true

# Wait for device in Download Mode (VolUp+VolDown while plugging USB; confirm VolUp). Odin4 lists devices with -l.
say "Put device in Download (Odin) Mode. Waiting for odin4 to see a device…"
for i in {1..60}; do
  if "${ODIN4}" -l 2>/dev/null | grep -q '/dev/bus/usb/'; then
    break
  fi
  sleep 2
done

# Build & run odin4 command (documented flags: -b BL -a AP -c CP -s CSC/HOME_CSC).
ODIN_CMD=( "${ODIN4}" -b "${BL_FILE}" -a "${AP_FILE}" -c "${CP_FILE}" -s "${CSC_FILE}" )
[[ -n "${DEVICE}" ]] && ODIN_CMD+=( -d "${DEVICE}" )

LOG="$(log_file odin4)"
say "Flashing with Odin4… (log: ${LOG})"
set +e
sudo "${ODIN_CMD[@]}" | tee "${LOG}"
RC="${PIPESTATUS[0]}"
set -e
[[ "${RC}" -ne 0 ]] && die "Odin4 failed (see ${LOG})"

say "Flash complete."
if [[ "${KEEP_FILES}" != "1" ]]; then
  say "Cleaning firmware artifacts…"
  rm -f "${REPO_DIR}"/*.zip. "${FW_DIR}"/*.tar.md5 "${FW_DIR}"/*.zip "${FW_DIR}"/*.zip.* "${FW_DIR}"/*.zip. "${FW_DIR}"/*.enc4 2>/dev/null || true
fi
say "Done."
