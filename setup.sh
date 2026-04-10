#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  GhostNet Deception Infrastructure — Setup                               ║
# ║  Zero-trust honeypot deployment with AI-powered behavioural analysis     ║
# ╚════════════════════════════════════════════════════════════════════════════╝
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
GHOSTNET_VERSION="3.1.0"
BUILD_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo 'release')"

# ── PALETTE ───────────────────────────────────────────────────────────────────
B='\033[1m'          # bold
D='\033[2m'          # dim
I='\033[3m'          # italic
R='\033[0m'          # reset

C1='\033[38;2;0;220;220m'        # cyan — primary accent
C2='\033[38;2;0;110;120m'        # dark cyan — borders, lines
RD='\033[38;2;255;70;70m'        # red — alerts
WH='\033[38;2;240;240;250m'      # white — text
GR='\033[38;2;140;145;165m'      # grey — labels
MU='\033[38;2;75;80;100m'        # muted — secondary
GN='\033[38;2;0;220;130m'        # green — success
AM='\033[38;2;255;180;40m'       # amber — warnings
VT='\033[38;2;150;100;255m'      # violet — decorative

# ── TAGLINES ──────────────────────────────────────────────────────────────────
TAGS=(
  "Every attacker you log is a signature you own."
  "Traps armed. AI watching. Let them come."
  "The best honeypot is one that looks real."
  "Low-interaction for them. High-intelligence for you."
  "They scan your ports — you log every packet."
  "Capture. Analyse. Understand. Repeat."
  "What the attacker reveals, the AI remembers."
)
TAG="${TAGS[$((RANDOM % ${#TAGS[@]}))]}"

# ── TMPFILES ──────────────────────────────────────────────────────────────────
_TMP=()
_cleanup() { local f; for f in "${_TMP[@]:-}"; do rm -rf "$f" 2>/dev/null; done; }
trap _cleanup EXIT
_mktmp() { local d; d="$(mktemp -d)"; _TMP+=("$d"); echo "$d"; }

# ── GUM CACHE ─────────────────────────────────────────────────────────────────
GUM_VER="0.17.0"
GUM_DIR="${SCRIPT_DIR}/.bin"
GUM=""

_gum_os()   { case "$(uname -s)" in Darwin) echo Darwin;; *) echo Linux;; esac; }
_gum_arch() { case "$(uname -m)" in x86_64|amd64) echo x86_64;; arm64|aarch64) echo arm64;; i386|i686) echo i386;; *) echo x86_64;; esac; }

bootstrap_gum() {
    mkdir -p "$GUM_DIR"
    command -v gum &>/dev/null && { GUM="gum"; return 0; }
    [[ -x "${GUM_DIR}/gum" ]]  && { GUM="${GUM_DIR}/gum"; return 0; }

    echo -e "  ${MU}Bootstrapping UI …${R}"
    local a="gum_${GUM_VER}_$(_gum_os)_$(_gum_arch).tar.gz"
    local u="https://github.com/charmbracelet/gum/releases/download/v${GUM_VER}"
    local t; t="$(_mktmp)"

    curl -fsSL -o "${t}/${a}" "${u}/${a}" 2>/dev/null           || return 1
    tar -xzf "${t}/${a}" -C "$t" >/dev/null 2>&1                || return 1
    local g; g="$(find "$t" -type f -name gum | head -1)"
    [[ -n "$g" ]] || return 1
    mv "$g" "${GUM_DIR}/gum"; chmod +x "${GUM_DIR}/gum"
    GUM="${GUM_DIR}/gum"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                              U I   H E L P E R S
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ok()   { echo -e "  ${GN}✓${R}  $*"; }
warn() { echo -e "  ${AM}⚠${R}  $*"; }
err()  { echo -e "  ${RD}✗${R}  $*"; }
inf()  { echo -e "  ${C1}▸${R}  ${GR}$*${R}"; }

line()  { echo -e "  ${C2}$(printf '─%.0s' {1..60})${R}"; }
dot()   { echo -e "  ${MU}$(printf '·%.0s' {1..60})${R}"; }

banner() {
    echo ""
    echo -e "${C2}  ┌────────────────────────────────────────────────────────────┐${R}"
    echo -e "${C2}  │${R}                                                            ${C2}│${R}"
    echo -e "${C2}  │${R}  ${C1}${B}   ██████  ██  ██  ██████  ██████  ██████${R}               ${C2}│${R}"
    echo -e "${C2}  │${R}  ${C1}${B}  ██       ██  ██ ██    ██ ██         ██${R}                ${C2}│${R}"
    echo -e "${C2}  │${R}  ${C1}${B}  ██  ███  ██████ ██    ██ ████████   ██${R}                ${C2}│${R}"
    echo -e "${C2}  │${R}  ${C1}${B}  ██   ██  ██  ██ ██    ██      ██   ██${R}                ${C2}│${R}"
    echo -e "${C2}  │${R}  ${C1}${B}   ██████  ██  ██  ██████  ██████    ██${R}                ${C2}│${R}"
    echo -e "${C2}  │${R}                                                            ${C2}│${R}"
    echo -e "${C2}  │${R}  ${VT}${B}  ██   ██ ██████ ██████${R}                                 ${C2}│${R}"
    echo -e "${C2}  │${R}  ${VT}${B}  ███  ██ ██        ██${R}                                  ${C2}│${R}"
    echo -e "${C2}  │${R}  ${VT}${B}  ██ ███  ████      ██${R}                                  ${C2}│${R}"
    echo -e "${C2}  │${R}  ${VT}${B}  ██  ███ ██        ██${R}                                  ${C2}│${R}"
    echo -e "${C2}  │${R}  ${VT}${B}  ██   ██ ██████    ██${R}                                  ${C2}│${R}"
    echo -e "${C2}  │${R}                                                            ${C2}│${R}"
    echo -e "${C2}  └────────────────────────────────────────────────────────────┘${R}"
    echo ""
    echo -e "  ${C1}${B}◆ GHOSTNET${R}  ${MU}v${GHOSTNET_VERSION} · ${BUILD_SHA}${R}"
    echo -e "  ${D}${I}${GR}${TAG}${R}"
    echo ""
}

section() {
    echo ""
    echo -e "  ${C1}${B}▸ $1${R} ${C2}$(printf '─%.0s' {1..48})${R}"
    echo ""
}

# ── SCROLLABLE PICKER (arrow ↑↓ + Enter) ─────────────────────────────────────
# Sets PICK to 1-based index of chosen option.
pick() {
    local title="$1"; shift
    local items=("$@")
    local n=${#items[@]}
    local cur=0

    echo ""
    echo -e "  ${WH}${B}${title}${R}"
    line

    # ─ render ─
    _draw() {
        local i
        for (( i=0; i<n; i++ )); do
            printf '\r\033[2K'
            if (( i == cur )); then
                echo -e "  ${C1}${B} ❯ ${R}${WH}${B}${items[$i]}${R}"
            else
                echo -e "  ${MU}   ${items[$i]}${R}"
            fi
        done
        printf '\r\033[2K'
        echo -en "  ${MU}↑/↓ navigate · Enter select${R}"
    }

    _top() { printf "\033[${n}A\r"; }

    _key() {
        local c s
        IFS= read -rsn1 c </dev/tty || true
        case "$c" in
            ''|$'\n'|$'\r') K=enter; return ;;
            $'\033')
                IFS= read -rsn1 -t 0.1 s </dev/tty || true
                [[ "$s" == "[" ]] || { K=other; return; }
                IFS= read -rsn1 -t 0.1 s </dev/tty || true
                case "$s" in A) K=up;; B) K=down;; *) K=other;; esac
                return ;;
        esac
        K=other
    }

    _draw

    local K old_tty
    old_tty="$(stty -g </dev/tty 2>/dev/null || true)"
    stty -echo -icanon min 1 time 0 </dev/tty 2>/dev/null || true

    while true; do
        _key
        case "$K" in
            up)    (( cur > 0 )) && (( cur-- )) || cur=$(( n-1 )); _top; _draw ;;
            down)  (( cur < n-1 )) && (( cur++ )) || cur=0;        _top; _draw ;;
            enter) break ;;
        esac
    done

    [[ -n "$old_tty" ]] && stty "$old_tty" </dev/tty 2>/dev/null || true
    echo ""
    PICK=$(( cur + 1 ))
}

# ── YES / NO (arrow ←→ + Enter) ──────────────────────────────────────────────
yesno() {
    local prompt="$1" default="${2:-y}"
    echo ""
    echo -e "  ${WH}${B}${prompt}${R}"

    local sel=0; [[ "$default" == "n" ]] && sel=1
    local K old_tty

    _yn() {
        printf '\r\033[2K'
        if (( sel == 0 )); then echo -en "  ${C1}${B}◆ Yes${R}  ${MU}○ No${R}   ${MU}←/→ · Enter${R}"
        else                     echo -en "  ${MU}○ Yes${R}  ${C1}${B}◆ No${R}   ${MU}←/→ · Enter${R}"; fi
    }
    _ynkey() {
        local c s
        IFS= read -rsn1 c </dev/tty || true
        case "$c" in
            ''|$'\n'|$'\r') K=enter ;;
            $'\033')
                IFS= read -rsn1 -t 0.1 s </dev/tty || true
                [[ "$s" == "[" ]] || { K=other; return; }
                IFS= read -rsn1 -t 0.1 s </dev/tty || true
                case "$s" in C|D) K=toggle;; *) K=other;; esac ;;
            y|Y) K=y ;; n|N) K=n ;; *) K=other ;;
        esac
    }

    _yn
    old_tty="$(stty -g </dev/tty 2>/dev/null || true)"
    stty -echo -icanon min 1 time 0 </dev/tty 2>/dev/null || true

    while true; do
        _ynkey
        case "$K" in
            toggle) sel=$(( 1 - sel )); _yn ;;
            y)      sel=0; break ;;
            n)      sel=1; break ;;
            enter)  break ;;
        esac
    done

    [[ -n "$old_tty" ]] && stty "$old_tty" </dev/tty 2>/dev/null || true
    echo ""
    REPLY=$sel; return $sel
}

# ── ENV HELPERS ───────────────────────────────────────────────────────────────
set_env() {
    local key="$1" val="$2" file=".env"
    local esc; esc="$(printf '%s' "$val" | sed -e 's/[\\\/&|]/\\&/g')"
    grep -qE "^${key}=" "$file" 2>/dev/null \
        && sed -i "s|^${key}=.*|${key}=${esc}|" "$file" \
        || echo "${key}=${val}" >> "$file"
}

init_env() {
    if [[ -f .env ]]; then
        echo -e "  ${AM}◆  Existing .env detected.${R}"
        yesno "Keep existing configuration and skip provider setup?" "y"
        if [[ $REPLY -eq 0 ]]; then return 1; fi  # Yes → skip
        local bak=".env.bak.$(date +%Y%m%d_%H%M%S)"
        cp .env "$bak"
        inf "Backed up → ${bak}"
    fi
    [[ -f .env.example ]] && cp .env.example .env || touch .env
    return 0
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                          P R E F L I G H T
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPOSE_CMD=()

preflight() {
    section "System checks"

    local os="Linux"
    [[ -f /etc/os-release ]] && source /etc/os-release && os="${NAME:-Linux}"
    echo -e "  ${GR}Platform${R}  ${WH}${os}${R}"
    echo ""

    local good=1
    for t in docker python3 curl; do
        if command -v "$t" &>/dev/null; then ok "${GR}${t}${R}"
        else err "${t} — not found"; good=0; fi
    done

    if ! docker info &>/dev/null 2>&1; then
        err "Docker daemon not running"
        echo -e "  ${MU}    Fix: sudo systemctl start docker${R}"; exit 1
    fi

    if   docker compose version &>/dev/null 2>&1; then COMPOSE_CMD=(docker compose)
    elif docker-compose version &>/dev/null 2>&1; then COMPOSE_CMD=(docker-compose)
    else err "Docker Compose not found"; exit 1; fi

    [[ $good -eq 0 ]] && exit 1
    echo ""; ok "System checks passed"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                     S E C U R I T Y   B R I E F I N G
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
security_briefing() {
    section "Security"
    echo -e "  ${WH}${B}Security notice — read before continuing.${R}"
    echo ""
    echo -e "  ${GR}GhostNet is an active deception system.${R}"
    echo -e "  ${GR}Expect real attacker traffic once deployed.${R}"
    echo ""
    echo -e "  ${WH}Exposed services:${R}"
    echo -e "  ${RD}◆${R}  Port ${WH}22${R}    ${GR}SSH honeypot${R}"
    echo -e "  ${RD}◆${R}  Port ${WH}23${R}    ${GR}Telnet honeypot${R}"
    echo -e "  ${RD}◆${R}  Port ${WH}80${R}    ${GR}HTTP honeypot${R}"
    echo -e "  ${C1}◆${R}  Port ${WH}8080${R}  ${GR}Dashboard (restrict to localhost)${R}"
    echo ""
    line
    echo ""
    echo -e "  ${WH}Recommendations:${R}"
    echo -e "  ${MU}◦  Dedicated VM or isolated machine${R}"
    echo -e "  ${MU}◦  Firewall the dashboard — allow only your IP${R}"
    echo -e "  ${MU}◦  Run ${WH}chmod 600 .env${R}${MU} after setup${R}"
    echo -e "  ${MU}◦  You are liable for all API token costs${R}"
    echo -e "  ${MU}◦  Deploy only on networks you own${R}"
    echo ""
    line

    yesno "I understand. Continue?" "y"
    if [[ $REPLY -ne 0 ]]; then
        echo -e "\n  ${MU}Setup cancelled.${R}\n"; exit 0
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                 A I   C O N F I G U R A T I O N
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_ai() {
    local provider pname api_var base_url model=""

    # ── Provider → Model loop (Go back restarts) ─────────────────────────────
    while true; do
        section "AI provider"

        pick "Select your AI provider" \
            "OpenRouter     — 300+ models, one key" \
            "Groq           — Ultra-fast inference" \
            "OpenAI         — GPT-5.4 / GPT-4o / o4-mini" \
            "Anthropic      — Claude Opus 4.6 / Sonnet 4.6" \
            "DeepSeek       — DeepSeek-V3 / R1" \
            "Together AI    — Llama, Qwen, DeepSeek" \
            "DeepInfra      — Fast OSS models" \
            "NVIDIA NIM     — Nemotron enterprise" \
            "Custom         — Any OpenAI-compatible endpoint"
        local c=$PICK

        case "$c" in
            1) provider=openrouter;  pname="OpenRouter";   api_var=OPENROUTER_API_KEY; base_url="https://openrouter.ai/api/v1" ;;
            2) provider=groq;        pname="Groq";         api_var=GROQ_API_KEY;       base_url="https://api.groq.com/openai/v1" ;;
            3) provider=openai;      pname="OpenAI";       api_var=OPENAI_API_KEY;     base_url="https://api.openai.com/v1" ;;
            4) provider=anthropic;   pname="Anthropic";    api_var=ANTHROPIC_API_KEY;   base_url="https://api.anthropic.com/v1" ;;
            5) provider=deepseek;    pname="DeepSeek";     api_var=DEEPSEEK_API_KEY;    base_url="https://api.deepseek.com/v1" ;;
            6) provider=together;    pname="Together AI";  api_var=TOGETHER_API_KEY;    base_url="https://api.together.xyz/v1" ;;
            7) provider=deepinfra;   pname="DeepInfra";    api_var=DEEPINFRA_API_KEY;   base_url="https://api.deepinfra.com/v1/openai" ;;
            8) provider=nvidia;      pname="NVIDIA NIM";   api_var=NVIDIA_API_KEY;      base_url="https://integrate.api.nvidia.com/v1" ;;
            9) provider=custom;      pname="Custom";       api_var=AI_API_KEY;          base_url="" ;;
        esac

        ok "Provider: ${pname}"

        # ── Model selection ───────────────────────────────────────────────────
        section "Default model"

        local m=()
        case "$provider" in
            openrouter) m=(
                "anthropic/claude-opus-4-6"
                "anthropic/claude-sonnet-4-6"
                "openai/gpt-5.4"
                "openai/gpt-5-mini"
                "google/gemini-3.1-pro"
                "google/gemini-2.5-flash"
                "deepseek/deepseek-chat"
                "deepseek/deepseek-reasoner"
                "meta-llama/llama-3.3-70b-instruct"
                "x-ai/grok-4.1"
            ) ;;
            groq) m=(
                "llama-3.3-70b-versatile"
                "llama-3.1-8b-instant"
                "mixtral-8x7b-32768"
                "deepseek-r1-distill-llama-70b"
                "gemma2-9b-it"
            ) ;;
            openai) m=(
                "gpt-5.4"   "gpt-5.4-pro"  "gpt-5-mini"
                "gpt-4o"    "gpt-4o-mini"   "o4-mini"   "o3-mini"
            ) ;;
            anthropic) m=(
                "claude-opus-4-6"   "claude-sonnet-4-6"
                "claude-haiku-4-5"  "claude-3-7-sonnet-20250219"
            ) ;;
            deepseek) m=("deepseek-chat" "deepseek-reasoner") ;;
            together) m=(
                "meta-llama/Llama-3.3-70B-Instruct-Turbo"
                "deepseek-ai/DeepSeek-V3"
                "deepseek-ai/DeepSeek-R1"
                "Qwen/Qwen2.5-72B-Instruct"
            ) ;;
            deepinfra) m=(
                "meta-llama/Meta-Llama-3.3-70B-Instruct"
                "deepseek-ai/DeepSeek-V3"
                "deepseek-ai/DeepSeek-R1"
                "mistralai/Mistral-Small-24B-Instruct-2501"
            ) ;;
            nvidia) m=(
                "meta/llama-3.3-70b-instruct"
                "nvidia/llama-3.1-nemotron-70b-instruct"
                "deepseek-ai/deepseek-r1"
            ) ;;
        esac

        if [[ "$provider" == "custom" ]]; then
            echo -en "  ${GR}Model ID${R} ${C1}›${R} "
            read -r model </dev/tty
            break
        fi

        local view=("← Go back" "${m[@]}" "Enter model ID manually")
        pick "Select model for ${pname}" "${view[@]}"
        local mc=$PICK

        if (( mc == 1 )); then continue; fi                 # Go back
        if (( mc == ${#view[@]} )); then                     # Manual entry
            echo -en "  ${GR}Model ID${R} ${C1}›${R} "
            read -r model </dev/tty
            break
        fi
        model="${view[$((mc-1))]}"
        break
    done

    ok "Model: ${model}"

    # ── Credentials ───────────────────────────────────────────────────────────
    section "${pname} credentials"

    if [[ "$provider" == "custom" ]]; then
        echo -en "  ${GR}Base URL${R} ${C1}›${R} "
        read -r base_url </dev/tty 2>/dev/null || true
    fi

    echo ""
    echo -en "  ${GR}${api_var}${R} ${MU}(hidden)${R} ${C1}›${R} "
    local api_key=""
    read -rs api_key </dev/tty 2>/dev/null || true
    echo ""

    if [[ -z "$api_key" ]]; then warn "No API key entered — set it later in .env"
    else ok "API key saved"; fi

    # ── Write .env ────────────────────────────────────────────────────────────
    for k in GROQ_API_KEY LLM_API_KEY NVIDIA_API_KEY "$api_var"; do
        set_env "$k" "$api_key"
    done
    for k in GROQ_BASE_URL LLM_BASE_URL NVIDIA_BASE_URL AI_BASE_URL; do
        set_env "$k" "$base_url"
    done
    for k in GROQ_MODEL GROQ_MODEL_PRIMARY GROQ_MODEL_SECONDARY LLM_MODEL_SSH LLM_MODEL_HTTP NVIDIA_MODEL AI_MODEL; do
        set_env "$k" "$model"
    done
    set_env "AI_PROVIDER" "$pname"

    # ── Analysis profile ──────────────────────────────────────────────────────
    section "Analysis profile"
    echo -e "  ${GR}Controls LLM timeout and max tokens per session.${R}"

    pick "Select profile" \
        "Fast      — 6s  · 800 tokens   (demos)" \
        "Balanced  — 10s · 1200 tokens  (recommended)" \
        "Deep      — 20s · 2000 tokens  (forensics)"

    case "$PICK" in
        1) set_env LLM_TIMEOUT_SECONDS 6.0  ; set_env LLM_MAX_TOKENS 800  ; set_env THINKING_ENABLED false ;;
        2) set_env LLM_TIMEOUT_SECONDS 10.0 ; set_env LLM_MAX_TOKENS 1200 ; set_env THINKING_ENABLED false ;;
        3) set_env LLM_TIMEOUT_SECONDS 20.0 ; set_env LLM_MAX_TOKENS 2000 ; set_env THINKING_ENABLED true  ;;
    esac

    echo ""
    line
    echo ""
    ok "Configuration saved"
    echo -e "  ${GR}   Provider  ${R}${WH}${pname}${R}"
    echo -e "  ${GR}   Model     ${R}${WH}${model}${R}"
    echo -e "  ${GR}   Base URL  ${R}${WH}${base_url}${R}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                       W A Z U H   S I E M   S E T U P
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WAZUH_DEPLOY=0

configure_wazuh() {
    section "SIEM Integration"
    echo -e "  ${GR}GhostNet can stream telemetry directly to Wazuh for analysis.${R}"
    echo -e "  ${GR}Wazuh requires at least ${WH}4GB RAM${R}${GR} and ${WH}dual-core CPU${R}${GR}.${R}"
    echo ""

    yesno "Deploy Wazuh SIEM alongside GhostNet?" "n"
    if [[ $REPLY -eq 0 ]]; then
        WAZUH_DEPLOY=1
        ok "Wazuh deployment queued"
    else
        inf "Skipping Wazuh SIEM"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                              D E P L O Y
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
deploy() {
    section "Launching GhostNet"

    if [[ $WAZUH_DEPLOY -eq 1 ]]; then
        local w_dir="../wazuh-docker"
        
        # 1. Clone Wazuh if missing
        if [[ ! -d "$w_dir" ]]; then
            echo -e "  ${GR}Cloning Wazuh v4.14.4 (this takes a moment) …${R}"
            git clone -b v4.14.4 https://github.com/wazuh/wazuh-docker.git "$w_dir" >/dev/null 2>&1
            ok "Wazuh repository cloned"
        fi

        # 2. Inject GhostNet Custom Rules
        echo -e "  ${GR}Injecting GhostNet rules and configurations …${R}"
        mkdir -p "${w_dir}/single-node/custom"
        cp configs/wazuh/rules/*.xml "${w_dir}/single-node/custom/" 2>/dev/null || true

        # 3. Patch ossec.conf for HTTP log ingestion
        local conf="${w_dir}/single-node/config/wazuh_cluster/wazuh_manager.conf"
        if ! grep -q "http_honeypot.json" "$conf" 2>/dev/null; then
            # Insert log parsing config before the last </ossec_config>
            sed -i '/<\/ossec_config>/i \  <!-- HTTP Honeypot Log Monitoring -->\n  <localfile>\n    <log_format>json</log_format>\n    <location>/var/ossec/logs/http/http_honeypot.json</location>\n  </localfile>\n' "$conf"
        fi

        # 4. Patch docker-compose.yml for volume mounts
        local dcy="${w_dir}/single-node/docker-compose.yml"
        local abs_logs_dir="$(pwd)/logs/http"
        mkdir -p "$abs_logs_dir"
        
        if ! grep -q "/var/ossec/logs/http" "$dcy" 2>/dev/null; then
            # Insert volume mappings under wazuh_wodles
            sed -i "/- wazuh_wodles:\/var\/ossec\/wodles/a \\      - ./custom/custom_http_honeypot_rules.xml:/wazuh-config-mount/etc/rules/custom_http_honeypot_rules.xml\\n      - ./custom/custom_cowrie_rules.xml:/wazuh-config-mount/etc/rules/custom_cowrie_rules.xml\\n      - ${abs_logs_dir}:/var/ossec/logs/http" "$dcy"
        fi
        
        # 5. SSL Certificates
        echo -e "  ${GR}Pre-flight: Checking Wazuh SSL certificates …${R}"
        if [[ ! -f "${w_dir}/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
            echo -e "  ${GR}Generating new indexer certificates …${R}"
            (cd "${w_dir}/single-node" && "${COMPOSE_CMD[@]}" -f generate-indexer-certs.yml run --rm generator >/dev/null 2>&1)
        fi
        
        # 6. Start the SIEM
        echo -e "  ${GR}Building and starting Wazuh SIEM (this may take a minute) …${R}"
        echo ""
        if (cd "${w_dir}/single-node" && "${COMPOSE_CMD[@]}" up -d 2>&1 | while IFS= read -r l; do
            echo -e "  ${MU}${l}${R}"
        done); then
            echo ""; ok "Wazuh SIEM started"
        else
            echo ""; err "Wazuh SIEM deployment failed. Continuing with GhostNet only."
        fi
        line
        echo ""
    fi

    echo -e "  ${GR}Building and starting GhostNet containers …${R}"
    echo ""

    if "${COMPOSE_CMD[@]}" up -d --build 2>&1 | while IFS= read -r l; do
        echo -e "  ${MU}${l}${R}"
    done; then
        echo ""; ok "Containers started"
    else
        echo ""; err "Deployment failed"
        echo -e "  ${MU}   Run: ${WH}${COMPOSE_CMD[*]} up -d --build${R}${MU} for details${R}"
        exit 1
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                             S U M M A R Y
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
show_summary() {
    echo ""
    echo -e "  ${C2}┌────────────────────────────────────────────────────────────┐${R}"
    echo -e "  ${C2}│${R}  ${C1}${B}◆  GhostNet is live.${R}                                      ${C2}│${R}"
    echo -e "  ${C2}└────────────────────────────────────────────────────────────┘${R}"
    echo ""
    echo -e "  ${GR}Dashboard    ${R} ${C1}http://localhost:8080${R}"
    if [[ $WAZUH_DEPLOY -eq 1 ]]; then
        echo -e "  ${GR}Wazuh SIEM   ${R} ${C1}https://localhost:443${R} ${MU}(admin / SecretPassword)${R}"
    fi
    echo -e "  ${GR}SSH trap     ${R} ${WH}tcp://0.0.0.0:22${R}"
    echo -e "  ${GR}Telnet trap  ${R} ${WH}tcp://0.0.0.0:23${R}"
    echo -e "  ${GR}HTTP trap    ${R} ${WH}http://0.0.0.0:80${R}"
    echo ""
    line
    echo ""
    echo -e "  ${GR}Useful commands:${R}"
    echo ""
    echo -e "  ${VT}\$${R}  ${WH}${COMPOSE_CMD[*]} logs -f${R}"
    echo -e "  ${VT}\$${R}  ${WH}${COMPOSE_CMD[*]} down${R}"
    echo -e "  ${VT}\$${R}  ${WH}rm analysis.db && ${COMPOSE_CMD[*]} restart${R}"
    echo ""
    line
    echo ""
    echo -e "  ${D}${I}${GR}Infrastructure masked. Monitoring active. Waiting.${R}"
    echo ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                                M A I N
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
architecture_overview() {
    section "Infrastructure Architecture"
    echo -e "  ${GR}GhostNet deploys a 4-tier deception intelligence stack:${R}"
    echo ""
    echo -e "  ${C1}1. Cowrie (Port 22/23)${R}"
    echo -e "     ${MU}High-interaction SSH/Telnet honeypot. Emulates a full Linux filesystem,${R}"
    echo -e "     ${MU}captures lateral movement, and feeds commands to the AI for hallucinated responses.${R}"
    echo ""
    echo -e "  ${C1}2. HTTP Trap (Port 80)${R}"
    echo -e "     ${MU}Dynamic web honeypot. Morphing attack surface that captures web exploits${R}"
    echo -e "     ${MU}(Log4j, SQLi, path traversal) and responds with generated synthetic payloads.${R}"
    echo ""
    echo -e "  ${C1}3. Analysis GUI (Port 8080)${R}"
    echo -e "     ${MU}Your tactical command center. Tracks active sessions, displays live LLM inferences,${R}"
    echo -e "     ${MU}and reviews attacker behavioral analysis in real-time.${R}"
    echo ""
    echo -e "  ${C1}4. Wazuh SIEM (Port 443)${R} ${GR}[Optional]${R}"
    echo -e "     ${MU}Heavy-duty log aggregation. Provides long-term threat hunting, dashboarding,${R}"
    echo -e "     ${MU}and MITRE ATT&CK mapping of all trapped activity.${R}"
    echo ""
    
    yesno "Proceed with deployment?" "y"
    if [[ $REPLY -ne 0 ]]; then
        echo -e "\n  ${MU}Setup cancelled.${R}\n"; exit 0
    fi
}

main() {
    bootstrap_gum || true
    banner
    architecture_overview
    preflight
    security_briefing

    if init_env; then
        configure_ai
    else
        echo -e "  ${MU}Skipping AI setup — using existing .env${R}"
    fi

    configure_wazuh
    deploy
    show_summary
}

main "$@"