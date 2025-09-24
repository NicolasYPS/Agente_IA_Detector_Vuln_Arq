#!/usr/bin/env bash
set -e

# =========================
# STRIDE One-Command Runner
# =========================
# Uso para recrutadores/quem clonar:
#   chmod +x dev.sh
#   ./dev.sh
#
# O script:
# 1) Cria .env/venv, instala deps
# 2) Detecta GPU; se não tiver, força CPU e avisa requisitos
# 3) Inicia Ollama (se base local), baixa modelos e testa inferência
# 4) Sobe backend (:8010) + frontend (:5500) e tenta abrir o navegador
#
# Comandos avançados (opcionais):
#   ./dev.sh setup | backend | frontend | up | pull | clean | env | help

PY=${PYTHON:-python3}
PIP=${PIP:-pip}
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$ROOT_DIR/app"
FRONT_DIR="$ROOT_DIR/modulo1/02-front-end"
VENV_DIR="$ROOT_DIR/venv"
ENV_FILE="$ROOT_DIR/.env"
MODELS_FILE="$ROOT_DIR/models.txt"

BACK_PORT=${BACK_PORT:-8010}
FRONT_PORT=${FRONT_PORT:-5500}

# ---------- util ----------
info(){ echo -e "\033[1;34m[info]\033[0m $*"; }
ok(){   echo -e "\033[1;32m[ok]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[warn]\033[0m $*"; }
err(){  echo -e "\033[1;31m[err]\033[0m $*" >&2; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "faltando: $1"; exit 1; }; }

activate_venv(){ # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

load_env_if_present(){ [[ -f "$ENV_FILE" ]] && set -a && source "$ENV_FILE" && set +a || true; }

write_env_kv(){
  local key="$1" val="$2"
  touch "$ENV_FILE"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|g" "$ENV_FILE"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
  fi
}

make_env(){
  if [[ -f "$ENV_FILE" ]]; then
    info ".env já existe — mantendo."
    return
  fi
  cat > "$ENV_FILE" <<EOF
# ===== STRIDE .env =====
OPENAI_BASE_URL=${OPENAI_BASE_URL:-http://127.0.0.1:11434/v1}
OPENAI_API_KEY=${OPENAI_API_KEY:-ollama}
LOCAL_VLM_MODEL=${LOCAL_VLM_MODEL:-llava}
PUBLIC_HOST=${PUBLIC_HOST:-http://localhost:${BACK_PORT}}
# OLLAMA_NUM_GPU será ajustado automaticamente pelo dev.sh após checagem de GPU
EOF
  ok "arquivo .env criado."
}

install_backend(){
  need_cmd "$PY"
  need_cmd "$PIP"
  if [[ ! -d "$VENV_DIR" ]]; then
    info "criando venv em $VENV_DIR"
    $PY -m venv "$VENV_DIR"
  fi
  activate_venv
  pip install --upgrade pip wheel
  info "instalando dependências do backend…"
  pip install fastapi uvicorn[standard] python-dotenv reportlab pillow openai httpx
  ok "dependências instaladas."
}

# ---------- GPU / CPU ----------
has_nvidia(){ command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; }
has_rocm(){ command -v rocminfo >/dev/null 2>&1 || command -v rocm-smi >/dev/null 2>&1; }
has_apple_metal(){
  case "$(uname -s)" in
    Darwin) sysctl -n machdep.cpu.brand_string 2>/dev/null | grep -qi "Apple" && return 0 || return 1 ;;
    *) return 1 ;;
  esac
}
detect_gpu(){
  if has_nvidia; then echo "NVIDIA"; return 0; fi
  if has_rocm; then echo "AMD/ROCm"; return 0; fi
  if has_apple_metal; then echo "Apple/Metal"; return 0; fi
  echo "NONE"; return 1
}
print_cpu_requirements(){
  cat <<'TXT'
──────────────── CPU MODE ─────────────────
Nenhuma GPU detectada. O modelo rodará 100% em CPU.

Requisitos RECOMENDADOS para experiência estável:
 • RAM:       ≥ 16 GB (mínimo). Modelos >7B: ideal ≥ 24–32 GB.
 • DISCO:     ≥ 10–20 GB livres (modelos + cache).
 • CPU:       ≥ 4–8 vCPUs (AVX/AVX2 ajuda), melhor com 12+ threads.
 • SWAP:      Habilite swap se a RAM for justa.
 • TEMPO:     Inferência em CPU é bem mais lenta que em GPU.

Dicas:
 • Use modelos menores (ex.: llava:7b) em CPU.
 • Feche apps pesados antes de iniciar.
TXT
}

# ---------- OLLAMA ----------
is_ollama_baseurl(){
  local url="${OPENAI_BASE_URL:-}"
  [[ "$url" =~ 127\.0\.0\.1:11434 ]] || [[ "$url" =~ localhost:11434 ]]
}
ensure_ollama_running(){
  if ! command -v ollama >/dev/null 2>&1; then
    err "‘ollama’ não encontrado no PATH. Instale em https://ollama.com/ (ou mude OPENAI_BASE_URL no .env)."
    exit 1
  fi
  if curl -sS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    ok "ollama está respondendo em 127.0.0.1:11434"
    return
  fi
  warn "ollama não parece estar rodando; tentando iniciar…"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q ollama; then
    sudo systemctl start ollama || true
  else
    nohup ollama serve >/dev/null 2>&1 &
  fi
  for i in {1..24}; do
    sleep 0.5
    curl -sS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && { ok "ollama iniciado."; return; }
  done
  err "não consegui iniciar o servidor do ollama (porta 11434)."
  exit 1
}
list_models_to_pull(){
  local list=""
  [[ -n "${LOCAL_VLM_MODEL:-}" ]] && list+="${LOCAL_VLM_MODEL}"$'\n'
  if [[ -f "$MODELS_FILE" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && list+="$line"$'\n'
    done < <(grep -vE '^\s*#' "$MODELS_FILE" || true)
  fi
  echo "$list" | awk 'NF' | awk '!seen[$0]++'
}
run_inference_test(){
  local model="$1"
  [[ -z "$model" ]] && { warn "modelo vazio, pulando teste de inferência."; return; }
  info "executando teste de inferência com '${model}'…"
  local PAYLOAD RESP
  PAYLOAD=$(cat <<JSON
{"model":"${model}","prompt":"ping","stream":false}
JSON
)
  set +e
  RESP=$(curl -sS --max-time 10 -H "Content-Type: application/json" -d "$PAYLOAD" http://127.0.0.1:11434/api/generate)
  CODE=$?
  set -e
  if [[ $CODE -ne 0 || -z "$RESP" ]]; then
    warn "sem resposta do modelo (timeout/erro). Verifique RAM/GPU/CPU e rode: ./dev.sh pull"
    return
  fi
  if echo "$RESP" | grep -q '"response"'; then
    ok "teste de inferência concluído — modelo respondeu!"
  else
    warn "resposta inesperada do modelo:"
    echo "$RESP" | head -c 400 | sed 's/$/\n.../'
  fi
}
pull_models(){
  load_env_if_present
  if ! is_ollama_baseurl; then
    info "OPENAI_BASE_URL não é Ollama local — pulando download de modelos."
    return
  fi

  local gpu="$(detect_gpu || true)"
  case "$gpu" in
    NVIDIA|AMD/ROCm|Apple/Metal)
      ok "GPU detectada: $gpu"
      write_env_kv OLLAMA_NUM_GPU 999
      ;;
    NONE|*)
      warn "GPU não detectada — forçando CPU."
      write_env_kv OLLAMA_NUM_GPU 0
      print_cpu_requirements
      ;;
  esac

  ensure_ollama_running

  local models; models="$(list_models_to_pull)"
  if [[ -z "$models" ]]; then
    warn "nenhum modelo especificado (LOCAL_VLM_MODEL vazio e sem models.txt)."
    return
  fi

  echo
  info "Resumo antes do download:"
  echo " • OPENAI_BASE_URL = ${OPENAI_BASE_URL}"
  echo " • LOCAL_VLM_MODEL = ${LOCAL_VLM_MODEL:-<não definido>}"
  echo " • OLLAMA_NUM_GPU  = $(grep -E '^OLLAMA_NUM_GPU=' "$ENV_FILE" | cut -d= -f2 2>/dev/null || echo '<não definido>')"
  echo

  info "baixando modelos do Ollama:"
  echo "$models" | while IFS= read -r model; do
    [[ -z "$model" ]] && continue
    info "-> ollama pull $model"
    ollama pull "$model"
  done
  ok "modelos prontos."

  [[ -n "${LOCAL_VLM_MODEL:-}" ]] && run_inference_test "${LOCAL_VLM_MODEL}"
}

# ---------- infra ----------
open_browser(){
  local url="$1"
  case "$(uname -s)" in
    Darwin) command -v open >/dev/null 2>&1 && open "$url" || true ;;
    Linux)  command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1 || true ;;
    MINGW*|MSYS*|CYGWIN*) command -v start >/dev/null 2>&1 && start "$url" || true ;;
  esac
}

port_in_use(){ lsof -iTCP -sTCP:LISTEN -P | grep -q ":$1\b" || ss -ltn 2>/dev/null | grep -q ":$1\b" || return 1; }

# ---------- comandos ----------
cmd_setup(){
  make_env
  install_backend
  pull_models
  ok "setup concluído."
}

cmd_backend(){
  [[ -d "$VENV_DIR" ]] || { err "venv não encontrada. Rode: ./dev.sh setup"; exit 1; }
  activate_venv
  export PORT="$BACK_PORT"
  info "iniciando backend em http://localhost:${BACK_PORT}"
  cd "$APP_DIR"
  exec uvicorn main:app --reload --host 0.0.0.0 --port "$BACK_PORT"
}

cmd_frontend(){
  [[ -d "$FRONT_DIR" ]] || { err "diretório do front não encontrado: $FRONT_DIR"; exit 1; }
  cd "$FRONT_DIR"
  info "servindo frontend em http://localhost:${FRONT_PORT}"
  exec ${PYTHON:-python3} -m h
