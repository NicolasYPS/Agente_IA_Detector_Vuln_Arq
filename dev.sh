#!/usr/bin/env bash
set -e

# =========================
# STRIDE One-Command Runner
# =========================
# Uso:
#   chmod +x dev.sh
#   ./dev.sh
#
# Comandos opcionais:
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

# ---------- utils ----------
info(){ echo -e "\033[1;34m[info]\033[0m $*"; }
ok(){   echo -e "\033[1;32m[ok]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[warn]\033[0m $*"; }
err(){  echo -e "\033[1;31m[err]\033[0m $*" >&2; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "faltando: $1"; exit 1; }; }

activate_venv(){ # shellcheck disable=SC1091
  # garante que o arquivo existe
  if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
    err "venv não encontrada. Rode: ./dev.sh setup"
    exit 1
  fi
  source "$VENV_DIR/bin/activate"
}

load_env_if_present(){
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  fi
}

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
    "$PY" -m venv "$VENV_DIR"
  fi
  activate_venv
  pip install --upgrade pip wheel
  info "instalando dependências do backend…"
  # mantenha compatível com seu requirements.txt
  if [[ -f "$ROOT_DIR/modulo1/requirements.txt" ]]; then
    pip install -r "$ROOT_DIR/modulo1/requirements.txt"
  else
    pip install fastapi uvicorn[standard] python-dotenv reportlab pillow openai httpx
  fi
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

Requisitos RECOMENDADOS:
 • RAM:   ≥ 16 GB (mínimo). Modelos >7B: ideal ≥ 24–32 GB.
 • DISCO: ≥ 10–20 GB livres (modelos + cache).
 • CPU:   ≥ 4–8 vCPUs (AVX/AVX2 ajuda); 12+ threads melhora bastante.
 • SWAP:  Habilite swap se a RAM for justa.

A inferência em CPU é mais lenta; prefira modelos menores (ex.: llava:7b).
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
    if curl -sS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      ok "ollama iniciado."
      return
    fi
  done
  err "não consegui iniciar o servidor do ollama (porta 11434)."
  exit 1
}

list_models_to_pull(){
  local list=""
  [[ -n "${LOCAL_VLM_MODEL:-}" ]] && list+="${LOCAL_VLM_MODEL}"$'\n'
  if [[ -f "$MODELS_FILE" ]]; then
    # ignora linhas em branco e comentários
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
  local PAYLOAD RESP CODE
  PAYLOAD='{"model":"'"${model}"'","prompt":"ping","stream":false}'
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
    echo "$RESP" | head -c 400; echo
  fi
}

pull_models(){
  load_env_if_present
  if ! is_ollama_baseurl; then
    info "OPENAI_BASE_URL não é Ollama local — pulando download de modelos."
    return
  fi

  local gpu
  gpu="$(detect_gpu || true)"
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

  local models
  models="$(list_models_to_pull)"
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
  while IFS= read -r model; do
    [[ -z "$model" ]] && continue
    info "-> ollama pull $model"
    ollama pull "$model"
  done <<< "$models"
  ok "modelos prontos."

  [[ -n "${LOCAL_VLM_MODEL:-}" ]] && run_inference_test "${LOCAL_VLM_MODEL}"
}

# ---------- infra ----------
open_browser(){
  local url="$1"
  case "$(uname -s)" in
    Darwin) command -v open >/dev/null 2>&1 && open "$url" || true ;;
    Linux)  command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1 || true ;;
    MINGW*|MSYS*|CYGWIN*) start "" "$url" >/dev/null 2>&1 || true ;;
  esac
}

port_in_use(){
  (command -v lsof >/dev/null 2>&1 && lsof -iTCP -sTCP:LISTEN -P | grep -q ":$1\b") \
  || (command -v ss >/dev/null 2>&1 && ss -ltn | grep -q ":$1\b")
}

# ---------- comandos ----------
cmd_setup(){
  make_env
  install_backend
  pull_models
  ok "setup concluído."
}

cmd_backend(){
  activate_venv
  export PORT="$BACK_PORT"
  info "iniciando backend em http://localhost:${BACK_PORT}"
  cd "$APP_DIR"
  exec uvicorn main:app --reload --host 0.0.0.0 --port "$BACK_PORT"
}

cmd_frontend(){
  if [[ ! -d "$FRONT_DIR" ]]; then
    err "diretório do front não encontrado: $FRONT_DIR"
    exit 1
  fi
  cd "$FRONT_DIR"
  info "servindo frontend em http://localhost:${FRONT_PORT}"
  exec ${PYTHON:-python3} -m http.server "$FRONT_PORT"
}

cmd_up(){
  # Ajusta portas se já estiverem em uso
  if port_in_use "$BACK_PORT"; then
    warn "porta $BACK_PORT em uso — tentando próxima livre…"
    BACK_PORT=$((BACK_PORT+1))
    write_env_kv PUBLIC_HOST "http://localhost:${BACK_PORT}"
  fi
  if port_in_use "$FRONT_PORT"; then
    warn "porta $FRONT_PORT em uso — tentando próxima livre…"
    FRONT_PORT=$((FRONT_PORT+1))
  fi

  info "subindo backend e frontend…"
  ./dev.sh backend & BACK_PID=$!
  sleep 1
  trap "info 'encerrando…'; kill $BACK_PID >/dev/null 2>&1 || true" INT TERM

  local url="http://localhost:${FRONT_PORT}"
  open_browser "$url" || true
  ./dev.sh frontend
}

cmd_clean(){
  info "removendo venv e caches…"
  rm -rf "$VENV_DIR"
  find "$ROOT_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} +
  ok "limpeza concluída."
}

cmd_env(){
  if [[ -f "$ENV_FILE" ]]; then
    info "variáveis do .env:"
    cat "$ENV_FILE"
  else
    err "sem .env — rode: ./dev.sh setup"
  fi
}

cmd_pull(){ pull_models; }

cmd_help(){
  cat <<EOF
Comandos:
  ./dev.sh            -> (padrão) quickstart: setup completo + sobe backend e frontend
  ./dev.sh setup      -> apenas setup (venv, deps, modelos, teste)
  ./dev.sh backend    -> roda backend (FastAPI) em :${BACK_PORT}
  ./dev.sh frontend   -> serve frontend estático em :${FRONT_PORT}
  ./dev.sh up         -> backend + frontend
  ./dev.sh pull       -> puxa modelos do Ollama + teste
  ./dev.sh env        -> mostra .env atual
  ./dev.sh clean      -> remove venv e caches
  ./dev.sh help       -> esta ajuda
EOF
}

# ---------- roteador ----------
case "${1:-quickstart}" in
  quickstart|"")
    cmd_setup
    cmd_up
    ;;
  setup)     cmd_setup ;;
  backend)   cmd_backend ;;
  frontend)  cmd_frontend ;;
  up)        cmd_up ;;
  clean)     cmd_clean ;;
  env)       cmd_env ;;
  pull)      cmd_pull ;;
  help|*)    cmd_help ;;
esac
