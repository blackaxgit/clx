#!/bin/bash
#
# CLX Services Manager
# Manages Docker-based CLX services (Ollama)
#
# Usage: clx-services [start|stop|status|logs|pull-models|restart]

set -e

# Model defaults — read from config if available.
CLX_CONFIG="$HOME/.clx/config.yaml"
if [[ -f "$CLX_CONFIG" ]]; then
    VALIDATION_MODEL=$(grep '^\s*model:' "$CLX_CONFIG" | head -1 | sed 's/.*model:\s*//' | tr -d '[:space:]')
    EMBEDDING_MODEL=$(grep '^\s*embedding_model:' "$CLX_CONFIG" | head -1 | sed 's/.*embedding_model:\s*//' | tr -d '[:space:]')
fi
VALIDATION_MODEL="${VALIDATION_MODEL:-qwen3:1.7b}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-qwen3-embedding:0.6b}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}$1${NC}"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}!${NC} $1"; }

COMPOSE_FILE="$HOME/.clx/docker/docker-compose.yml"

# Check if docker-compose.yml exists
if [[ ! -f "$COMPOSE_FILE" ]]; then
    warn "Docker compose file not found: $COMPOSE_FILE"
    echo "Run the CLX installer to set up Docker services."
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    warn "Docker is not running. Please start Docker Desktop first."
    exit 1
fi

case "$1" in
    start)
        info "Pulling latest Ollama image..."
        docker compose -f "$COMPOSE_FILE" pull
        info "Starting CLX services..."
        docker compose -f "$COMPOSE_FILE" up -d
        success "Services started"
        echo ""
        echo "Waiting for Ollama to be ready..."
        sleep 3
        for i in {1..30}; do
            if curl -s http://localhost:11434/ > /dev/null 2>&1; then
                success "Ollama is ready at http://localhost:11434"
                exit 0
            fi
            echo -n "."
            sleep 1
        done
        warn "Ollama did not become ready in 30 seconds. Check logs with: clx-services logs"
        ;;

    stop)
        info "Stopping CLX services..."
        docker compose -f "$COMPOSE_FILE" down
        success "Services stopped"
        ;;

    restart)
        info "Restarting CLX services..."
        docker compose -f "$COMPOSE_FILE" restart
        success "Services restarted"
        ;;

    status)
        docker compose -f "$COMPOSE_FILE" ps
        echo ""
        if curl -s http://localhost:11434/ > /dev/null 2>&1; then
            success "Ollama is responding at http://localhost:11434"
        else
            warn "Ollama is not responding"
        fi
        ;;

    logs)
        docker compose -f "$COMPOSE_FILE" logs -f
        ;;

    pull-models)
        info "Pulling required Ollama models..."
        echo ""

        info "Pulling $VALIDATION_MODEL..."
        docker exec clx-ollama ollama pull "$VALIDATION_MODEL"
        success "$VALIDATION_MODEL pulled"

        echo ""
        info "Pulling $EMBEDDING_MODEL..."
        docker exec clx-ollama ollama pull "$EMBEDDING_MODEL"
        success "$EMBEDDING_MODEL pulled"

        echo ""
        success "All models pulled successfully"
        ;;

    *)
        echo "CLX Services Manager"
        echo ""
        echo "Usage: clx-services [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  start         Start CLX services (Ollama)"
        echo "  stop          Stop CLX services"
        echo "  restart       Restart CLX services"
        echo "  status        Show service status"
        echo "  logs          Follow service logs"
        echo "  pull-models   Pull required Ollama models"
        echo ""
        echo "Examples:"
        echo "  clx-services start"
        echo "  clx-services pull-models"
        echo "  clx-services logs"
        exit 1
        ;;
esac
