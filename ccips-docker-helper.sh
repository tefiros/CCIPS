#!/bin/bash

# Script auxiliar para gestionar CCIPS Docker Compose
# Uso: ./ccips-docker-helper.sh [comando] [argumentos]

set -e

COMPOSE_FILE="docker-compose-local.yml"
CONTROLLER_URL="http://localhost:5000"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_help() {
    cat << EOF
${BLUE}CCIPS Docker Compose Helper${NC}

Uso: $(basename "$0") [COMANDO] [ARGUMENTOS]

Comandos:
  up              Levanta los contenedores (foreground)
  up-d            Levanta los contenedores en background
  down            Apaga los contenedores
  logs            Ver logs de todos los servicios
  logs-controller Ver logs del controlador
  logs-agent1     Ver logs del agente 1
  logs-agent2     Ver logs del agente 2
  status          Estado de los contenedores
  tunnel-create   Crea un túnel G2G (parámetros: encAlg intAlg softLifetime hardLifetime)
  tunnel-create-aes-cbc   Crea un túnel con AES-CBC (recomendado para pruebas)
  tunnel-create-aes-gcm  Crea un túnel con AES-GCM (AEAD recomendado)
  tunnel-list     Lista túneles activos
  tunnel-delete   Borra un túnel (parámetro: uuid)
  test-ping       Prueba conectividad test1 -> test2
  test-ping-rev   Prueba conectividad test2 -> test1
  test-sad        Ver SADs en agentes
  test-spd        Ver SPDs en agentes
  clean           Limpia SAD/SPD de los agentes
  rebuild         Recompila sin caché
  shell-agent1    Abre shell en agent1
  shell-agent2    Abre shell en agent2
  shell-test1     Abre shell en test1
  shell-test2     Abre shell en test2
  help            Muestra esta ayuda

Ejemplos:
  $(basename "$0") up
  $(basename "$0") tunnel-create-aes-cbc
  $(basename "$0") test-ping
  $(basename "$0") tunnel-delete 12345678-1234-5678-1234-567812345678

EOF
}

check_compose() {
    if ! command -v docker compose &> /dev/null; then
        echo -e "${RED}Error: docker compose no está instalado${NC}"
        exit 1
    fi
}

check_containers() {
    if ! docker compose -f "$COMPOSE_FILE" ps | grep -q ccips_controller; then
        echo -e "${YELLOW}Advertencia: Los contenedores no están corriendo.${NC}"
        echo -e "Ejecuta: ${BLUE}$(basename "$0") up${NC}"
        return 1
    fi
    return 0
}

cmd_up() {
    echo -e "${BLUE}Levantando CCIPS...${NC}"
    docker compose -f "$COMPOSE_FILE" up
}

cmd_up_d() {
    echo -e "${BLUE}Levantando CCIPS en background...${NC}"
    docker compose -f "$COMPOSE_FILE" up -d
    echo -e "${GREEN}✓ Contenedores levantados${NC}"
    sleep 5
    echo -e "${BLUE}Estado:${NC}"
    docker compose -f "$COMPOSE_FILE" ps
}

cmd_down() {
    echo -e "${BLUE}Apagando CCIPS...${NC}"
    docker compose -f "$COMPOSE_FILE" down
    echo -e "${GREEN}✓ Contenedores apagados${NC}"
}

cmd_logs() {
    docker compose -f "$COMPOSE_FILE" logs -f
}

cmd_logs_service() {
    docker compose -f "$COMPOSE_FILE" logs -f "$1"
}

cmd_status() {
    docker compose -f "$COMPOSE_FILE" ps
}

cmd_tunnel_create() {
    local encAlg="${1:-aes-cbc}"
    local intAlg="${2:-sha2-256}"
    local softLifetime="${3:-1800}"
    local hardLifetime="${4:-3600}"

    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}Creando túnel...${NC}"
    echo "  Cifrado: $encAlg"
    echo "  Autenticación: $intAlg"
    echo "  Soft Lifetime: $softLifetime"
    echo "  Hard Lifetime: $hardLifetime"

    response=$(curl -s -X POST "$CONTROLLER_URL/ccips" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -d "{
        \"encAlg\": [\"$encAlg\"],
        \"hardLifetime\": {
            \"nTime\": $hardLifetime
        },
        \"intAlg\": [\"$intAlg\"],
        \"softLifetime\": {
            \"nTime\": $softLifetime
        },
        \"nodes\": [
            {
                \"ipControl\": \"192.168.100.101\",
                \"ipData\": \"10.0.0.101\",
                \"ipDMZ\": \"10.0.0.101\",
                \"networkInternal\": \"192.168.1.0/24\"
            },
            {
                \"ipControl\": \"192.168.100.102\",
                \"ipData\": \"10.0.0.102\",
                \"ipDMZ\": \"10.0.0.102\",
                \"networkInternal\": \"192.168.2.0/24\"
            }
        ]
    }")

    echo -e "${GREEN}Respuesta del controlador:${NC}"
    echo "$response" | jq . 2>/dev/null || echo "$response"
}

cmd_tunnel_create_aes_cbc() {
    cmd_tunnel_create "aes-cbc" "sha2-256" "1800" "3600"
}

cmd_tunnel_create_aes_gcm() {
    # AES-GCM con ICV de 12 bytes + SHA2-256
    cmd_tunnel_create "aes-gcmv-12" "sha2-256" "1800" "3600"
}

cmd_tunnel_list() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}Túneles activos:${NC}"
    curl -s "$CONTROLLER_URL/ccips" | jq . 2>/dev/null || echo "No hay túneles o error en la API"
}

cmd_tunnel_delete() {
    local uuid="$1"
    if [ -z "$uuid" ]; then
        echo -e "${RED}Error: Debes proporcionar un UUID${NC}"
        exit 1
    fi

    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}Borrando túnel $uuid...${NC}"
    response=$(curl -s -X DELETE "$CONTROLLER_URL/ccips/$uuid")
    echo -e "${GREEN}Respuesta:${NC}"
    echo "$response" | jq . 2>/dev/null || echo "$response"
}

cmd_test_ping() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}Test: ping desde test1 (192.168.1.101) a test2 (192.168.2.101)${NC}"
    docker exec -it test1 ping -c 3 192.168.2.101
}

cmd_test_ping_rev() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}Test: ping desde test2 (192.168.2.101) a test1 (192.168.1.101)${NC}"
    docker exec -it test2 ping -c 3 192.168.1.101
}

cmd_test_sad() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}SAD en agent1:${NC}"
    docker exec -it ccips_agent1 ip xfrm state list || true
    echo ""
    echo -e "${BLUE}SAD en agent2:${NC}"
    docker exec -it ccips_agent2 ip xfrm state list || true
}

cmd_test_spd() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${BLUE}SPD en agent1:${NC}"
    docker exec -it ccips_agent1 ip xfrm policy list || true
    echo ""
    echo -e "${BLUE}SPD en agent2:${NC}"
    docker exec -it ccips_agent2 ip xfrm policy list || true
}

cmd_clean() {
    if ! check_containers; then
        exit 1
    fi

    echo -e "${YELLOW}Limpiando SAD en agent1...${NC}"
    docker exec -it ccips_agent1 ip xfrm state flush || true
    echo -e "${YELLOW}Limpiando SPD en agent1...${NC}"
    docker exec -it ccips_agent1 ip xfrm policy flush || true

    echo -e "${YELLOW}Limpiando SAD en agent2...${NC}"
    docker exec -it ccips_agent2 ip xfrm state flush || true
    echo -e "${YELLOW}Limpiando SPD en agent2...${NC}"
    docker exec -it ccips_agent2 ip xfrm policy flush || true

    echo -e "${GREEN}✓ Limpieza completada${NC}"
}

cmd_rebuild() {
    echo -e "${BLUE}Reconstruyendo sin caché...${NC}"
    docker compose -f "$COMPOSE_FILE" build --no-cache
    echo -e "${GREEN}✓ Reconstrucción completada${NC}"
}

cmd_shell() {
    local container="$1"
    if ! check_containers; then
        exit 1
    fi

    docker exec -it "$container" /bin/sh
}

main() {
    check_compose

    case "${1:-help}" in
        up)              cmd_up ;;
        up-d)            cmd_up_d ;;
        down)            cmd_down ;;
        logs)            cmd_logs ;;
        logs-controller) cmd_logs_service "controller" ;;
        logs-agent1)     cmd_logs_service "agent1" ;;
        logs-agent2)     cmd_logs_service "agent2" ;;
        status)          cmd_status ;;
        tunnel-create)   cmd_tunnel_create "$2" "$3" "$4" "$5" ;;
        tunnel-create-aes-cbc) cmd_tunnel_create_aes_cbc ;;
        tunnel-create-aes-gcm) cmd_tunnel_create_aes_gcm "$2" "$3" ;;
        tunnel-list)     cmd_tunnel_list ;;
        tunnel-delete)   cmd_tunnel_delete "$2" ;;
        test-ping)       cmd_test_ping ;;
        test-ping-rev)   cmd_test_ping_rev ;;
        test-sad)        cmd_test_sad ;;
        test-spd)        cmd_test_spd ;;
        clean)           cmd_clean ;;
        rebuild)         cmd_rebuild ;;
        shell-agent1)    cmd_shell "ccips_agent1" ;;
        shell-agent2)    cmd_shell "ccips_agent2" ;;
        shell-test1)     cmd_shell "test1" ;;
        shell-test2)     cmd_shell "test2" ;;
        help)            print_help ;;
        *)
            echo -e "${RED}Comando desconocido: $1${NC}"
            print_help
            exit 1
            ;;
    esac
}

main "$@"
