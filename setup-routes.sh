#!/bin/bash

echo "=== Configurando rutas en test1 ==="
docker exec -it test1 sh -c "
  ip route del default 2>/dev/null || true
  ip route add default via 192.168.1.100
  echo 'Rutas en test1:'
  ip route show
"

echo -e "\n=== Configurando rutas en test2 ==="
docker exec -it test2 sh -c "
  ip route del default 2>/dev/null || true
  ip route add default via 192.168.2.100
  echo 'Rutas en test2:'
  ip route show
"

echo -e "\n=== Configurando agent1 ==="
docker exec -it ccips_agent1 sh -c "
  # Detectar interfaz data
  DATA_IFACE=\$(ip addr | grep -B2 '10.0.0.101' | head -1 | awk '{print \$2}' | awk -F'@' '{print \$1}')
  ip route add 192.168.2.0/24 via 10.0.0.102 dev \$DATA_IFACE 2>/dev/null || true
  echo 'Rutas en agent1:'
  ip route show
"

echo -e "\n=== Configurando agent2 ==="
docker exec -it ccips_agent2 sh -c "
  # Detectar interfaz data
  DATA_IFACE=\$(ip addr | grep -B2 '10.0.0.102' | head -1 | awk '{print \$2}' | awk -F'@' '{print \$1}')
  ip route add 192.168.1.0/24 via 10.0.0.101 dev \$DATA_IFACE 2>/dev/null || true
  echo 'Rutas en agent2:'
  ip route show
"

echo -e "\n✅ Configuración completada. Prueba conectividad:"
echo "  docker exec -it test1 ping -c 3 192.168.2.101"

