# CCIPS Docker Compose - Escenario Local (1 Controlador + 2 Agentes)

Este `docker-compose.yml` moderno levanta un escenario completo de **CCIPS** en Docker con:

- **1 Controlador** (Go, API REST en puerto 5000)
- **2 Agentes CCIPS** (Sysrepo + Netopeer2 + PF_KEY/XFRM)
- **2 Contenedores de prueba** (Alpine Linux para validación de conectividad)

## Topología de redes

```
┌─────────────────────────────────────────────────────────────────┐
│                     CONTROL NETWORK (192.168.100.0/24)          │
│                                                                 │
│  Controller          Agent1              Agent2                 │
│  192.168.100.100    192.168.100.101     192.168.100.102        │
│                     (NETCONF:830)       (NETCONF:830)          │
└─────────────────────────────────────────────────────────────────┘
         │                 │                    │
         └─────────────────┼────────────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    v                      v                      v
DATA NET (10.0.0.0/24)
    Agent1              Agent2
   10.0.0.101         10.0.0.102
    (GRE/IPsec tunnel)
    │                  │
    └──────────────────┘

INTERNAL1 (192.168.1.0/24)     INTERNAL2 (192.168.2.0/24)
    │                               │
    └─ Agent1 ──────────────────────┴─ Agent2
       192.168.1.100                192.168.2.100
       │                            │
       v                            v
     Test1                        Test2
   192.168.1.101               192.168.2.101
```

## Requisitos

- **Docker** y **docker-compose** (versión 3.8+)
- **Linux con soporte IPsec en el kernel**:
  ```bash
  grep -i xfrm /boot/config-$(uname -r)
  # Debe mostrar:
  # CONFIG_XFRM=y
  # CONFIG_NET_KEY=y
  ```
- **Permisos de sudoer** (para `docker` y cambios de red)

## Estructura del proyecto

```
CCIPS/
├── ccips_controller/          # Controlador Go (moderno)
│   ├── Dockerfile
│   ├── cmd/
│   ├── i2nsf/
│   ├── go.mod
│   └── ...
├── ccips-cfgipsec/            # Agente CCIPS (moderno)
│   ├── Dockerfile
│   ├── src/
│   ├── yang/
│   ├── CMakeLists.txt
│   └── ...
└── docker-compose-local.yml   # Este archivo
```

## Instrucciones de uso

### 1. Verificar soporte IPsec

```bash
uname -r
grep -i xfrm /boot/config-$(uname -r) | head -5
# Si no ves CONFIG_XFRM=y, el kernel no tiene soporte IPsec compilado, si es CONFIG_XFRM=m, tienes que activar el modulo
```

### 2. Levantar los contenedores

Desde la **raíz del proyecto CCIPS**:

```bash
# Modo foreground (para ver logs)
docker compose -f docker-compose-local.yml up

# O en background
docker compose -f docker-compose-local.yml up -d
```

**Tiempo esperado de arranque**: 30-90 segundos (compila Go y C).

### 3. Verificar que está todo operativo

```bash
# Ver logs del controlador
docker compose -f docker-compose-local.yml logs controller

# Ver logs de agentes
docker compose -f docker-compose-local.yml logs agent1
docker compose -f docker-compose-local.yml logs agent2

# Listar contenedores
docker ps | grep ccips
```

Deberías ver algo como:
```
ccips_controller    (puerto 5000 expuesto)
ccips_agent1        (NETCONF en 192.168.100.101:830)
ccips_agent2        (NETCONF en 192.168.100.102:830)
test1               (en red internal1)
test2               (en red internal2)
```

### 4. Configurar el túnel IPsec

Una vez todo levantado, ejecuta el siguiente comando **desde el host** para crear un túnel G2G entre `192.168.1.0/24` y `192.168.2.0/24`:

```bash
curl -X 'POST' \
  'http://localhost:5000/i2nsf' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "encAlg": [
    "aes-cbc"
  ],
  "hardLifetime": 3600,
  "intAlg": [
    "sha2-256"
  ],
  "softLifetime": 1800,
  "nodes": [
    {
      "ipControl": "192.168.100.101",
      "ipData": "10.0.0.101",
      "networkInternal": "192.168.1.0/24"
    },
    {
      "ipControl": "192.168.100.102",
      "ipData": "10.0.0.102",
      "networkInternal": "192.168.2.0/24"
    }
  ]
}'
```

**Respuesta esperada**: HTTP 200 con ID del túnel (UUID).

#### Parámetros disponibles

- **encAlg**: `des`, `3des`, `aes-cbc`, `aes-ctr`, `aes-ccmv-8`, `aes-ccmv-12`, `aes-ccmv-16`, `aes-gcmv-8`, `aes-gcmv-12`, `aes-gcmv-16`
- **intAlg**: `hmac-md5-96`, `hmac-md5-128`, `hmac-sha1-96`, `hmac-sha1-160`, `sha2-256`, `sha2-384`, `sha2-512`
- **softLifetime** / **hardLifetime**: segundos (números enteros)

### 5. Verificar que el túnel está funcionando

#### Desde test1, hacer ping a test2:

```bash
docker exec -it test1 ping -c 3 192.168.2.101
```

**Salida esperada**:
```
PING 192.168.2.101 (192.168.2.101): 56 data bytes
64 bytes from 192.168.2.101: seq=0 ttl=64 time=X.XXX ms
64 bytes from 192.168.2.101: seq=1 ttl=64 time=X.XXX ms
64 bytes from 192.168.2.101: seq=2 ttl=64 time=X.XXX ms
```

#### Desde test2, hacer ping a test1:

```bash
docker exec -it test2 ping -c 3 192.168.1.101
```

#### Ver entradas SAD/SPD en el kernel de cada agente:

```bash
# SAD entries en agent1
docker exec -it ccips_agent1 ip xfrm state list

# SPD entries en agent1
docker exec -it ccips_agent1 ip xfrm policy list

# (Lo mismo en agent2)
docker exec -it ccips_agent2 ip xfrm state list
docker exec -it ccips_agent2 ip xfrm policy list
```

### 6. Borrar el túnel

```bash
# Obtener el ID del túnel (UUID) de la respuesta anterior
# Ejemplo: si la respuesta fue {"uuid":"12345678-1234-..."}

curl -X 'DELETE' \
  'http://localhost:5000/i2nsf/12345678-1234-5678-1234-567812345678'
```

Deberías ver desaparecer las entradas SAD/SPD del kernel.

### 7. Apagar los contenedores

```bash
docker compose -f docker-compose-local.yml down

# Si quieres también limpiar volúmenes
docker compose -f docker-compose-local.yml down -v
```

## Solución de problemas

### Error: "Docker daemon not running"

```bash
sudo systemctl start docker
```

### El túnel no se crea (error en la API)

Mira los logs del controlador:

```bash
docker compose -f docker-compose-local.yml logs controller -f
```

Los agentes necesitan estar disponibles en NETCONF. Verifica:

```bash
docker compose -f docker-compose-local.yml logs agent1
docker compose -f docker-compose-local.yml logs agent2
```

### El ping entre test1 y test2 no funciona

1. Verifica que SAD/SPD están en el kernel:
   ```bash
   docker exec -it ccips_agent1 ip xfrm state list
   docker exec -it ccips_agent1 ip xfrm policy list
   ```

2. Si no ves entradas, la API probable no completó la configuración. Mira logs de controlador y agentes.

3. Comprueba que el kernel soporta IPsec:
   ```bash
   grep -i xfrm /boot/config-$(uname -r)
   ```

### Limpiar estado de Sysrepo/kernel

Si queda estado residual entre reintentos:

```bash
# Flush SAD
docker exec -it ccips_agent1 ip xfrm state flush
docker exec -it ccips_agent2 ip xfrm state flush

# Flush SPD
docker exec -it ccips_agent1 ip xfrm policy flush
docker exec -it ccips_agent2 ip xfrm policy flush

# Reiniciar contenedores
docker compose -f docker-compose-local.yml restart agent1 agent2
```

## Nota sobre la compilación

- **Primera ejecución**: tarda 30-90 segundos (compila Go + librerías C).
- **Ejecuciones posteriores**: usa caché de Docker (mucho más rápido).

Si quieres forzar recompilación:

```bash
docker compose -f docker-compose-local.yml build --no-cache
```

## Referencias

- [tefiros/CCIPS](https://github.com/tefiros/CCIPS): Repositorio original
- [RFC 9061](https://datatracker.ietf.org/doc/html/rfc9061): I2NSF IPsec configuration
- [Sysrepo Documentation](https://github.com/sysrepo/sysrepo)
- [Linux XFRM](https://man7.org/linux/man-pages/man8/ip-xfrm.8.html): IPsec kernel API
