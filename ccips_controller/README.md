# I2NSF_go_controller

# CCIPS Controller

The CCIPS controller is developed in go using the [`go-netconf-client`](https://github.com/openshift-telco/go-netconf-client) library.


## API Endpoints

## How to launch
If you are running the CCIPS Controller, directly using the code, you need to first install golang using the instructions from [here](https://go.dev/doc/install).

Then inside the directory of the CCIPS Controller run 
```bash!
go mod tidy
```
This will automatically download all the needed dependencies.

To launch the controller you can go to the folder `./cmd/server/` and run the following command
```bash!
go run main.go
```
It will prompt the following message `INFO: 2023/10/23 15:24:19 main.go:12: HTTP server started`
### Docker version
First build the controller
```bash
docker build -t ccips_controller .
```
To run it, by default it runs at port 5000, so you can run the docker image as follows:
```bash
docker run -it --rm -p 5000:5000 ccips_controller
```

It will prompt the following message `INFO: 2023/10/23 15:24:19 main.go:12: HTTP server started`

# Requests para el controller:

* Nodes: Información de los nodos con lo siguiente:
    - ipData: IP con la que le va a ver el otro agente y la que va a usar para levantar el tunel.
    - ipControl: IP que tiene en la red de control.
    - ipDMZ: IP privada del agente.
    - networkInternal: subred privada.
* encAlg: Algoritmo usado por el tunel para encriptar. soporta:
    - des
    - 3des
    - aes
* intAlg: Algoritmo usado por el tunel para comprobar la integridad de los paquetes. soporta:
    - hmac-md5-96
    - hmac-md5-128
    - hmac-sha1-96
    - hmac-sha1-160
    - hmac-sha2-256
* softLifeTime: Tiempo para inicializar el proceso de rekey.
* hardLifeTime: Tiempo en el que si no se ha realizado el rekey tira el enlace ipsec.

# G2G
```xml

curl -X 'POST' \
'http://10.0.0.82:5000/ccips' \
-H 'accept: application/json' \
-H 'Content-Type: application/json' \
-d '{
"nodes": [
 {
    "ipData": "2.138.181.166",
    "ipControl": "192.168.165.169",
    "ipDMZ": "192.168.1.141",
     "networkInternal" : "192.168.1.0/24" 
 },
 {
     "ipData": "195.37.154.72",
     "ipControl": "10.10.244.245",
     "ipDMZ": "192.168.10.2",
     "networkInternal" : "192.168.10.0/24"
 }
],
"encAlg": [
 "aes-cbc"
],
"intAlg": [
 "sha2-256"
],
"softLifetime": {
 "nTime": 15
},
"hardLifetime": {
 "nTime": 30
}
}'


```
# H2H

```xml
curl -X 'POST' \
  'http://controller_ip:5000/ccips' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "nodes": [
      {
        "ipData": "10.0.0.201",
        "ipControl": "192.168.165.128"
      },
    {
      "ipData": "10.0.0.10",
      "ipControl": "192.168.165.169"
    }
  ],
  "encAlg": [
    "aes-cbc"
  ],
  "intAlg": [
    "sha2-256"
  ],
  "softLifetime": {
    "nTime": 25
  },
  "hardLifetime": {
    "nTime": 50
  }
}'


```
