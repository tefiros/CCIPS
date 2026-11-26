<!-- # © 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. -->

# CCIPS 


## ccips-cfgipsec
Includes the latest agent code, it may have some additional code to another development usiging the enarx framework on the /src directory 

## ccips-controller
Includes the latest controller code developed on Go.

### Aditional notes
Each directory has the corresponding README


# Deployment 

## Requirements

* Have a running CCIPS Controller. [How launch and build](https://github.com/tefiros/CCIPS/blob/main/ccips_controller/README.md)
* Have two CCIPS agents. [Installation guide](https://github.com/tefiros/CCIPS/tree/main/ccips-cfgipsec#installation-guide)
* A Mgmnt Network to allow communication between the Controller and the agents.
* A Data network to so both agents can see each other.

## Setting up all the process:

## Controller

In the VM with the controller just run the following command:
```bash!
sudo docker build -t ccips-controller .
sudo docker compose up
```
This will start a process that runs an HTTP server that handles the requests to deploy the IPsec Tunnel.

## Agents
In this scenario we are deploying two Agent running in docker mode.

Here you only need to run as follows in each agent.
```bash!
docker run -it --network host --cap-add ALL --name ccips_agent --rm ccips_agent
```

## Hybridization configuration

Send a JSON configuration to `POST /ccips/config-hybridization`:

```bash
curl -X POST 'https://controller_ip:5000/ccips/config-hybridization' \
  -H 'Content-Type: application/json' \
  -d '{
    "use-qkd": "yes",
    "pqc-algorithm": "kyber-512",
    "hybridization-method": "xor",
    "endpoint1": "192.168.159.35",
    "endpoint2": "192.168.159.21"
  }'
```

The controller's HTTPS certificate must be trusted by the client. All fields shown
are required: `use-qkd` accepts `yes` or `no`, `hybridization-method` accepts
`xor` or `none`, and both endpoints must be IPv4 addresses. `pqc-algorithm` must
be a non-empty string. The optional `method` must also be a non-empty string;
when omitted, it defaults to `http`.

A valid request returns `200 OK` with the configuration, including `method`.
Invalid JSON or fields return `400` with an error message. Currently the endpoint
only validates and returns the configuration; it does not apply or forward it.

## Deploying the tunnel
### H2H
You can check a similar demo in the [SPIRS Repository](https://www.spirs-project.eu/nextcloud/index.php/s/fBXpkbeH9WGKfMF).
![](https://hackmd.io/_uploads/H1_I7MFz6.png)

### Controller request
To configure a H2H tunnel (transport mode) so you can enable a encrypted communication between networks 192.168.165.169 and 192.168.165.93 you can request the following to the controller
```bash!
curl -X 'POST' \
  'http://controller_ip:5000/ccips' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "nodes": [
      {
        "ipData": "10.0.0.100",
        "ipControl": "192.168.165.93"
      },
    {
      "ipData": "10.0.0.10",
      "ipControl": "192.168.165.169"
    }
  ],
  "encAlg": [
    "3-des-cbc"
  ],
  "intAlg": [
    "sha1"
  ],
  "softLifetime": {
    "nTime": 25
  },
  "hardLifetime": {
    "nTime": 50
  }
}'
```

### How to check the entries:
* SPD entries:
```
ip xfrm policy
```
* SAD entries:
```
ip xfrm state
```

### Reset scenario

## Standard reset
If everything has run succesfuly, you can delete the deployed tunnel following this command:
```bash
curl -X 'DELETE' \
  'http://controller_ip:5000/ccips/{id}'
```



### Removing entries from sysrepo

If you are running the ccips without using the cointainer, it could be possible to have some entries stuck in sysrepo. To remove them, under the directory `examples` in the ccips_controller proyect, there is an script called `removeEntries.go` that tries to remove the sysrepo entries associated with the SAD and SPD entries from a set of servers. 

You can change the servers ips at **line 49**

Note that you should first kill the ccips process before trying to remove the entries from sysrepo. 

### Removing SAD and SPD entries from kernel

* SPD entries:
```
ip xfrm policy flush
```
* SAD entries:
```
ip xfrm state flush
```


## G2G
![](https://hackmd.io/_uploads/rkmumMFM6.png)

### Controller request
To configure a G2G tunnel (tunnel mode) so you can enable a encrypted communication between networks 192.168.100.0/24 and 192.168.200.0/24 you can request the following to the controller.

```bash!
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
### How to check the entries:
* SPD entries:
```
ip xfrm policy
```
* SAD entries:
```
ip xfrm state
```

### Reset scenario

## Standard reset
If everything has run succesfuly, you can delete the deployed tunnel following this command:
```bash
curl -X 'DELETE' \
  'http://controller_ip:5000/ccips/{id}'
```


### Removing entries from sysrepo

If you are running the ccips without using the cointainer, it could be possible to have some entries stuck in sysrepo. To remove them, under the directory `examples` in the ccips_controller proyect, there is an script called `removeEntries.go` that tries to remove the sysrepo entries associated with the SAD and SPD entries from a set of servers. 

You can change the servers ips at **line 49**

Note that you should first kill the ccips process before trying to remove the entries from sysrepo. 

### Removing SAD and SPD entries from kernel

* SPD entries:
```
ip xfrm policy flush
```
* SAD entries:
```
ip xfrm state flush
```

# Modes of operation
![](https://hackmd.io/_uploads/Hk6Mhj9xa.png)

## Host-To-Host
This mode of operation, is for only between two hosts, with direct visibility.

![](https://hackmd.io/_uploads/SJlfhi9la.png)

## Gateway-To-Gateway
This mode of operation, is for enabling a protected communication between two subnetworks.

![](https://hackmd.io/_uploads/ByTxhscx6.png)