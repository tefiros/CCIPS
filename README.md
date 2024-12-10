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
* Have two CCIPS agents.
* A Mgmnt Network to allow communication between the Controller and the agents.
* A Data network to so both agents can see each other.

## Setting up all the process:

## Controller

In the VM with the controller just run the following command:
```bash!
docker run -it --rm -p 5000:5000 ccips_controller
```
This will start a process that runs an HTTP server that handles the requests to deploy the IPsec Tunnel.

## Agents
In this scenario we are deploying one Agent running with the Enarx TA version and another agent running the standalone.

Here you only need to run the standalone version as follows.
```bash!
docker run -it --network host --cap-add ALL --name ccips_agent --rm ccips_agent
```

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
  'http://controller_ip:5000/ccips' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "nodes": [
    {
        "ipData": "192.168.165.169",
        "ipControl": "192.168.165.169",
        "networkInternal" : "192.168.100.0/24"  
    },
    {
        "ipData": "192.168.165.93",
        "ipControl": "192.168.165.93",
        "networkInternal" : "192.168.200.0/24"
    }
  ],
  "encAlg": [
    "3-des-cbc"
  ],
  "intAlg": [
    "sha1"
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
