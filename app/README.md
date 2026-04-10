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
# CCIPS Controller

The CCIPS controller is developed in go using the [`go-netconf-client`](https://github.com/openshift-telco/go-netconf-client) library.


## API Endpoints

### **1. Create IPsec Tunnel**
- **Endpoint:** `/ccips`
- **Method:** `POST`
- **Summary:** Create an IPsec tunnel.
- **Description:** Creates an I2NSF IPsec tunnel using the provided configuration.
- **Request Body (JSON):**

- **Responses:**
- `200 OK`: Tunnel created successfully with details.
- `500 Internal Server Error`: An error occurred while creating the tunnel.

---

### **2. Get IPsec Tunnel Status**
- **Endpoint:** `/ccips/{uuid}`
- **Method:** `GET`
- **Summary:** Retrieve the status of an IPsec tunnel.
- **Description:** Fetches the current status of the IPsec tunnel identified by its UUID.
- **Path Parameters:**
- `uuid` (string, required): The unique identifier of the IPsec tunnel.
- **Responses:**
- `200 OK`: Tunnel status retrieved successfully.
- `400 Bad Request`: Invalid request or UUID.

---

### **3. Delete IPsec Tunnel**
- **Endpoint:** `/ccips/{uuid}`
- **Method:** `DELETE`
- **Summary:** Delete an IPsec tunnel.
- **Description:** Deletes the I2NSF IPsec tunnel identified by its UUID.
- **Path Parameters:**
- `uuid` (string, required): The unique identifier of the IPsec tunnel.
- **Responses:**
- `200 OK`: Tunnel deleted successfully.
- `404 Not Found`: Tunnel not found.
- `500 Internal Server Error`: An error occurred while deleting the tunnel.

---

### **4. Get all tunnel's ids**
- **Endpoint:** `/ccips-all`
- **Method:** `GET`
- **Summary:** Get all tunnel's ids.
- **Description:** Allows retrieve all tunnel's ids.

## How to launch
If you are running the CCIPS Controller, directly using the code, you need to first install python using the instructions from [here](https://packaging.python.org/en/latest/tutorials/installing-packages/).

Then inside the directory of the CCIPS Controller run 
```bash!
python3 --version
```
This will automatically download all the needed dependencies.

To launch the controller you can go to the folder `app/` and run the following command
```bash!
python3 main.py
```
It will prompt the following message:
```bash!
DEBUG: 2026/04/10 09:37:36 main.py:28 HTTP server started
 * Serving Flask app 'main'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.165.118:5000
 ```
### Docker version
First build the controller
```bash
docker build -t ccips-python .
```
To run it, by default it runs at port 5000, so you can run the docker image as follows:
```bash
docker run -it --network host --cap-add ALL --name ccips-python --rm ccips-python
```

It will prompt the following message:
```bash!
DEBUG: 2026/04/10 09:37:36 main.py:28 HTTP server started
 * Serving Flask app 'main'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.165.118:5000
 ```

# Requests for the controller:

* Nodes: Information of the nodes with the following:
    - ipData: IP with which the other agent is going to see it and the one it is going to use to raise the tunnel.
    - ipControl: IP that it has in the control network.
    - ipDMZ: Agent's private IP. (G2G)
    - networkInternal: Private subnet. (G2G)
* encAlg: Algorithm used by the tunnel to encrypt. supports:
    - des
    - 3des
    - aes
* intAlg: Algorithm used by the tunnel to check the integrity of the packets. supports:
     - hmac-md5-96
     - hmac-md5-128
     - hmac-sha1-96
     - hmac-sha1-160
     - hmac-sha2-256
* softLifeTime: Time for initialising the rekey process.
* hardLifeTime: Time in which if the rekey has not been performed, it throws the ipsec link.

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
