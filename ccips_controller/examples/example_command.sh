curl -X 'POST' \
  'http://localhost:8080/ccips' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "nodes": [
    {
      "networkInternal": "10.0.1.0/24",
      "ipData": "192.1.1.1",
      "ipControl": "192.168.165.169"
    },
    {
      "networkInternal": "10.0.2.0/24",
      "ipData": "192.2.2.1",
      "ipControl": "192.168.165.93"
    }
  ],
  "encAlg": [
    "des"
  ],
  "intAlg": [
    "hmac-md5-96"
  ],
  "softLifetime": {
    "nBytes": 0,
    "nPackets": 0,
    "nTime": 20000,
    "nTimeIdle": 0
  },
  "hardLifetime": {
    "nBytes": 0,
    "nPackets": 0,
    "nTime": 3000000,
    "nTimeIdle": 0
  }
}'


curl -X 'POST' \
  'http://localhost:5000/ccips' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "nodes": [
      {
        "ipData": "192.168.165.93",
        "ipControl": "192.168.165.93"
      },
    {
      "ipData": "192.168.165.169",
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
    "nTime": 500
  },
  "hardLifetime": {
    "nTime": 1000
  }
}'



curl -X 'DELETE' \
  'http://localhost:5000/ccips/7d101f68-2f94-4db8-bb84-31d47c3e7a92' \
  -H 'accept: application/json'