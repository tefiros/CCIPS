package i2nsf

import (
	"fmt"
	"testing"
)

func TestIpsecConfig_CreateSADConfig(t *testing.T) {
	err := LoadTemplates("../templates")
	if err != nil {
		panic(err)
	}

	cryptoConfig := &CryptoConfig{
		encAlg:       7,
		intAlg:       7,
		encKeyLength: 4,
		encKey:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
		intKey:       []byte{0xdd, 0xcc, 0xbb, 0xaa},
		iv:           []byte{0x11, 0x11, 0x11, 0x11},
	}

	softConfig := &LifetimeConfig{
		nBytes:   100000,
		nPackets: 200000,
		time:     3000000,
		timeIdle: 400000,
	}

	hardConfig := &LifetimeConfig{
		nBytes:   500000,
		nPackets: 600000,
		time:     700000,
		timeIdle: 800000,
	}

	ipsec := IpsecConfig{
		confType:     G2G,
		name:         "testEntry",
		spi:          12,
		reqId:        24,
		origin:       "10.0.0.1",
		end:          "10.0.0.2",
		prefixOrigin: "192.168.1.0/24",
		prefixEnd:    "192.168.2.0/24",
		dataOrigin:   "24.0.0.1",
		dataEnd:      "24.0.0.2",
		cryptoConfig: cryptoConfig,
		softLifetime: softConfig,
		hardLifetime: hardConfig,
	}

	outSAD, inSAD, err := ipsec.CreateSADConfig()
	if err != nil {
		panic(err)
	}
	outSPD, inSPD, err := ipsec.CreateSPDConfig()
	if err != nil {
		panic(err)
	}

	fmt.Printf("--------- Out entry ---------\n%s\n", GenerateI2NSFConfig([]string{outSAD}, []string{outSPD}))
	fmt.Printf("--------- IN entry ---------\n%s\n", GenerateI2NSFConfig([]string{inSAD}, []string{inSPD}))

	//fmt.Printf("--------- Out SAD entry ---------\n%s\n", outSAD)
	//fmt.Printf("--------- In SAD entry ---------\n%s\n", inSAD)
}
