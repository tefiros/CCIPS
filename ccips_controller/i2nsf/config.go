package i2nsf

import (
	"encoding/json"
	"fmt"
	log "i2nsf-controller/logger"
	"i2nsf-controller/swagger"
	"io/ioutil"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
)

// LifetimeConfig stores the lifetime configuration of the IPsec tunnel
type LifetimeConfig struct {
	nBytes   int64
	nPackets int64
	time     int64
	timeIdle int64
}

// CryptoConfig stores and manages the cryptographic material of the IPsec tunnel
type CryptoConfig struct {
	encAlg        EncAlgType
	intAlg        AuthAlgType
	encKeyLength  int64
	authKeyLength int64
	// Crypto values
	encKey []byte
	intKey []byte
	iv     []byte
	lock   sync.RWMutex
}

func NewCryptoConfig(encAlg EncAlgType, authAlg AuthAlgType) *CryptoConfig {
	// TODO guess the length of keys from algtypes
	return &CryptoConfig{
		encAlg:        encAlg,
		intAlg:        authAlg,
		encKeyLength:  ENCKEYLENGTH[encAlg],
		authKeyLength: AUTHKEYLENGTH[authAlg],
	}
}

// SetNewCryptoValues this method changes generates and changes the cryptographic material of the IPsecConfig
// NOTE: for future implementations, the way to generate this values should be replaced by an interface. In this way
// we can implement different random generators or modify this values depending on the PoC
func (c *CryptoConfig) SetNewCryptoValues() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	// Set new encKey
	c.encKey = make([]byte, c.encKeyLength)
	rand.Read(c.encKey)
	// Set mew intKey
	c.intKey = make([]byte, c.authKeyLength)
	rand.Read(c.intKey)
	// Set IV
	c.iv = make([]byte, c.encKeyLength)
	rand.Read(c.iv)
	return nil
}

type IPsecConfigType int

const (
	// H2H Used for host to host configuration
	H2H IPsecConfigType = 0
	// G2G Used for gateway to gateway configuration
	G2G = 1
)

// IpsecConfig stores and manages the IPsec configuration of one direction
type IpsecConfig struct {
	lock sync.RWMutex
	// Standard values
	confType IPsecConfigType
	name     string
	spi      int64
	reqId    int64
	// Config Addresses
	origin string // Always outbound
	end    string // Always inbound
	// Prefix addresses only for g2g case
	prefixOrigin string
	prefixEnd    string
	// Data Addresses
	dataOrigin string
	dataEnd    string

	// DMZ
	dmzOrigin string
	dmzEnd    string
	// Crypto data
	cryptoConfig *CryptoConfig
	// Lifetime config
	softLifetime *LifetimeConfig
	hardLifetime *LifetimeConfig
	// lastRekey
	timestamp  int64
	uuid       uuid.UUID
	reKeysDone map[int64]bool
}

// ToJSON converts an IpsecConfig instance to its JSON representation.
func (config *Handler) ToJSON(id uuid.UUID) (string, error) {
	// Acquire a read lock to safely access the structure
	//config.lock.RLock()
	//defer config.lock.RUnlock()

	// Convert the structure to JSON
	jsonData, err := json.Marshal(config.GetConfigH())
	if err != nil {
		return "", err
	}
	log.Debug("pruebaaaa: %s", jsonData)
	return string(jsonData), nil
}

// SendJSON sends the JSON representation of the configuration to a specific URL using a POST request
/*func (config *IpsecConfig) SendJSON(url string) error {
	jsonString, err := config.ToJSON()
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer([]byte(jsonString)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send JSON: received status %s", resp.Status)
	}

	return nil
}*/

func SaveConfigToFile(config *Handler, filename string, id uuid.UUID) error {
	// Get the JSON representation
	jsonData, err := config.ToJSON(id)
	if err != nil {
		return err
	}

	// Save JSON data to file
	err = ioutil.WriteFile(filename, []byte(jsonData), 0644)
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

// NewConfigFromSwagger function that returns
func NewConfigFromSwagger(node1, node2 swagger.Node, softLifetime, hardLifetime swagger.LifetimeConfig, confType IPsecConfigType, cryptoCfg *CryptoConfig, id uuid.UUID) (cfg *IpsecConfig, err error) {
	cfg = &IpsecConfig{
		reKeysDone: make(map[int64]bool),
	}
	cfg.uuid = id
	cfg.confType = confType
	cfg.name = fmt.Sprintf("out/%s/in/%s", node1.IpData, node2.IpData)
	// Set control ips
	cfg.origin = node1.IpControl
	cfg.end = node2.IpControl

	if cfg.confType == G2G {
		// Setup internal networks
		cfg.prefixOrigin = node1.NetworkInternal
		cfg.prefixEnd = node2.NetworkInternal
		// Setup DMZ
		cfg.dmzOrigin = node1.IpDMZ
		cfg.dmzEnd = node2.IpDMZ
	}
	// Set data ips
	cfg.dataOrigin = node1.IpData
	cfg.dataEnd = node2.IpData
	cfg.timestamp = time.Now().Unix()
	// Setup random reqid
	// TODO need to check between which values can we range the cfg
	// also this must be handled by an external handler like the SPIs.
	cfg.reqId = int64(rand.Intn(1e4))
	log.Debug("Generated reqId is %d", cfg.reqId)
	// Setup crypto config
	cfg.cryptoConfig = cryptoCfg
	if err := cryptoCfg.SetNewCryptoValues(); err != nil {
		return nil, err
	}
	// Lifetime
	// TODO change this to
	cfg.softLifetime = &LifetimeConfig{
		int64(softLifetime.NBytes),
		int64(softLifetime.NPackets),
		int64(softLifetime.NTime),
		int64(softLifetime.NTimeIdle),
	}
	cfg.hardLifetime = &LifetimeConfig{
		int64(hardLifetime.NBytes),
		int64(hardLifetime.NPackets),
		int64(hardLifetime.NTime),
		int64(hardLifetime.NTimeIdle),
	}
	return cfg, nil

}

func (c *IpsecConfig) SetNewSPI() {
	c.spi = spiManager.GetNewSPI()
}

// CreateDelSAD wrapper of the formatDelSAD
func (c *IpsecConfig) CreateDelSAD() string {
	return formatDelSADJson(c)
}

// CreateDelSPD wrapper of the formatDelSPD
func (c *IpsecConfig) CreateDelSPD() string {
	return formatDelSPDJson(c)
}

// CreateSADConfig returns the <sad-entry> configuration based in the current status of the IPsecConfigStructure
func (c *IpsecConfig) CreateSADConfig() (outCfg string, inCfg string, err error) {
	switch c.confType {
	case G2G:
		{
			// First set the config for the
			outCfg = formatG2GSADValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd) //antes c.dataOrigin donde DMZ
			inCfg = formatG2GSADValues(c, c.prefixOrigin, c.prefixEnd, c.dataOrigin, c.dmzEnd)  //antes c.dataOrigin donde DMZ; dmzEnd antes era dataEnd
		} //(c, c.prefixEnd, c.prefixOrigin, c.dmzEnd, c.dataOrigin)
	default:
		outCfg = formatH2HSADValues(c, c.dataOrigin, c.dataEnd)
		inCfg = formatH2HSADValues(c, c.dataOrigin, c.dataEnd)
	}
	return outCfg, inCfg, err
}

func (c *IpsecConfig) CreateSADConfigJson() (outCfg string, inCfg string, err error) {
	switch c.confType {
	case G2G:
		{
			// First set the config for the
			outCfg = formatG2GSADValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd) //antes c.dataOrigin donde DMZ
			inCfg = formatG2GSADValues(c, c.prefixOrigin, c.prefixEnd, c.dataOrigin, c.dmzEnd)  //antes c.dataOrigin donde DMZ; dmzEnd antes era dataEnd
		} //(c, c.prefixEnd, c.prefixOrigin, c.dmzEnd, c.dataOrigin)
	default:
		outCfg = formatH2HSADValuesJson(c, c.dataOrigin, c.dataEnd)
		inCfg = formatH2HSADValuesJson(c, c.dataOrigin, c.dataEnd)
	}
	return outCfg, inCfg, err
}

// CreateSPDConfig returns the <spd-entry> configuration based in the current status of the IPsecConfigStructure
func (c *IpsecConfig) CreateSPDConfig() (outCfg string, inCfg string, err error) {
	switch c.confType {
	case G2G:
		{
			// First set the config for the
			outCfg = formatG2GSPDValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd, "outbound") // antes c.dataOrigin donde DMZ
			inCfg = formatG2GSPDValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd, "inbound")   // antes c.dataOrigin donde DMZ igual que la de arriba los origenes y ends
		} //(c, c.prefixEnd, c.prefixOrigin, c.dmzEnd, c.dataOrigin, "inbound")
	default:
		{
			outCfg = formatH2HSPDValues(c, c.dataOrigin, c.dataEnd, "outbound")
			inCfg = formatH2HSPDValues(c, c.dataOrigin, c.dataEnd, "inbound")
		}
	}
	return outCfg, inCfg, err
}

func (c *IpsecConfig) CreateSPDConfigJson() (outCfg string, inCfg string, err error) {
	switch c.confType {
	case G2G:
		{
			// First set the config for the
			outCfg = formatG2GSPDValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd, "outbound") // antes c.dataOrigin donde DMZ
			inCfg = formatG2GSPDValues(c, c.prefixOrigin, c.prefixEnd, c.dmzOrigin, c.dataEnd, "inbound")   // antes c.dataOrigin donde DMZ igual que la de arriba los origenes y ends
		} //(c, c.prefixEnd, c.prefixOrigin, c.dmzEnd, c.dataOrigin, "inbound")
	default:
		{
			outCfg = formatH2HSPDValuesJson(c, c.dataOrigin, c.dataEnd, "outbound")
			inCfg = formatH2HSPDValuesJson(c, c.dataOrigin, c.dataEnd, "inbound")
		}
	}
	return outCfg, inCfg, err
}

func encAlgDecoder(alg EncAlgType) string {
	switch alg {
	case 2:
		return "des-cbc"
	case 3:
		return "3-des-cbc"
	case 6:
		return "cast-cbc"
	case 7:
		return "blowfish-cbc"
	case 12:
		return "aes-cbc"
	case 13:
		return "aes-ctr"
	case 14:
		return "aes-ccmv-8"
	case 15:
		return "aes-ccmv-12"
	case 16:
		return "aes-ccmv-16"
	case 18:
		return "aes-gcmv-8"
	case 19:
		return "aes-gcmv-12"
	case 10:
		return "aes-gcmv-16"
	default:
		return "Algorithm not Identified"
	}
}

func intAlgDecoder(alg AuthAlgType) string {
	switch alg {
	case 2:
		return "md5"
	case 3:
		return "sha1"
	case 5:
		return "sha2-256"
	case 6:
		return "sha2-384"
	case 7:
		return "sha2-512"
	case 8:
		return "ripemd-160"
	case 9:
		return "aes-cbc-mac"
	default:
		return "Algorithm not Identified"
	}
}

func (c *IpsecConfig) ParseConfigToSwagger() *swagger.I2NSFConfigResponse {
	return &swagger.I2NSFConfigResponse{
		Id: c.uuid.String(),
		Nodes: []swagger.Node{
			{IpControl: c.origin, NetworkInternal: c.prefixOrigin, IpData: c.dataOrigin, IpDMZ: c.dmzOrigin},
			{IpControl: c.end, NetworkInternal: c.prefixEnd, IpData: c.dataEnd, IpDMZ: c.dmzEnd},
		},
		Status:       "Deployed",
		SoftLifetime: float64(c.softLifetime.time),
		HardLifetime: float64(c.hardLifetime.time),
		EncAlg:       encAlgDecoder(c.cryptoConfig.encAlg),
		IntAlg:       intAlgDecoder(c.cryptoConfig.intAlg),
	}
}
