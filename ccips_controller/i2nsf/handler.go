package i2nsf

import (
	"encoding/xml"
	"errors"
	"fmt"
	log "i2nsf-controller/logger"
	"i2nsf-controller/swagger"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openshift-telco/go-netconf-client/netconf"
	"github.com/openshift-telco/go-netconf-client/netconf/message"
	"golang.org/x/crypto/ssh"
)

type StorageHandler struct {
	storage map[uuid.UUID]*Handler
	lock    sync.RWMutex
}

func NewStorageHandler() *StorageHandler {
	return &StorageHandler{
		storage: make(map[uuid.UUID]*Handler),
	}
}
func (s *StorageHandler) CreateHandler(request *swagger.I2NSFRequest) (interface{}, error) {
	id := uuid.New()
	h, err := NewHandler(request, id)
	log.Debug("Handler created")
	if err != nil {
		return nil, err
	}
	// This will mean that most probably the handler has established the session with the Netconf
	// server
	if err := h.SetInitialConfigValues(); err != nil {
		return nil, err
	}
	log.Debug("Initial values have been established")
	log.Debug("Handler assigned to id %s", id.String())
	s.lock.Lock()
	defer s.lock.Unlock()
	s.storage[id] = h
	log.Debug("Handler %s stored", id.String())
	// Sacar el ID de aqui y hacer la primera llamada a la funcion que guarda/manda el JSON. Se podria en esta función tmb guardar el  uuid para poder acceder a el.
	/*if err := SaveConfigToFile(h, "prueba.json", id); err != nil {
		return nil, err
	}*/
	return h.cfg[0].ParseConfigToSwagger(), err
}

func (s *StorageHandler) DeleteHandler(id uuid.UUID) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if v, ok := s.storage[id]; !ok {
		return errors.New(fmt.Sprintf("Handler with id %x, does not exist", id))
	} else {
		if err := v.Stop(); err != nil {
			return err
		} else {
			delete(s.storage, id)
		}
	}
	return nil
}

// obtain GET
func (s *StorageHandler) GetConfig(id uuid.UUID) interface{} {
	h := *s.storage[id]
	return h.cfg[0].ParseConfigToSwagger()
}

// Para el JSON que luego se usa en el config.go
func (s *Handler) GetConfigH() interface{} {
	return s.cfg[0].ParseConfigToSwagger()
}


var spiManager = new(SPIManager)

type SPIManager struct {
	cSPI int64 // Current SPI number
	lock sync.RWMutex
}

func (s *SPIManager) GetNewSPI() int64 {
	s.cSPI++
	return s.cSPI
}

//var s1, s2 *netconf.Session
//var cfg *IpsecConfig

// outIn is just a manager to facilitate which is the cfg and the order of the session. So always s1 is associated to
// the outbound device and s2 associated with the inbound device
type outIn struct {
	cfg *IpsecConfig
	s1  *netconf.Session
	s2  *netconf.Session
}

type Handler struct {
	s         [4]*netconf.Session // 2 for configuraiton sessions 2 for netconf notifications
	cfg       [2]*IpsecConfig
	ids       map[string]*outIn
	locker    sync.RWMutex
	isStopped bool
}

func NewHandler(request *swagger.I2NSFRequest, id uuid.UUID) (*Handler, error) {
	node1 := request.Nodes[0].IpControl
	node2 := request.Nodes[1].IpControl
	var mode IPsecConfigType
	// Check mode:
	if len(request.Nodes[0].NetworkInternal) == 0 {
		mode = H2H
		log.Debug("New Handler for H2H mode")
	} else {
		mode = G2G
		log.Debug("New Handler for G2G mode")
	}
	var (
		encAlg  EncAlgType
		authAlg AuthAlgType
	)
	if v, ok := ENCALGS[request.EncAlg[0]]; !ok {
		return nil, errors.New(fmt.Sprintf("ENC algorithm not found: %s", request.EncAlg[0]))
	} else {
		encAlg = v
	}
	if v, ok := AUTHALGS[request.IntAlg[0]]; !ok && request.EncAlg[0] != "aes-gcmv-16"{
		return nil, errors.New(fmt.Sprintf("AUTH algorithm not found: %s", request.IntAlg[0]))
	} else {
		authAlg = v
	}

	cryptoConfig := NewCryptoConfig(encAlg, authAlg)
	cfg1, err := NewConfigFromSwagger(request.Nodes[0], request.Nodes[1], request.SoftLifetime, request.HardLifetime, mode, cryptoConfig, id)
	if err != nil {
		return nil, err
	}

	cfg2, err := NewConfigFromSwagger(request.Nodes[1], request.Nodes[0], request.SoftLifetime, request.HardLifetime, mode, cryptoConfig, id)
	if err != nil {
		return nil, err
	}
	cfg1.SetNewSPI()
	cfg2.SetNewSPI()
	//h, err:= newHandler(node1, node2, cfg1, cfg2) //añadido para encriptar
	//return Encrypt(h,swagger.ApiGetCertificate()),err  //añandid para encriptar
	return newHandler(node1, node2, cfg1, cfg2)

}

func newHandler(node1, node2 string, cfg1, cfg2 *IpsecConfig) (*Handler, error) {
	s1Nots, err := EstablishSession(node1)
	if err != nil {
		log.Error("There was an error trying to setup the session with node %s: %s", node1, err.Error())
		return nil, err
	}

	s2Nots, err := EstablishSession(node2)
	if err != nil {
		log.Error("There was an error trying to setup the session with node %s: %s", node2, err.Error())
		return nil, err
	}

	s1, err := EstablishSession(node1)
	if err != nil {
		log.Error("The:re was an error trying to setup the session with node %s", node1)
		return nil, err
	}

	s2, err := EstablishSession(node2)
	if err != nil {
		log.Error("There was an error trying to setup the session with node %s", node2)
		return nil, err
	}

	h := &Handler{
		ids: make(map[string]*outIn, 2),
	}
	// Store session so later we can use this slice to disconnect from them if the tunnel is removed
	h.s[0] = s1
	h.s[1] = s2
	h.s[2] = s1Nots
	h.s[3] = s2Nots
	// Save config
	h.cfg[0] = cfg1
	h.cfg[1] = cfg2
	// Now generate the OutIn config
	h.ids[cfg1.name] = &outIn{cfg1, s1, s2}
	h.ids[cfg2.name] = &outIn{cfg2, s2, s1}

	// Establish subscriptions
	if err := s1Nots.CreateNotificationStream(5, "", "", "", h.HandleNotification); err != nil {
		return nil, err
	}
	if err := s2Nots.CreateNotificationStream(5, "", "", "", h.HandleNotification); err != nil {
		return nil, err
	}

	return h, nil
}

// SetInitialConfigValues
func (h *Handler) SetInitialConfigValues() error {
	var spd1, spd2, sad1, sad2 [2]string
	var err error
	// Set first the
	// Set spd1 outbound and spd2 inbound
	spd1[0], spd2[0], err = h.cfg[0].CreateSPDConfig()
	if err != nil {
		return err
	}
	// Set spd2 outbound and spd1 inbound
	spd2[1], spd1[1], err = h.cfg[1].CreateSPDConfig()
	if err != nil {
		return err
	}
	// Set sad1 outbound and sad2 inbound
	sad1[0], sad2[0], err = h.cfg[0].CreateSADConfig()
	if err != nil {
		return err
	}
	// Set sad2 outbound and sad1 inbound
	sad2[1], sad1[1], err = h.cfg[1].CreateSADConfig()
	if err != nil {
		return err
	}
	log.Debug("Generated configuration values")
	// Now format the data
	s1DataIn := GenerateI2NSFConfig([]string{sad1[1]}, spd1[:])
	s2DataIn := GenerateI2NSFConfig([]string{sad2[0]}, spd2[:])
	s1DataOut := GenerateI2NSFConfig([]string{sad1[0]}, []string{})
	s2DataOut := GenerateI2NSFConfig([]string{sad2[1]}, []string{})

	/*log.Debug("SAD1[1]: %s", sad1[1])
	log.Debug("SAD2[0]: %s", sad2[0])
	log.Debug("SAD1[0]: %s", sad1[0])
	log.Debug("SAD2[1]: %s", sad2[1])*/
	//He hecho los prints y es como esperamos
	// This setup is necessary so no traffic is lost when the SA are established
	// Setup first inbound configs

	if err := editConfig(h.s[0], s1DataIn, 0); err != nil { //los editconfig están modificados ya que NO hay que especificar el endpoint de un proxy
		log.Error("%s: %s", h.cfg[0].origin, err.Error())
		// 	    log.error
		return err
	}

	if err := editConfig(h.s[1], s2DataOut, 0); err != nil { 
		log.Error("%s: %s", h.cfg[1].origin, err.Error())
		return err
	}
	
	// Then setup outbounds configs
	

	if err := editConfig(h.s[0], s1DataOut, 0); err != nil {
		log.Error("%s: %s", h.cfg[0].origin, err.Error())
		// 	    log.error
		return err
	}

	

	if err := editConfig(h.s[1], s2DataIn, 0); err != nil { 
		log.Error("%s: %s", h.cfg[1].origin, err.Error())
		return err
	}
	return nil
}

func (h *Handler) HandleNotification(event netconf.Event) {
	not := event.Notification()
	if strings.Contains(not.Data, "sadb-expire") {
		var sadbNot SADBExpireNotification
		if err := xml.Unmarshal([]byte(not.RawReply), &sadbNot); err != nil {
			log.Error("Incorrect sadb-expire notification", err)
			return
		}
		if err := h.processRekey(&sadbNot); err != nil {
			log.Error(err.Error()) //TODO check error in GUI
		}
	}
}

var threshold int64 = 5

// processRekey Handles the rekey process if a SADBExpireNotification notification has been received.
func (h *Handler) processRekey(notification *SADBExpireNotification) error {
	h.locker.Lock()
	defer h.locker.Unlock()
	if h.isStopped {
		return nil

	}
	s := strings.Split(notification.IPsecName, "_")
	if len(s) < 2 {
		return errors.New("the id of the SAD notificaiton is incorrect")
	}
	id := s[0]
	var manager *outIn
	// Check if the id is in our ids map
	if v, ok := h.ids[id]; !ok {
		return nil
	} else {
		manager = v
	}
	// Initialize variables
	var (
		cfg = manager.cfg
		s1  = manager.s1
		s2  = manager.s2
	)
	log.Debug("Received notification to proceed with rekey of %s", id)
	spi, err := strconv.Atoi(s[1])
	if err != nil {
		log.Error("We should never receive anything different than a number")
		panic(err)
	}
	// Check if timer has expired
	if cfg.spi != int64(spi) || cfg.reKeysDone[int64(spi)] {
		log.Warning("Rekey of %s has been already completed", s[1])
		return nil
	}

	// Set new time
	cfg.reKeysDone[cfg.spi] = true
	oldSPI := cfg.spi

	log.Debug("Timer for %s has expired. Proceed to setup new SADs", cfg.name)
	// If the timer expires
	// Store old SPIs to remove the
	log.Debug("Creating delete config SPI %d from config %s", cfg.spi, cfg.name)
	delSADXml := cfg.CreateDelSAD()
	// Recalculate the new values. For the moment do not handle possible errors
	// Generate new SPIs and crypto material
	cfg.cryptoConfig.SetNewCryptoValues()
	cfg.SetNewSPI()
	// Generate SAD entries
	outSad, inSad, err := cfg.CreateSADConfig() //CAMBIADO por si no se necesita JSON
	s1Data := GenerateI2NSFConfig([]string{outSad}, nil) //CAMBIADO por si no se necesita JSON
	s2Data := GenerateI2NSFConfig([]string{inSad}, nil) //CAMBIADO por si no se necesita JSON
	if err != nil {
		log.Error("Couldn't generate sad entries during the rekey process of %s", cfg.name)
		return err
	}
	// Install SAD entries //TODO check error
	log.Info("Adding new entries out %s in %s SPI %d", cfg.origin, cfg.end, cfg.spi)

	if err := editConfig(s1, s1Data, 0); err != nil {
		log.Error("%s: %s", cfg.origin, err.Error()) //aqui tambien he quitado cfg.origin[0]
		return err
	}
	if err := editConfig(s2, s2Data, 0); err != nil {
		log.Error("%s: %s", cfg.origin, err.Error())
		return err
	}

	// Deleting old entries
	log.Info("Deleting old entries out %s in %s SPI %d", cfg.origin, cfg.end, oldSPI)
	if err := editConfig(s1, delSADXml, 1); err != nil {
		log.Error("%s: %s", cfg.origin, err.Error())
		return err
	}
	if err := editConfig(s2, delSADXml, 1); err != nil {
		log.Error("%s: %s", cfg.origin, err.Error())
		return err
	}

	log.Info("Rekey process of %d already completed", cfg.reqId)

	return nil
}

// Stop closes all sessions and removes SAD/SPD entries without rekeying.
func (h *Handler) Stop() error {
	h.locker.Lock()
	defer h.locker.Unlock()

	for _, i := range h.ids {
		cfg := i.cfg
		s1 := i.s1
		s2 := i.s2

		// Generate del SADs and SPDs
		delSADXml := cfg.CreateDelSAD()
		delSPDXml := cfg.CreateDelSPD()

		// Delete SADs (outbound then inbound)
		if err := editConfig(s1, delSADXml, 1); err != nil {
			log.Error("%s: %s", cfg.origin, err.Error())
		}
		if err := editConfig(s2, delSADXml, 1); err != nil {
			log.Error("%s: %s", cfg.end, err.Error())
		}

		// Delete SPDs (outbound then inbound)
		if err := editConfig(s1, delSPDXml, 1); err != nil {
			log.Error("%s: %s", cfg.origin, err.Error())
		}
		if err := editConfig(s2, delSPDXml, 1); err != nil {
			log.Error("%s: %s", cfg.end, err.Error())
		}

		log.Info("Removed SAD/SPD entries for session %s (reqId=%d)", cfg.name, cfg.reqId)
	}

	h.isStopped = true
	time.Sleep(10 * time.Second)

	for _, s := range h.s {
		// TODO: check if subscription channels are stopped after closing
		if err := s.Close(); err != nil {
			log.Error(err.Error())
		}
	}

	return nil
}


func EstablishSession(address string) (*netconf.Session, error) {
	sshConfig := &ssh.ClientConfig{
		User:            "netconf",
		Auth:            []ssh.AuthMethod{ssh.Password("netconf")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 20,
	}
	s, err := netconf.DialSSH(fmt.Sprintf("%s:%d", address, 830), sshConfig)
	if err != nil {
		return nil, err
	}
	capabilities := netconf.DefaultCapabilities
	err = s.SendHello(&message.Hello{Capabilities: capabilities})
	if err != nil {
		log.Fatal("Error asking for capabilities: %s", err)
	}
	return s, err
}

func editConfig(s *netconf.Session, data string, method int) error {
	var editMessage *message.EditConfig

	if method == 1 {
		// DELETE
		editMessage = message.NewEditConfig(
			message.DatastoreRunning,
			message.DefaultOperationTypeDelete,
			data,
		)
	} else {
		// POST (merge por defecto)
		editMessage = message.NewEditConfig(
			message.DatastoreRunning,
			message.DefaultOperationTypeMerge,
			data,
		)
	}

	reply, err := s.SyncRPC(editMessage, 100)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	if len(reply.Errors) > 0 {
		return fmt.Errorf("RPC error: %v", reply.Errors)
	}

	return nil
}

func defaultLogRpcReplyCallback(eventId string) netconf.Callback {
	return func(event netconf.Event) {
		reply := event.RPCReply()
		if reply == nil {
			println("Failed to execute RPC")
		}
		if event.EventID() == eventId {
			println("Successfully executed RPC")
			println(reply.RawReply)
		}
	}
}

