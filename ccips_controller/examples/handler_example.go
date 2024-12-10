package main

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/openshift-telco/go-netconf-client/netconf"
	"github.com/openshift-telco/go-netconf-client/netconf/message"
	"i2nsf-controller/i2nsf"
	"i2nsf-controller/logger"
	"i2nsf-controller/swagger"
)

func main() {
	err := i2nsf.LoadTemplates("../templates")
	logger.NewLogger()
	if err != nil {
		panic(err)
	}
	// Generate first the cryptographic values
	cryptoConfig := i2nsf.NewCryptoConfig(3, 3)
	softLifeTime := swagger.LifetimeConfig{
		NBytes:    0,
		NPackets:  0,
		NTime:     20,
		NTimeIdle: 0,
	}

	hardLifeTime := swagger.LifetimeConfig{
		NBytes:    0,
		NPackets:  0,
		NTime:     30,
		NTimeIdle: 0,
	}
	cryptoConfig.SetNewCryptoValues()
	node1 := swagger.Node{
		"10.0.1.0/24",
		"192.1.1.1",
		"192.168.165.169",
		"",
	}
	node2 := swagger.Node{
		"10.0.2.0/24",
		"192.2.2.1",
		"192.168.165.93",
		"",
	}
	id := uuid.New()
	var config1, config2 *i2nsf.IpsecConfig
	// Setup swaggerConfig
	if config1, err = i2nsf.NewConfigFromSwagger(node1, node2, softLifeTime, hardLifeTime, i2nsf.G2G, cryptoConfig, id); err != nil {
		panic(err)
	}
	if config2, err = i2nsf.NewConfigFromSwagger(node2, node1, softLifeTime, hardLifeTime, i2nsf.G2G, cryptoConfig, id); err != nil {
		panic(err)
	}
	config1.SetNewSPI()
	config2.SetNewSPI()

	sad1, _, err := config1.CreateSADConfig()
	if err != nil {
		panic(err)
	}

	s1Data := i2nsf.GenerateI2NSFConfig([]string{sad1}, []string{})

	s1, err := i2nsf.EstablishSession("192.168.165.169")
	if err != nil {
		panic(err)
	}

	if err := editConfig(s1, s1Data); err != nil {
		// 	    log.error
		panic(err)
	}

	//h, err := i2nsf.NewHandler(node1.IpControl, node2.IpControl, config1, config2)
	//if err != nil {
	//	panic(err)
	//}
	//err = h.SetInitialConfigValues()
	//if err != nil {
	//	panic(err)
	//}
	//var wg sync.WaitGroup
	//wg.Add(1)
	//wg.Wait()
}

func editConfig(s *netconf.Session, data string) error {
	editMessage := message.NewEditConfig(message.DatastoreRunning, message.DefaultOperationTypeMerge, data)
	reply, err := s.SyncRPC(editMessage, 100)
	if err != nil {
		panic(err)
	}
	if len(reply.Errors) > 0 {
		return errors.New(fmt.Sprintf("RPC error: %v", reply.Errors))
	}
	return err
}
