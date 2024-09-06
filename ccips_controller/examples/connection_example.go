package main

import (
	"fmt"
	"github.com/openshift-telco/go-netconf-client/netconf"
	"github.com/openshift-telco/go-netconf-client/netconf/message"
	"golang.org/x/crypto/ssh"
	log "i2nsf-controller/logger"
	"os"
	"sync"
)

// The purpose of this script is only for testing the communication with sysrepo using the netconf client

func main() {
	log.NewLogger()
	sshConfig := &ssh.ClientConfig{
		User:            "netconf",
		Auth:            []ssh.AuthMethod{ssh.Password("netconf")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	s, err := netconf.DialSSH(fmt.Sprintf("192.168.165.169:%d", 830), sshConfig)
	if err != nil {
		log.Fatal("Error connecting to ssh: %s", err)
	}
	// Print capabilities
	capabilities := netconf.DefaultCapabilities
	err = s.SendHello(&message.Hello{Capabilities: capabilities})
	if err != nil {
		log.Fatal("Error asking for capabilities: %s", err)
	}
	log.Info("Session established")
	// Get Config
	//    g := message.NewGetConfig(message.DatastoreRunning, message.FilterTypeSubtree, "")
	//    msg, err := s.SyncRPC(g,100)
	//    if err != nil {
	//        log.Fatal(err.Error())
	//    }
	//    log.Info(msg.RawReply)

	// Lets try to setup a new config file
	dat, err := os.ReadFile("add_sad_g2g.xml")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(string(dat))
	editMessage := message.NewEditConfig(message.DatastoreRunning, message.DefaultOperationTypeReplace, string(dat))
	msg2, err := s.SyncRPC(editMessage, 100)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Info(msg2.RawReply)

	// Del from sysrepo
	//    delDat, err := os.ReadFile("del_sad_g2g.xml")
	//    if err != nil {
	//        log.Fatal(err.Error())
	//    }
	//    deleteMessage := message.NewEditConfig(message.DatastoreRunning, message.DefaultOperationTypeReplace, string(delDat))
	//    msg3, err := s.SyncRPC(deleteMessage, 100)
	//    if err != nil {
	//        log.Fatal(err.Error())
	//    }
	//    log.Info(msg3.RawReply)
	//    var wg sync.WaitGroup

	// Notification management

	// First create a callBack
	callback := func(event netconf.Event) {
		reply := event.Notification()
		println(reply.RawReply)
	}
	if err := s.CreateNotificationStream(1, "", "", "", callback); err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
