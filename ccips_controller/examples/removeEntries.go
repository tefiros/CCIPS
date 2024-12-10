package main

import (
	"encoding/xml"
	"fmt"
	"github.com/openshift-telco/go-netconf-client/netconf"
	"github.com/openshift-telco/go-netconf-client/netconf/message"
	"golang.org/x/crypto/ssh"
	"i2nsf-controller/i2nsf"
	log "i2nsf-controller/logger"
	"strings"
)

type SADEntry struct {
	Name  string `xml:"name"`
	ReqID string `xml:"reqid"`
	SPI   int64  `xml:"ipsec-sa-config->spi"`
}

type SAD struct {
	Entries []SPDEntry `xml:"sad-entry"`
}

type SPDEntry struct {
	Name  string `xml:"name"`
	ReqID string `xml:"reqid"`
}

type SPD struct {
	Entries []SPDEntry `xml:"spd-entry"`
}

type IpsecIkeless struct {
	Spd SPD `xml:"spd"`
	Sad SAD `xml:"sad"`
}

type Data struct {
	IpsecIkeless IpsecIkeless `xml:"ipsec-ikeless"`
}

func main() {
	log.NewLogger()
	sshConfig := &ssh.ClientConfig{
		User:            "netconf",
		Auth:            []ssh.AuthMethod{ssh.Password("netconf")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	servers := []string{"192.168.165.169:830", "192.168.165.93:830"}
	for _, address := range servers {
		s, err := netconf.DialSSH(address, sshConfig)
		//s, err := netconf.DialSSH(fmt.Sprintf("192.168.165.169:%d", 830), sshConfig)
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
		g := message.NewGetConfig(message.DatastoreRunning, message.FilterTypeSubtree, "<ipsec-ikeless\n  xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\"\n  xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<spd>\n</spd>\n<sad>\n</sad>\n</ipsec-ikeless>")
		msg, err := s.SyncRPC(g, 100)
		if err != nil {

			log.Fatal(err.Error())
		}
		log.Info(msg.Data)

		var entries Data
		if err := xml.Unmarshal([]byte(msg.Data), &entries); err != nil {
			panic(err)
		}
		log.Info(string(len(entries.IpsecIkeless.Spd.Entries)))

		err = i2nsf.LoadTemplates("../templates")
		if err != nil {
			panic(err)
		}

		for _, entry := range entries.IpsecIkeless.Spd.Entries {
			t := i2nsf.G2GTemplates[i2nsf.DelSPD]
			t = replace(t, "ID_NAME", entry.Name)
			t = replace(t, "REQ_ID", entry.ReqID)
			t = replace(i2nsf.EditconfigTemplate, "REPLACE_DATA", fmt.Sprintf("<spd>%s</spd>", t))
			deleteMessage := message.NewEditConfig(message.DatastoreRunning, message.DefaultOperationTypeReplace, string(t))
			msg3, err := s.SyncRPC(deleteMessage, 100)
			if err != nil {
				log.Fatal(err.Error())
			}
			log.Info(msg3.RawReply)
		}
	}
}

func replace(template string, replaceName string, val interface{}) (newT string) {
	switch val.(type) {
	case bool:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%t", val), -1)
	case string:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%s", val), -1)
	case int, int8, int16, int64, uint, uint8, uint16, uint64:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%d", val), -1)
	case []byte:
		{
			input := fmt.Sprintf("%x", val)
			chunks := make([]string, 0, len(input)/2)
			for i := 0; i < len(input); i += 2 {
				if i+2 > len(input) {
					chunks = append(chunks, input[i:])
				} else {
					chunks = append(chunks, input[i:i+2])
				}
			}
			// join the chunks with ":" separator
			output := strings.Join(chunks, ":")
			newT = strings.Replace(template, replaceName, fmt.Sprintf("%s", output), -1)
		}
	default:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%v", val), -1)
	}
	return newT
}
