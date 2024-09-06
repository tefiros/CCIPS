package main

import (
	"bytes"
	"encoding/xml"
	"github.com/openshift-telco/go-netconf-client/netconf/message"
	log "i2nsf-controller/logger"
	"os"
	"strings"
)

type SADBExpireNotification struct {
	EventTime    string `xml:"eventTime"`
	IPsecName    string `xml:"sadb-expire>ipsec-sa-name"`
	SoftLifeTime bool   `xml:"sadb-expire>soft-lifetime-expire"`
}

func main() {
	log.NewLogger()
	dat, err := os.ReadFile("sadb_expire_example.xml")
	if err != nil {
		log.Fatal(err.Error())
	}
	not, err := message.NewNotification(dat)
	if err != nil {
		panic(err)
	}
	log.Info("Data %s", not.Data)
	if strings.Contains(not.Data, "sadb-expire") {
		log.Info("Sadb notification received")

	} else {
		log.Error("Not a sadb expire notification")
	}

	var sadbNot SADBExpireNotification

	b := make([]byte, 0)
	buf := bytes.NewBuffer(b)
	_, err = buf.WriteString(not.RawReply)

	if err != nil {
		panic(err)
	}

	//fmt.Printf("%x\n", buf)
	if err := xml.Unmarshal([]byte(not.RawReply), &sadbNot); err != nil {
		panic(err)
	}
	log.Info("IPsecName: %s", sadbNot.IPsecName)
	log.Info("SoftLifeTime: %t", sadbNot.SoftLifeTime)

}
