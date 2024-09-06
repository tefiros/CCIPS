package i2nsf

type SADBExpireNotification struct {
	EventTime    string `xml:"eventTime"`
	IPsecName    string `xml:"sadb-expire>ipsec-sa-name"`
	SoftLifeTime bool   `xml:"sadb-expire>soft-lifetime-expire"`
}
