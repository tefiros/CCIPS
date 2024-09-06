module i2nsf-controller

go 1.20

require (
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/openshift-telco/go-netconf-client v1.0.5
	golang.org/x/crypto v0.6.0
)

require golang.org/x/sys v0.5.0 // indirect

replace github.com/openshift-telco/go-netconf-client => github.com/hugorp97/go-netconf-client v1.0.6
