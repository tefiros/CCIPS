module i2nsf-controller

go 1.21

toolchain go1.21.3

require (
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/openshift-telco/go-netconf-client v1.0.6
	golang.org/x/crypto v0.29.0
)

require golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect

require (
	github.com/nemith/netconf v0.0.2
	golang.org/x/sys v0.27.0 // indirect
)

replace github.com/openshift-telco/go-netconf-client => github.com/hugorp97/go-netconf-client v1.0.6
