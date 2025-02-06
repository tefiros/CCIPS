package main

import (
	"i2nsf-controller/i2nsf"
	log "i2nsf-controller/logger"
	"i2nsf-controller/swagger"
	"net/http"
)

func main() {
	log.NewLogger()
	log.Info("HTTP server started")
	if err := i2nsf.LoadTemplates("../../templates/"); err != nil {
		panic(err)
	}
	handlerStorage := i2nsf.NewStorageHandler()
	router := swagger.NewRouter(handlerStorage)
	log.Fatal(http.ListenAndServe(":5000", router).Error())
}
