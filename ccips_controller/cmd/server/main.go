/*© 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.*/
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
