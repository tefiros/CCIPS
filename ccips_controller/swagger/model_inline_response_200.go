/*/*© 2026 Telefónica Innovación Digital 
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

package swagger

type I2NSFConfigResponse struct {
	Id string `json:"id,omitempty"`

	Nodes []Node `json:"nodes,omitempty"`

	EncAlg string`json:"encAlg,omitempty"`

	IntAlg string `json:"intAlg,omitempty"`

	Status string `json:"status,omitempty"`

	SoftLifetime float64 `json:"softLifetime,omitempty"`

	HardLifetime float64 `json:"hardLifetime,omitempty"`
}
