''' © 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)
(laura.dominguez.cespedes@telefonica.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. ''' 

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional


class Node(BaseModel):
    networkInternal: Optional[str] = None
    ipData: Optional[str] = None
    ipControl: Optional[str] = None
    ipDMZ: Optional[str] = None

class InlineResponse500(BaseModel):
    code: float
    message: str
    description: str

class LifetimeConfig(BaseModel):
    nBytes: Optional[float] = None
    nPackets: Optional[float] = None
    nTime: Optional[float] = None
    nTimeIdle: Optional[float] = None

class I2NSFRequest(BaseModel):
    nodes: List[Node]
    encAlg: List[str]
    intAlg: List[str]
    softLifetime: Optional[LifetimeConfig] = None
    hardLifetime: Optional[LifetimeConfig] = None
    method: str = None

class HybridizationConfig(BaseModel):
    use_qkd: str = Field(alias="use-qkd")
    pqc_algorithm: str = Field(alias="pqc-algorithm")
    hybridization_method: str = Field(alias="hybridization-method")
    endpoint1: str
    endpoint2: str
    method: str = "http"

    class Config:
        allow_population_by_field_name = True
        extra = "allow"

class I2NSFConfigResponse(BaseModel):
    id: string
    nodes: List[Node]
    encAlg: List[str]
    intAlg: List[str]
    status: str
    softLifetime: Optional[LifetimeConfig] = None
    hardLifetime: Optional[LifetimeConfig] = None

class InlineResponse201(BaseModel):
    code: float
    message: str




