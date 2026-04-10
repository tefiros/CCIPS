"""© 2026 Telefónica Innovación Digital 
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
limitations under the License.
"""

from enum import IntEnum

# Encryption Algorithm Types
class EncAlgType(IntEnum):
    DES_CBC = 2
    _3DES_CBC = 3
    CAST_CBC = 6
    BLOWFISH_CBC = 7
    AES_CBC = 12
    AES_CTR = 13
    AES_CCM_8 = 14
    AES_CCM_12 = 15
    AES_CCM_16 = 16
    AES_GCM_8 = 18
    AES_GCM_12 = 19
    AES_GCM_16 = 20

ENCALGS = {
    "des-cbc": EncAlgType.DES_CBC,
    "3-des-cbc": EncAlgType._3DES_CBC,
    "cast-cbc": EncAlgType.CAST_CBC,
    "blowfish-cbc": EncAlgType.BLOWFISH_CBC,
    "aes-cbc": EncAlgType.AES_CBC,
    "aes-ctr": EncAlgType.AES_CTR,
    "aes-ccm-8": EncAlgType.AES_CCM_8,
    "aes-ccm-12": EncAlgType.AES_CCM_12,
    "aes-ccmv-16": EncAlgType.AES_CCM_16,
    "aes-gcmv-8": EncAlgType.AES_GCM_8,
    "aes-gcmv-12": EncAlgType.AES_GCM_12,
    "aes-gcmv-16": EncAlgType.AES_GCM_16,
}

# Authentication Algorithm Types
class AuthAlgType(IntEnum):
    MD5 = 2
    SHA1 = 3
    SHA2_256 = 5
    SHA2_384 = 6
    SHA2_512 = 7
    RIPEMD160 = 8
    AES_XCBC_MAC = 9

ENCKEYLENGTH = {
    EncAlgType.DES_CBC: 8,
    EncAlgType._3DES_CBC: 10,
    EncAlgType.CAST_CBC: 16,
    EncAlgType.BLOWFISH_CBC: 24,
    EncAlgType.AES_CBC: 32,
    EncAlgType.AES_CTR: 64,
    EncAlgType.AES_CCM_8: 32,
    EncAlgType.AES_CCM_12: 48,
    EncAlgType.AES_CCM_16: 64,
    EncAlgType.AES_GCM_8: 32,
    EncAlgType.AES_GCM_12: 48,
    EncAlgType.AES_GCM_16: 64,
}

AUTHKEYLENGTH = {
    AuthAlgType.MD5: 16,
    AuthAlgType.SHA1: 10,
    AuthAlgType.SHA2_256: 32,
    AuthAlgType.SHA2_384: 48,
    AuthAlgType.SHA2_512: 64,
    AuthAlgType.RIPEMD160: 20,
    AuthAlgType.AES_XCBC_MAC: 16,
}

AUTHALGS = {
    "md5": AuthAlgType.MD5,
    "sha1": AuthAlgType.SHA1,
    "sha2-256": AuthAlgType.SHA2_256,
    "sha2-384": AuthAlgType.SHA2_384,
    "sha2-512": AuthAlgType.SHA2_512,
    "ripemd-160": AuthAlgType.RIPEMD160,
    "aes-cbc-mac": AuthAlgType.AES_XCBC_MAC,
}

def enc_alg_decoder(alg: EncAlgType) -> str:
    mapping = {
        EncAlgType.DES_CBC: "des-cbc",
        EncAlgType._3DES_CBC: "3-des-cbc",
        EncAlgType.CAST_CBC: "cast-cbc",
        EncAlgType.BLOWFISH_CBC: "blowfish-cbc",
        EncAlgType.AES_CBC: "aes-cbc",
        EncAlgType.AES_CTR: "aes-ctr",
        EncAlgType.AES_CCM_8: "aes-ccm-8",
        EncAlgType.AES_CCM_12: "aes-ccm-12",
        EncAlgType.AES_CCM_16: "aes-ccm-16",
        EncAlgType.AES_GCM_8: "aes-gcmv-8",
        EncAlgType.AES_GCM_12: "aes-gcmv-12",
        EncAlgType.AES_GCM_16: "aes-gcmv-16",
    }
    return mapping.get(alg, "Algorithm not Identified")

def int_alg_decoder(alg: AuthAlgType) -> str:
    mapping = {
        AuthAlgType.MD5: "md5",
        AuthAlgType.SHA1: "sha1",
        AuthAlgType.SHA2_256: "sha2-256",
        AuthAlgType.SHA2_384: "sha2-384",
        AuthAlgType.SHA2_512: "sha2-512",
        AuthAlgType.RIPEMD160: "ripemd-160",
    }
    return mapping.get(alg, "Algorithm not Identified")