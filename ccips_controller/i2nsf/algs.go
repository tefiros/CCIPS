package i2nsf

type EncAlgType int

const (
	DESCBC       EncAlgType = 2
	TRIPLEDESCBC            = 3
	CASTCBC                 = 6
	BLOWFISHCBC             = 7
	AESCBC                  = 12
	AESCTR                  = 13
	AESCCMV8                = 14
	AESCCMV12               = 15
	AESCCMV16               = 16
	AESGCMV8                = 18
	AESGCMV12               = 19
	AESGCMV16               = 20
)

var ENCALGS = map[string]EncAlgType{
	"des-cbc":      DESCBC,
	"3-des-cbc":    TRIPLEDESCBC,
	"cast-cbc":     CASTCBC,
	"blowfish-cbc": BLOWFISHCBC,
	"aes-cbc":      AESCBC,
	"aes-ctr":      AESCTR,
	"aes-ccmv-8":   AESCCMV8,
	"aes-ccmv-12":  AESCCMV12,
	"aes-ccmv-16":  AESCCMV16,
	"aes-gcmv-8":   AESGCMV8,
	"aes-gcmv-12":  AESGCMV12,
	"aes-gcmv-16":  AESGCMV16,
}

type AuthAlgType int

const (
	MD5          AuthAlgType = 2
	SHA1                     = 3
	SHA2_256                 = 5
	SHA2_384                 = 6
	SHA2_512                 = 7
	RIPEMD160                = 8
	AES_XCBC_MAC             = 9
)

var ENCKEYLENGTH = map[EncAlgType]int64{
	DESCBC:       8,  // DES: 8 bytes
	TRIPLEDESCBC: 24, // 3DES: 24 bytes
	CASTCBC:      16, // CAST: 16 bytes
	BLOWFISHCBC:  24, // Blowfish: 24 bytes
	AESCBC:       32, // AES-256-CBC: 32 bytes
	AESCTR:       32, // AES-256-CTR: 32 bytes (sin salt extra)
	AESCCMV8:     20, // AES-128-CCM: 16 + 4 salt
	AESCCMV12:    28, // AES-192-CCM: 24 + 4 salt
	AESCCMV16:    36, // AES-256-CCM: 32 + 4 salt
	AESGCMV8:     20, // AES-128-GCM: 16 + 4 salt (RFC4106)
	AESGCMV12:    28, // AES-192-GCM: 24 + 4 salt (RFC4106)
	AESGCMV16:    36, // AES-256-GCM: 32 + 4 salt (RFC4106)
}

var AUTHKEYLENGTH = map[AuthAlgType]int64{
	MD5:          16,
	SHA1:         10,
	SHA2_256:     32,
	SHA2_384:     48,
	SHA2_512:     64,
	RIPEMD160:    20,
	AES_XCBC_MAC: 16,
}

var AUTHALGS = map[string]AuthAlgType{
	"md5":         MD5,
	"sha1":        SHA1,
	"sha2-256":    SHA2_256,
	"sha2-384":    SHA2_384,
	"sha2-512":    SHA2_512,
	"ripemd-160":  RIPEMD160,
	"aes-cbc-mac": AES_XCBC_MAC,
}
