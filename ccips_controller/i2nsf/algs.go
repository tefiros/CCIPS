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
	DESCBC:       8,  //
	TRIPLEDESCBC: 10, //
	CASTCBC:      16, //
	BLOWFISHCBC:  24, //
	AESCBC:       32, //
	AESCTR:       64, //
	AESCCMV8:     32,
	AESCCMV12:    48,
	AESCCMV16:    64,
	AESGCMV8:     32,
	AESGCMV12:    48,
	AESGCMV16:    64,
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
