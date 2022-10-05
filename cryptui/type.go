package cryptui

type TypeCrypt string

var (
	defaultTypeCrypt = func() TypeCrypt { return "" }
	typeCrypt        = defaultTypeCrypt()
)

func (TypeCrypt) typeSymmetry() string     { return "对称" }
func (TypeCrypt) typeAsymmetrical() string { return "非对称" }
func (TypeCrypt) typeHash() string         { return "哈西" }
func (TypeCrypt) typeEncoding() string     { return "编码" }
func (TypeCrypt) typeTool() string         { return "工具" }

func (TypeCrypt) rsa() string { return "rsa" }
func (TypeCrypt) ecc() string { return "ecc" }
func (TypeCrypt) dsa() string { return "dsa" }
func (TypeCrypt) pgp() string { return "pgp" }
func (TypeCrypt) sm4() string { return "sm4" }
func (TypeCrypt) sm2() string { return "sm2" }

func (TypeCrypt) base64() string { return "base64" }
func (TypeCrypt) base32() string { return "base32" }
func (TypeCrypt) gzip() string   { return "gzip" }

func (TypeCrypt) hmacSha() string    { return "hmacSha" }
func (TypeCrypt) hmacSha1() string   { return "hmacSha1" }
func (TypeCrypt) hmacSha224() string { return "hmacSha224" }
func (TypeCrypt) hmacSha256() string { return "hmacSha256" }
func (TypeCrypt) hmacSha384() string { return "hmacSha384" }
func (TypeCrypt) hmacSha512() string { return "hmacSha512" }

func (TypeCrypt) hash() string   { return "hash" }
func (TypeCrypt) md2() string    { return "md2" }
func (TypeCrypt) md4() string    { return "md4" }
func (TypeCrypt) md5() string    { return "md5" }
func (TypeCrypt) sha1() string   { return "sha1" }
func (TypeCrypt) sha224() string { return "sha224" }
func (TypeCrypt) sha256() string { return "sha256" }
func (TypeCrypt) sha384() string { return "sha384" }
func (TypeCrypt) sha512() string { return "sha512" }

func (TypeCrypt) des() string      { return "des" }
func (TypeCrypt) des3() string     { return "des3" }
func (TypeCrypt) tea() string      { return "tea" }
func (TypeCrypt) aes() string      { return "aes" }
func (TypeCrypt) blowfish() string { return "blowfish" }
func (TypeCrypt) twoFish() string  { return "twoFish" }
func (TypeCrypt) rc4() string      { return "rc4" }
func (TypeCrypt) rc2() string      { return "rc2" }
