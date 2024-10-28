package hash

import (
	"crypto"
	"hash"
	"io"

	"golang.org/x/crypto/md4"

	"github.com/ddkwork/crypt/src/hash/go-md2"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

const MD2 crypto.Hash = 999

func Md2(src string) string { return setHash(src, MD2) }
func Md4(src string) string { return setHash(src, crypto.MD4) }
func Md5(src string) string { return setHash(src, crypto.MD5) }

func Sha1(src string) string   { return setHash(src, crypto.SHA1) }
func Sha224(src string) string { return setHash(src, crypto.SHA224) }
func Sha384(src string) string { return setHash(src, crypto.SHA384) }
func Sha256(src string) string { return setHash(src, crypto.SHA256) }
func Sha512(src string) string { return setHash(src, crypto.SHA512) }

func setHash(src string, kind crypto.Hash) string {
	switch kind {
	case crypto.SHA1:
		return setSum(src, crypto.SHA1.New())
	case crypto.SHA224:
		return setSum(src, crypto.SHA224.New())
	case crypto.SHA384:
		return setSum(src, crypto.SHA384.New())
	case crypto.SHA256:
		return setSum(src, crypto.SHA256.New())
	case crypto.SHA512:
		return setSum(src, crypto.SHA512.New())
	case MD2:
		return setSum(src, md2.New())
	case crypto.MD4:
		return setSum(src, md4.New())
	case crypto.MD5:
		return setSum(src, crypto.MD5.New())
	}
	return ""
}

func setSum(src string, hash hash.Hash) string {
	mylog.Check2(io.WriteString(hash, src))
	return string(stream.NewBuffer(hash.Sum(nil)).HexString())
}
