package hash

import (
	"crypto"
	"github.com/ddkwork/crypt/src/hash/go-md2"
	"golang.org/x/crypto/md4"
)

type md interface {
	Md2(src string) (ok bool)
	Md4(src string) (ok bool)
	Md5(src string) (ok bool)
}

const MD2 crypto.Hash = 999

func (o *object) Md2(src string) (ok bool) { return o.setMdHash(src, MD2) }
func (o *object) Md4(src string) (ok bool) { return o.setMdHash(src, crypto.MD4) }
func (o *object) Md5(src string) (ok bool) { return o.setMdHash(src, crypto.MD5) }
func (o *object) setMdHash(src string, kind crypto.Hash) (ok bool) {
	o.src = src
	switch kind {
	case MD2:
		return o.setSum(md2.New())
	case crypto.MD4:
		return o.setSum(md4.New())
	case crypto.MD5:
		return o.setSum(crypto.MD5.New())
	}
	return
}
