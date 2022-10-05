package hash

import (
    "crypto"
)

type sha interface {
    Sha1(src string) (ok bool)
    Sha224(src string) (ok bool)
    Sha384(src string) (ok bool)
    Sha256(src string) (ok bool)
    Sha512(src string) (ok bool)
}

func (o *object) Sha1(src string) (ok bool)   { return o.setShaHash(src, crypto.SHA1) }
func (o *object) Sha224(src string) (ok bool) { return o.setShaHash(src, crypto.SHA224) }
func (o *object) Sha384(src string) (ok bool) { return o.setShaHash(src, crypto.SHA384) }
func (o *object) Sha256(src string) (ok bool) { return o.setShaHash(src, crypto.SHA256) }
func (o *object) Sha512(src string) (ok bool) { return o.setShaHash(src, crypto.SHA512) }
func (o *object) setShaHash(src string, kind crypto.Hash) (ok bool) {
    o.src = src
    switch kind {
    case crypto.SHA1:
        return o.setSum(crypto.SHA1.New())
    case crypto.SHA224:
        return o.setSum(crypto.SHA224.New())
    case crypto.SHA384:
        return o.setSum(crypto.SHA384.New())
    case crypto.SHA256:
        return o.setSum(crypto.SHA256.New())
    case crypto.SHA512:
        return o.setSum(crypto.SHA512.New())
    }
    return
}