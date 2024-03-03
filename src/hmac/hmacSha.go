package hmac

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/ddkwork/golibrary/safeType"
	"hash"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

type (
	Interface interface {
		HmacSha1(src string, key safeType.HexString) *stream.Stream
		HmacSha224(src string, key safeType.HexString) *stream.Stream
		HmacSha256(src string, key safeType.HexString) *stream.Stream
		HmacSha384(src string, key safeType.HexString) *stream.Stream
		HmacSha512(src string, key safeType.HexString) *stream.Stream
	}
	object struct {
		src      *stream.Stream
		key      *stream.Stream
		fnNewSha func() hash.Hash
		err      *stream.Stream
	}
)

func New() Interface {
	return &object{
		src:      nil,
		key:      nil,
		fnNewSha: nil,
		err:      nil,
	}
}

func (o *object) Check(src string, key safeType.HexString) (ok bool) {
	o.src = stream.New(src)
	o.key = stream.New(key)
	return true
}

func (o *object) HmacSha1(src string, key safeType.HexString) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA1)
}

func (o *object) HmacSha224(src string, key safeType.HexString) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA224)
}

func (o *object) HmacSha256(src string, key safeType.HexString) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA256)
}

func (o *object) HmacSha384(src string, key safeType.HexString) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA384)
}

func (o *object) HmacSha512(src string, key safeType.HexString) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA512)
}

func (o *object) do(Type crypto.Hash) *stream.Stream {
	switch Type {
	case crypto.SHA1:
		o.fnNewSha = func() hash.Hash { return sha1.New() }
	case crypto.SHA224:
		o.fnNewSha = func() hash.Hash { return crypto.SHA224.New() }
	case crypto.SHA256:
		o.fnNewSha = func() hash.Hash { return sha256.New() }
	case crypto.SHA384:
		o.fnNewSha = func() hash.Hash { return crypto.SHA384.New() }
	case crypto.SHA512:
		o.fnNewSha = func() hash.Hash { return sha512.New() }
	}
	h2 := hmac.New(o.fnNewSha, o.key.Bytes())
	_, err := h2.Write(o.src.Bytes())
	if !mylog.Error(err) {
		return nil
	}
	return stream.New(h2.Sum(nil))
}
