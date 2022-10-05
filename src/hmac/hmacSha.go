package hmac

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/src/stream"
	"hash"
)

type (
	Interface interface {
		HmacSha1(src, key string) *stream.Stream
		HmacSha224(src, key string) *stream.Stream
		HmacSha256(src, key string) *stream.Stream
		HmacSha384(src, key string) *stream.Stream
		HmacSha512(src, key string) *stream.Stream
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

func (o *object) Check(src, key string) (ok bool) {
	o.src = stream.NewString(src)
	o.key = stream.NewString(key)
	return true
}

func (o *object) HmacSha1(src, key string) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA1)
}

func (o *object) HmacSha224(src, key string) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA224)
}

func (o *object) HmacSha256(src, key string) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA256)
}

func (o *object) HmacSha384(src, key string) *stream.Stream {
	if !o.Check(src, key) {
		return o.err
	}
	return o.do(crypto.SHA384)
}

func (o *object) HmacSha512(src, key string) *stream.Stream {
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
	default:
		return stream.NewErrorInfo("unknown Type of crypto.hash")
	}
	h2 := hmac.New(o.fnNewSha, o.key.Bytes())
	_, err := h2.Write(o.src.Bytes())
	if !mylog.Error(err) {
		return stream.NewErrorInfo(err.Error())
	}
	return stream.NewBytes(h2.Sum(nil))
}
