package des

import "github.com/ddkwork/golibrary/src/stream"

type (
	Interface interface {
		Encrypt(src, key any) (dst *stream.Stream)
		Decrypt(src, key any) (dst *stream.Stream)
	}
	object struct {
	}
)

func (o *object) Encrypt(src, key any) (dst *stream.Stream) {
	s := stream.NewHexStringOrBytes(src)
	if !s.DesBlockSizeSizeCheck() {
		return s
	}
	k := stream.NewHexStringOrBytes(key)
	if !k.DesBlockSizeSizeCheck() {
		return k
	}
	subkeys := expand(k.Bytes())
	return stream.NewBytes(des_encrypt(s.Bytes(), subkeys))
}

func (o *object) Decrypt(src, key any) (dst *stream.Stream) {
	d := stream.NewHexStringOrBytes(src)
	if !d.DesBlockSizeSizeCheck() {
		return d
	}
	k := stream.NewHexStringOrBytes(key)
	if !k.DesBlockSizeSizeCheck() {
		return k
	}
	subkeys := expand(k.Bytes())
	return stream.NewBytes(des_decrypt(d.Bytes(), subkeys))
}

var Default = New()

func New() Interface { return &object{} }
