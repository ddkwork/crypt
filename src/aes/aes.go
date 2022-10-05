package aes

import "github.com/ddkwork/golibrary/src/stream"

type (
	Interface interface {
		Encrypt(src *stream.Stream, key *stream.Stream) (dst *stream.Stream)
		Decrypt(src *stream.Stream, key *stream.Stream) (dst *stream.Stream)
	}
	object struct {
	}
)

func (o *object) Encrypt(src *stream.Stream, key *stream.Stream) (dst *stream.Stream) {
	c := encrypt(src.Bytes(), key.Bytes())
	return stream.NewBytes(c[:])
}

func (o *object) Decrypt(src *stream.Stream, key *stream.Stream) (dst *stream.Stream) {
	c := decrypt(src.Bytes(), key.Bytes())
	return stream.NewBytes(c[:])
}

var Default = New()

func New() Interface { return &object{} }
