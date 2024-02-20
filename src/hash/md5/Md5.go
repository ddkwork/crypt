package md5

import (
	"crypto/md5"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

type (
	Interface interface {
		Sum(src string) *stream.Stream
		Sum2(src string) *stream.Stream
	}
	object struct {
		s *stream.Stream
	}
)

func New() Interface { return &object{s: stream.New("")} }
func (o *object) Sum(src string) *stream.Stream {
	s := stream.New(src)
	hash := md5.New()
	if !mylog.Error2(hash.Write(s.Bytes())) {
		return nil
	}
	return stream.New(hash.Sum(nil))
}

func (o *object) Sum2(src string) *stream.Stream {
	s := stream.New(src)
	array := md5.Sum(s.Bytes())
	return stream.New(array[:])
}
