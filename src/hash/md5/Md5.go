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

func New() Interface { return &object{s: stream.NewBuffer("")} }
func (o *object) Sum(src string) *stream.Stream {
	s := stream.NewBuffer(src)
	hash := md5.New()
	mylog.Check(hash.Write(s.Bytes()))
	return stream.NewBuffer(hash.Sum(nil))
}

func (o *object) Sum2(src string) *stream.Stream {
	s := stream.NewBuffer(src)
	array := md5.Sum(s.Bytes())
	return stream.NewBuffer(array[:])
}
