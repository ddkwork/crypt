package pgp

import (
	"runtime/debug"
)

type (
	Interface interface {
		Work() (ok bool) // TODO implement me and rename
		Result() any     // TODO implement me and rename
		helper
	}
	helper interface {
		ErrorInfo() string
		Stack() string // all goroutine use runtime.Stack
	}
	object struct {
		errorInfo string
		err       error
		stack     string
	}
)

func (o *object) Work() (ok bool)   { panic("implement me") }
func (o *object) Result() any       { panic("implement me") }
func (o *object) Stack() string     { return o.stack }
func (o *object) ErrorInfo() string { return o.errorInfo }
func (o *object) checkError() bool {
	if o.err != nil {
		o.errorInfo = o.err.Error()
		o.stack = string(debug.Stack())
		return false
	}
	return true
}

var Default = New()

func New() Interface { return &object{} }
