package hash

type (
	Interface interface {
		sha
		md
		Sum() string
	}
	object struct {
		src string
		sum string
	}
)

var Default = New()

func New() Interface          { return &object{} }
func (o *object) Sum() string { return o.sum }
