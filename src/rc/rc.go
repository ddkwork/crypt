package rc

type (
    Interface interface {
    }
    object struct {
    }
)

var Default = New()

func New() Interface { return &object{} }