package sm

type (
	Interface any
	object    struct{}
)

var Default = New()

func New() Interface { return &object{} }
