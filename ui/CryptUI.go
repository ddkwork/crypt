package main

import (
	"strconv"
	"strings"

	"github.com/ddkwork/app"
	"github.com/ddkwork/app/widget"
	"github.com/richardwilkes/unison"
)

func main() {
	app.Run("crypt", func(w *unison.Window) {
		NewCryptUI().Layout(w.Content())
	})
}

type CryptUI struct{}

func NewCryptUI() *CryptUI {
	return &CryptUI{}
}

type CryptTable struct {
	PrentName string
	Name      string
}

func (c *CryptUI) Layout(parent unison.Paneler) unison.Paneler {
	widget.NewTableScroll(parent, CryptTable{}, widget.TableContext[CryptTable]{
		ContextMenuItems: nil,
		MarshalRow: func(node *widget.Node[CryptTable]) (cells []widget.CellData) {
			if node.Container() {
				node.Data.PrentName = node.Type
				node.Data.PrentName = strings.TrimSuffix(node.Data.PrentName, widget.ContainerKeyPostfix)
				node.Data.PrentName = strings.TrimSuffix(node.Data.PrentName, "Node")
				node.Data.PrentName += " ("
				node.Data.PrentName += strconv.Itoa(node.LenChildren())
				node.Data.PrentName += ")"
			}
			return []widget.CellData{{Text: node.Data.PrentName}, {Text: node.Data.Name}}
		},
		UnmarshalRow:             nil,
		SelectionChangedCallback: nil,
		SetRootRowsCallBack: func(root *widget.Node[CryptTable]) {
			fnSkip := func(name string) bool {
				return strings.HasPrefix(name, "Invalid")
			}
			for _, kind := range InvalidCryptNodeKind.Kinds() {
				if fnSkip(kind.String()) {
					continue
				}
				switch kind {
				case SymmetryNodeKind:
					container := widget.NewContainerNode(SymmetryNodeKind.String(), CryptTable{})
					root.AddChild(container)
					for _, s := range InvalidSymmetryKind.Keys() {
						if fnSkip(s) {
							continue
						}
						container.AddChildByData(CryptTable{
							PrentName: "",
							Name:      s,
						})
					}
				case AsymmetricalNodeKind:
					container := widget.NewContainerNode(AsymmetricalNodeKind.String(), CryptTable{})
					root.AddChild(container)
					for _, s := range InvalidAsymmetricalKind.Keys() {
						if fnSkip(s) {
							continue
						}
						container.AddChildByData(CryptTable{
							PrentName: "",
							Name:      s,
						})
					}
				case HashNodeKind:
					container := widget.NewContainerNode(HashNodeKind.String(), CryptTable{})
					root.AddChild(container)
					for _, s := range InvalidHashKind.Keys() {
						if fnSkip(s) {
							continue
						}
						container.AddChildByData(CryptTable{
							PrentName: "",
							Name:      s,
						})
					}
				case EncodingNodeKind:
					container := widget.NewContainerNode(EncodingNodeKind.String(), CryptTable{})
					root.AddChild(container)
					for _, s := range InvalidEncodingKind.Keys() {
						if fnSkip(s) {
							continue
						}
						container.AddChildByData(CryptTable{
							PrentName: "",
							Name:      s,
						})
					}
				case ToolNodeKind:
					container := widget.NewContainerNode(ToolNodeKind.String(), CryptTable{})
					root.AddChild(container)
					for _, s := range InvalidToolKind.Keys() {
						if fnSkip(s) {
							continue
						}
						container.AddChildByData(CryptTable{
							PrentName: "",
							Name:      s,
						})
					}
				}
			}
		},
		JsonName:   "Crypt",
		IsDocument: false,
	})
	return nil
}
