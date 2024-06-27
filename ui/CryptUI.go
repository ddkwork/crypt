package main

import (
	"strconv"
	"strings"

	"github.com/ddkwork/crypt/src/aes"
	"github.com/ddkwork/golibrary/stream"

	"github.com/ddkwork/golibrary/mylog"

	"github.com/ddkwork/golibrary/stream/orderedmap"

	"github.com/ddkwork/app"
	"github.com/ddkwork/app/widget"
	"github.com/richardwilkes/unison"
)

func main() {
	app.Run("crypto tool", func(w *unison.Window) {
		content := w.Content()
		panel := widget.NewPanel()
		panel.AddChild(NewCryptUI().Layout())
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		content.AddChild(scrollPanelFill)
	})
}

type CryptUI struct{}

func NewCryptUI() *CryptUI {
	return &CryptUI{}
}

type (
	CryptTable struct {
		PrentName string
		Name      CryptNameKind
	}
	skdData struct {
		Src string
		Key string
		Dst string
	}
	HashData struct {
		Src    string
		Md2    string
		Md4    string
		Md5    string
		Sha1   string
		Sha224 string
		Sha256 string
		Sha384 string
		Sha512 string
	}
	RsaData struct {
		P string // 质数
		Q string // 质数
		E string // 指数
		N string // 模数
		D string // 私钥
		M string // 明文
		C string // 密文
	}
)

func (c *CryptUI) Layout() *unison.Panel {
	table, header := widget.NewTable(CryptTable{}, widget.TableContext[CryptTable]{
		ContextMenuItems: nil,
		MarshalRow: func(node *widget.Node[CryptTable]) (cells []widget.CellData) {
			name := node.Data.Name.String()
			if node.Container() {
				name = ""
				node.Data.PrentName = node.Type
				node.Data.PrentName = strings.TrimSuffix(node.Data.PrentName, widget.ContainerKeyPostfix)
				node.Data.PrentName = strings.TrimSuffix(node.Data.PrentName, "Node")
				node.Data.PrentName += " ("
				node.Data.PrentName += strconv.Itoa(node.LenChildren())
				node.Data.PrentName += ")"
			}
			return []widget.CellData{{Text: node.Data.PrentName}, {Text: name}}
		},
		UnmarshalRow:             nil,
		SelectionChangedCallback: nil,
		SetRootRowsCallBack: func(root *widget.Node[CryptTable]) {
			for _, kind := range InvalidCryptKind.Kinds() {
				switch kind {
				case SymmetryKind:
					container := widget.NewContainerNode(SymmetryKind.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{PrentName: "", Name: AesKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: DesKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Des3Kind})
					container.AddChildByData(CryptTable{PrentName: "", Name: TeaKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: BlowfishKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: TwoFishKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Rc4Kind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Rc2Kind})
				case AsymmetricalKind:
					container := widget.NewContainerNode(AsymmetricalKind.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{PrentName: "", Name: RsaKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: EccKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: DsaKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: PgpKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Sm4Kind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Sm2Kind})
				case HashKind:
					container := widget.NewContainerNode(HashKind.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{PrentName: "", Name: HmacKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: HashAllKind})
				case EncodingKind:
					container := widget.NewContainerNode(EncodingKind.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{PrentName: "", Name: Base64Kind})
					container.AddChildByData(CryptTable{PrentName: "", Name: Base32Kind})
					container.AddChildByData(CryptTable{PrentName: "", Name: GzipKind})
				case ToolKind:
					container := widget.NewContainerNode(ToolKind.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{PrentName: "", Name: TrimSpaceKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: SwapKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: RequestHeaderKind})
					container.AddChildByData(CryptTable{PrentName: "", Name: TimeStampKind})
				default:
				}
			}
		},
		JsonName:   "Crypt",
		IsDocument: false,
	})

	splitPanel := widget.NewPanel()
	widget.SetScrollLayout(splitPanel, 2)

	left := widget.NewTableScrollPanel(table, header)
	layouts := orderedmap.New(InvalidCryptNameKind, func() unison.Paneler { return widget.NewPanel() })
	layouts.Set(AesKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(DesKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Des3Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TeaKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(BlowfishKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TwoFishKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Rc4Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Rc2Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(RsaKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(EccKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(DsaKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(PgpKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Sm4Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Sm2Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(HmacKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(HashAllKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Base64Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Base32Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(GzipKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TrimSpaceKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(SwapKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(RequestHeaderKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TimeStampKind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Base64Kind, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(skdData{}, func(data skdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				view.MetaData.Dst = view.Editors[2].Label.String()
				view.MetaData.Key = view.Editors[1].Label.String()
				view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(widget.NewVSpacer())
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(widget.NewVSpacer())
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})

	right := widget.NewPanel()
	right.AddChild(mylog.Check2Bool(layouts.Get(AesKind))()) // todo make a welcoming page
	splitPanel.AddChild(left)
	splitPanel.AddChild(right)

	table.SelectionChangedCallback = func() {
		for i, n := range table.SelectedRows(false) {
			if i > 1 {
				break
			}
			switch n.Data.Name {
			case AesKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(AesKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case DesKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(DesKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Des3Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Des3Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case TeaKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(TeaKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case BlowfishKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(BlowfishKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case TwoFishKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(TwoFishKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Rc4Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Rc4Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Rc2Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Rc2Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case RsaKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(RsaKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case EccKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(EccKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case DsaKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(DsaKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case PgpKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(PgpKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Sm4Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Sm4Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Sm2Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Sm2Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case HmacKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(HmacKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case HashAllKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(HashAllKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case Base64Kind:
				right.RemoveAllChildren()
				panel := mylog.Check2Bool(layouts.Get(Base64Kind))()
				right.AddChild(panel)
				splitPanel.AddChild(right)
			case Base32Kind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(Base32Kind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case GzipKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(GzipKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case TrimSpaceKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(TrimSpaceKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case SwapKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(SwapKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case RequestHeaderKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(RequestHeaderKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			case TimeStampKind:
				right.RemoveAllChildren()
				paneler := mylog.Check2Bool(layouts.Get(TimeStampKind))()
				right.AddChild(paneler)
				splitPanel.AddChild(right)
			default:
			}
		}
	}
	return splitPanel.AsPanel()
}
