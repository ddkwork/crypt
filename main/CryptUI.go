package main

import (
	"github.com/ddkwork/app"
	"github.com/ddkwork/app/widget"
	"github.com/ddkwork/crypt/src/aes"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/safemap"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/unison"
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
		Name CryptNameType
	}
	SrcKeyDstdData struct {
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
				name = node.Sum()
			}
			return []widget.CellData{{Text: name}}
		},
		UnmarshalRow: func(node *widget.Node[CryptTable], values []string) {
			mylog.Todo("unmarshal row")
		},
		SelectionChangedCallback: func(root *widget.Node[CryptTable]) {
			mylog.Todo("selection changed callback")
		},
		SetRootRowsCallBack: func(root *widget.Node[CryptTable]) {
			for _, kind := range SymmetryType.EnumTypes() {
				switch kind {
				case SymmetryType:
					container := widget.NewContainerNode(SymmetryType.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{Name: AesType})
					container.AddChildByData(CryptTable{Name: DesType})
					container.AddChildByData(CryptTable{Name: Des3Type})
					container.AddChildByData(CryptTable{Name: TeaType})
					container.AddChildByData(CryptTable{Name: BlowfishType})
					container.AddChildByData(CryptTable{Name: TwoFishType})
					container.AddChildByData(CryptTable{Name: Rc4Type})
					container.AddChildByData(CryptTable{Name: Rc2Type})
				case AsymmetricalType:
					container := widget.NewContainerNode(AsymmetricalType.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{Name: RsaType})
					container.AddChildByData(CryptTable{Name: EccType})
					container.AddChildByData(CryptTable{Name: DsaType})
					container.AddChildByData(CryptTable{Name: PgpType})
					container.AddChildByData(CryptTable{Name: Sm4Type})
					container.AddChildByData(CryptTable{Name: Sm2Type})
				case HashType:
					container := widget.NewContainerNode(HashType.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{Name: HmacType})
					container.AddChildByData(CryptTable{Name: HashAllType})
				case EncodingType:
					container := widget.NewContainerNode(EncodingType.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{Name: Base64Type})
					container.AddChildByData(CryptTable{Name: Base32Type})
					container.AddChildByData(CryptTable{Name: GzipType})
				case ToolType:
					container := widget.NewContainerNode(ToolType.String(), CryptTable{})
					root.AddChild(container)
					container.AddChildByData(CryptTable{Name: TrimSpaceType})
					container.AddChildByData(CryptTable{Name: SwapType})
					container.AddChildByData(CryptTable{Name: RequestHeaderType})
					container.AddChildByData(CryptTable{Name: TimeStampType})
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
	layouts := new(safemap.M[CryptNameType, func() unison.Paneler])
	layouts.Set(AesType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
			return []widget.CellData{{Text: data.Src}, {Text: data.Key}, {Text: data.Dst}}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				if view.Editors[0].Label.String() == "" { // todo
					view.Editors[0].Label.Text = "1122334455667788"
				}
				if view.Editors[1].Label.String() == "" {
					view.Editors[1].Label.Text = "1122334455667788"
				}

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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(DesType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Des3Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TeaType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(BlowfishType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TwoFishType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Rc4Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Rc2Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(RsaType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(RsaData{}, func(data RsaData) (values []widget.CellData) {
			/*
				P string
				Q string
				E string
				N string
				D string
				M string
				C string

			*/
			return []widget.CellData{
				{Text: data.P},
				{Text: data.Q},
				{Text: data.E},
				{Text: data.N},
				{Text: data.D},
				{Text: data.M},
				{Text: data.C},
			}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				// view.MetaData.Src = view.Editors[0].Label.String()
				// view.MetaData.Key = view.Editors[1].Label.String()
				// view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(2, view.MetaData.C)
			},
			func() {
				// view.MetaData.Dst = view.Editors[2].Label.String()
				// view.MetaData.Key = view.Editors[1].Label.String()
				// view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.M)
			},
		)
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(EccType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(DsaType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(PgpType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Sm4Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Sm2Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(HmacType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(HashAllType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(HashData{}, func(data HashData) (values []widget.CellData) {
			return []widget.CellData{
				/*
							Src    string
					Md2    string
					Md4    string
					Md5    string
					Sha1   string
					Sha224 string
					Sha256 string
					Sha384 string
					Sha512 string

				*/
				{Text: data.Src},
				{Text: data.Md2},
				{Text: data.Md4},
				{Text: data.Md5},
				{Text: data.Sha1},
				{Text: data.Sha224},
				{Text: data.Sha256},
				{Text: data.Sha384},
				{Text: data.Sha512},
			}
		})
		panel1 := widget.NewButtonsPanel(
			[]string{"encode", "decode"},
			func() {
				view.MetaData.Src = view.Editors[0].Label.String()
				// view.MetaData.Key = view.Editors[1].Label.String()
				// view.MetaData.Dst = string(aes.Encrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				// view.UpdateField(2, view.MetaData.Dst)
			},
			func() {
				// view.MetaData.Dst = view.Editors[2].Label.String()
				// view.MetaData.Key = view.Editors[1].Label.String()
				// view.MetaData.Src = string(aes.Decrypt(stream.HexString(view.MetaData.Src), stream.HexString(view.MetaData.Key)).HexString())
				view.UpdateField(0, view.MetaData.Src)
			},
		)
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Base64Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(Base32Type, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(GzipType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TrimSpaceType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(SwapType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(RequestHeaderType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(TimeStampType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})
	layouts.Set(AesType, func() unison.Paneler {
		view, RowPanel := widget.NewStructView(SrcKeyDstdData{}, func(data SrcKeyDstdData) (values []widget.CellData) {
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
		RowPanel.AddChild(panel1)

		panel := widget.NewPanel()
		panel.AddChild(view)
		panel.AddChild(RowPanel)
		scrollPanelFill := widget.NewScrollPanelFill(panel)
		return scrollPanelFill
	})

	right := widget.NewPanel()
	value := layouts.GetMust(AesType)
	right.AddChild(value()) // todo make a welcoming page
	splitPanel.AddChild(left)
	splitPanel.AddChild(right)

	// todo get and set inputted ctx,not clean it every time
	table.SelectionChangedCallback = func() {
		for i, n := range table.SelectedRows(false) {
			if i > 1 {
				break
			}
			switch n.Data.Name {
			case AesType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(AesType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case DesType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(DesType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Des3Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Des3Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case TeaType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(TeaType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case BlowfishType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(BlowfishType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case TwoFishType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(TwoFishType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Rc4Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Rc4Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Rc2Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Rc2Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case RsaType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(RsaType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case EccType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(EccType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case DsaType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(DsaType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case PgpType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(PgpType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Sm4Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Sm4Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Sm2Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Sm2Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case HmacType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(HmacType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case HashAllType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(HashAllType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case Base64Type:
				right.RemoveAllChildren()
				panel := layouts.GetMust(Base64Type)
				right.AddChild(panel())
				splitPanel.AddChild(right)
			case Base32Type:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(Base32Type)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case GzipType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(GzipType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case TrimSpaceType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(TrimSpaceType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case SwapType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(SwapType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case RequestHeaderType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(RequestHeaderType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			case TimeStampType:
				right.RemoveAllChildren()
				paneler := layouts.GetMust(TimeStampType)
				right.AddChild(paneler())
				splitPanel.AddChild(right)
			default:
			}
		}
	}
	return splitPanel.AsPanel()
}
