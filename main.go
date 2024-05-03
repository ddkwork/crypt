package main

import (
	_ "embed"
	"strings"

	"github.com/ddkwork/golibrary/safeType"

	"cogentcore.org/core/events"
	"cogentcore.org/core/gi"
	"cogentcore.org/core/giv"
	"cogentcore.org/core/styles"
	"cogentcore.org/core/texteditor"

	"github.com/ddkwork/crypt/packetHeadToGo"
	"github.com/ddkwork/crypt/src/aes"
	"github.com/ddkwork/crypt/src/base32"
	"github.com/ddkwork/crypt/src/base64"
	"github.com/ddkwork/crypt/src/des"
	"github.com/ddkwork/crypt/src/hash"
	"github.com/ddkwork/crypt/src/hmac"
	"github.com/ddkwork/crypt/src/rsa"
	"github.com/ddkwork/crypt/unixTimestampConverter"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	//"github.com/ddkwork/golibrary/widget"
)

//go:generate core generate
//go:generate core build -v -t android/arm64
//go:generate core build -v -t windows/amd64
//go:generate go build .
//go:generate go install .
//go:generate svg embed-image 2.png

//go:embed 2.svg
var icon []byte

func main() {
	gi.TheApp.SetIconBytes(icon)
	b := gi.NewBody("crypt tools")
	tabs := gi.NewTabs(b)
	// tabs.SetType(gi.FunctionalTabs) // can close
	// tabs.SetType(gi.NavigationAuto) //bottom
	// tabs.SetType(gi.NavigationBar)  //bottom
	tabs.SetType(gi.NavigationRail) // left
	//tabs.Style(func(s *styles.Style) {
	//	s.Direction = styles.Row
	//})

	//////////////////////////////Symmetry 对称页面//////////////////////////////
	Symmetry := tabs.NewTab("Symmetry").SetTooltip("对称")
	parent := gi.NewTabs(Symmetry)
	template := &ObjectTemplate{
		Src: "",
		Key: "",
		Dst: "",
	}

	CanvasTemplate(parent.NewTab("Aes"), template, Aes)
	CanvasTemplate(parent.NewTab("Des"), template, Des)
	CanvasTemplate(parent.NewTab("Des3"), template, Des3)
	CanvasTemplate(parent.NewTab("Tea"), template, Tea)
	CanvasTemplate(parent.NewTab("Blowfish"), template, Blowfish)
	CanvasTemplate(parent.NewTab("TwoFish"), template, TwoFish)
	CanvasTemplate(parent.NewTab("Rc4"), template, Rc4)
	CanvasTemplate(parent.NewTab("Rc2"), template, Rc2)

	//////////////////////////////Asymmetrical 非对称页面//////////////////////////////
	Asymmetrical := tabs.NewTab("Asymmetrical").SetTooltip("非对称")
	newTabs := gi.NewTabs(Asymmetrical)

	type RsaInfo struct {
		P string `width:"100"` // 质数
		Q string `width:"100"` // 质数
		E string `width:"100"` // 指数
		N string `width:"100"` // 模数
		D string `width:"100"` // 私钥
		M string `width:"100"` // 明文
		C string `width:"100"` // 密文
	}
	info := &RsaInfo{
		P: "",
		Q: "",
		E: "10001",
		N: "703BF7A53D830F04A183A925211E322ADEB27404AEBD65607246934930A666B1",
		D: "172586F1613A4242A63CCD098746FEF96A7C930F2B357223F7DA700C26C85871",
		M: "ddk",
		C: "",
	}
	newTab := newTabs.NewTab("rsa")
	view := giv.NewStructView(newTab)
	view.SetStruct(info)
	newFrame := gi.NewFrame(newTab)
	r := rsa.New()

	//widget.NewButton(newFrame).SetText("pai").SetTooltip("密钥对").OnClick(func(e events.Event) {
	//})
	//widget.NewButton(newFrame).SetText("encode").SetTooltip("加密 C=M^e(mod n)").OnClick(func(e events.Event) {
	//	encrypt := r.Encrypt(stream.Data2Buffer(info.M), info.N, info.E)
	//	if encrypt == nil {
	//		return
	//	}
	//	info.C = string(encrypt.HexStringUpper())
	//	view.SetStruct(info)
	//})
	//widget.NewButton(newFrame).SetText("decode").SetTooltip("解密 M=C^d(mod n)").OnClick(func(e events.Event) {
	//	decrypt := r.Decrypt(stream.NewHexString(safeType.HexString(info.C)), info.N, info.E, info.D)
	//	if decrypt == nil {
	//		return
	//	}
	//	info.M = decrypt.String()
	//	view.SetStruct(info)
	//})
	//widget.NewButton(newFrame).SetText("calcD").SetTooltip("计算私钥(D)").OnClick(func(e events.Event) {
	//	calcD := r.CalcD(info.E, info.P, info.Q)
	//	if calcD == nil {
	//		return
	//	}
	//	info.D = string(calcD.HexStringUpper())
	//	view.SetStruct(info)
	//})
	//widget.NewButton(newFrame).SetText("FactorizationN").SetTooltip("因式分解(N)").OnClick(func(e events.Event) {
	//})

	switches := gi.NewSwitches(newFrame).SetType(gi.SwitchSegmentedButton).SetMutex(true).
		SetItems(
			gi.SwitchItem{Label: "gen pai", Tooltip: "生成密钥对"},
			gi.SwitchItem{Label: "encode", Tooltip: "加密 C=M^e(mod n)"},
			gi.SwitchItem{Label: "decode", Tooltip: "解密 M=C^d(mod n)"},
			gi.SwitchItem{Label: "calcD", Tooltip: "计算私钥(D)"},
			gi.SwitchItem{Label: "FactorizationN", Tooltip: "因式分解(N)"},
		)
	// gi.NewSpace(newFrame)
	switches.OnChange(func(e events.Event) {
		switch switches.SelectedItem() {
		case "gen pai":
		case "encode":
			encrypt := r.Encrypt(stream.NewBuffer(info.M), info.N, info.E)
			if encrypt == nil {
				return
			}
			info.C = string(encrypt.HexStringUpper())
			view.SetStruct(info)
		case "decode":
			decrypt := r.Decrypt(stream.NewHexString(safeType.HexString(info.C)), info.N, info.E, info.D)
			if decrypt == nil {
				return
			}
			info.M = decrypt.String()
			view.SetStruct(info)
		case "calcD":
			calcD := r.CalcD(info.E, info.P, info.Q)
			if calcD == nil {
				return
			}
			info.D = string(calcD.HexStringUpper())
			view.SetStruct(info)
		case "FactorizationN":
		}
	})

	newTabs.NewTab("ecc")
	newTabs.NewTab("dsa")
	newTabs.NewTab("pgp")
	newTabs.NewTab("sm4")
	newTabs.NewTab("sm2")

	//////////////////////////////hashWithHmac页面//////////////////////////////
	hashWithHmac := tabs.NewTab("Hash").SetTooltip("哈西 hmac")
	hashTab := gi.NewTabs(hashWithHmac)

	type HmacData struct {
		Src        string `width:"158" immediate:"+"`
		Key        string `width:"158" immediate:"+"`
		HmacSha1   string `width:"158"`
		HmacSha224 string `width:"158"`
		HmacSha256 string `width:"158"`
		HmacSha384 string `width:"158"`
		HmacSha512 string `width:"158"`
	}
	hmacData := &HmacData{
		Src:        "",
		Key:        "",
		HmacSha1:   "",
		HmacSha224: "",
		HmacSha256: "",
		HmacSha384: "",
		HmacSha512: "",
	}
	HmacStructView := giv.NewStructView(hashTab.NewTab("Hmac")).SetStruct(hmacData)
	HmacStructView.OnInput(func(e events.Event) {
		h := hmac.New()
		*hmacData = HmacData{
			Src:        hmacData.Src,
			Key:        hmacData.Key,
			HmacSha1:   string(h.HmacSha1(hmacData.Src, safeType.HexString(hmacData.Key)).HexString()),
			HmacSha224: string(h.HmacSha224(hmacData.Src, safeType.HexString(hmacData.Key)).HexString()),
			HmacSha256: string(h.HmacSha256(hmacData.Src, safeType.HexString(hmacData.Key)).HexString()),
			HmacSha384: string(h.HmacSha384(hmacData.Src, safeType.HexString(hmacData.Key)).HexString()),
			HmacSha512: string(h.HmacSha512(hmacData.Src, safeType.HexString(hmacData.Key)).HexString()),
		}
		HmacStructView.Update()
	})

	type HashData struct {
		Src    string `width:"158" immediate:"+"`
		Md2    string `width:"158"`
		Md4    string `width:"158"`
		Md5    string `width:"158"`
		Sha1   string `width:"158"`
		Sha224 string `width:"158"`
		Sha256 string `width:"158"`
		Sha384 string `width:"158"`
		Sha512 string `width:"158"`
	}
	hashData := &HashData{
		Src:    "",
		Md2:    "",
		Md4:    "",
		Md5:    "",
		Sha1:   "",
		Sha224: "",
		Sha256: "",
		Sha384: "",
		Sha512: "",
	}
	hashStructView := giv.NewStructView(hashTab.NewTab("hash")).SetStruct(hashData)
	hashStructView.OnInput(func(e events.Event) {
		src := hashData.Src
		*hashData = HashData{
			Src:    src,
			Md2:    hash.Md2(src),
			Md4:    hash.Md4(src),
			Md5:    hash.Md5(src),
			Sha1:   hash.Sha1(src),
			Sha224: hash.Sha224(src),
			Sha256: hash.Sha256(src),
			Sha384: hash.Sha384(src),
			Sha512: hash.Sha512(src),
		}
		mylog.Struct(hashData)
		hashStructView.Update()
	})

	Encoding := tabs.NewTab("Encoding").SetTooltip("编码")
	e := gi.NewTabs(Encoding)
	CanvasTemplate(e.NewTab("Base64"), template, Base64)
	CanvasTemplate(e.NewTab("Base32"), template, Base32)
	CanvasTemplate(e.NewTab("Gzip"), template, Gzip)

	//////////////////////////////工具页面//////////////////////////////
	tool := tabs.NewTab("tool").SetTooltip("工具")

	t := gi.NewTabs(tool)
	splits := gi.NewSplits(t.NewTab("tool"))
	SrcEditor := texteditor.NewEditor(splits)
	buf := texteditor.NewBuf()
	buf.SetText([]byte("111"))
	SrcEditor.SetBuf(buf)

	dstEditor := texteditor.NewEditor(splits)
	dstBuf := texteditor.NewBuf()
	dstBuf.SetText([]byte("111"))
	dstEditor.SetBuf(dstBuf)

	frame := gi.NewFrame(tool)
	frame.Style(func(s *styles.Style) {
		// s.Display = styles.Grid
	})
	timeConv := unixTimestampConverter.New()
	gi.NewSwitch(frame).SetText("ToUpper").SetTooltip("大写").OnChange(func(e events.Event) {
		buf.SetText([]byte(strings.ToUpper(string(buf.Text()))))
		SrcEditor.SetBuf(buf)
	})
	gi.NewSwitch(frame).SetText("isTimeStampHex").SetTooltip("hex utc").OnChange(func(e events.Event) {
		dstBuf.SetText([]byte(timeConv.FromInteger(string(buf.Text()))))
		dstEditor.SetBuf(dstBuf)
	})

	widget.NewButton(frame).SetText("space").SetTooltip("去空格").OnClick(func(e events.Event) {
		space := strings.Replace(string(buf.Text()), " ", "", -1) // 去除空格
		// str = strings.Replace(str, "\n", "", -1) // 去除换行符
		buf.SetText([]byte(space))
		SrcEditor.SetBuf(buf)
	})
	widget.NewButton(frame).SetText("swap").SetTooltip("逆序").OnClick(func(e events.Event) {
		array := stream.SwapBytes(buf.Text())
		buf.SetText(array)
		SrcEditor.SetBuf(buf)
	})
	widget.NewButton(frame).SetText("head").SetTooltip("charles head").OnClick(func(e events.Event) {
		a := packetHeadToGo.New()
		if !a.Convert(string(buf.Text())) {
			return
		}
		dstBuf.SetText([]byte(a.String()))
		dstEditor.SetBuf(buf)
	})
	widget.NewButton(frame).SetText("timeStamp").SetTooltip("时间戳转换").OnClick(func(e events.Event) {
		dstBuf.SetText([]byte(timeConv.FromInteger(string(buf.Text()))))
		dstEditor.SetBuf(buf)
	})

	b.RunMainWindow()
}

type (
	ObjectTemplate struct {
		Src string `width:"50"`
		Key string `width:"50"`
		Dst string `width:"50"`
	}
)

func CanvasTemplate(parent *gi.Frame, template *ObjectTemplate, kind Kind) {
	structView := giv.NewStructView(parent)
	frame := gi.NewFrame(parent) // 水平布局需要,按钮是自动的？
	encode := widget.NewButton(frame).SetText("encode")
	decode := widget.NewButton(frame).SetText("decode")
	structView.SetStruct(template)
	encode.OnClick(func(e events.Event) {
		switch kind {
		case Aes:
			template.Dst = string(aes.Encrypt(safeType.HexString(template.Src), safeType.HexString(template.Key)).HexString())
		case Des:
			template.Dst = string(des.Encrypt(safeType.HexString(template.Src), safeType.HexString(template.Key)).HexString())
		case Des3:
		case Tea:
		case Blowfish:
		case TwoFish:
		case Rc4:
		case Rc2:
		case Rsa:
		case Ecc:
		case Dsa:
		case Pgp:
		case Sm4:
		case Sm2:
		case Base64:
			template.Dst = base64.New().StdEncoding().EncodeToString([]byte(template.Src))
		case Base32:
			template.Dst = base32.New().StdEncoding().EncodeToString([]byte(template.Src))
		case Gzip:
		}
		structView.SetStruct(template)
	})
	decode.OnClick(func(e events.Event) {
		switch kind {
		case Aes:
			template.Src = string(aes.Decrypt(safeType.HexString(template.Dst), safeType.HexString(template.Key)).HexString())
		case Des:
			template.Src = string(des.Decrypt(safeType.HexString(template.Dst), safeType.HexString(template.Key)).HexString())
		case Des3:
		case Tea:
		case Blowfish:
		case TwoFish:
		case Rc4:
		case Rc2:
		case Rsa:
		case Ecc:
		case Dsa:
		case Pgp:
		case Sm4:
		case Sm2:
		case Base64:
			decodeString, err := base64.New().StdEncoding().DecodeString(template.Dst)
			mylog.Check(err)
			template.Src = string(decodeString)
		case Base32:
			decodeString, err := base32.New().StdEncoding().DecodeString(template.Dst)
			mylog.Check(err)
			template.Src = string(decodeString)
		case Gzip:
			template.Src = string(stream.ReaderGzip(safeType.HexString(template.Dst)).HexStringUpper())
		}
		structView.SetStruct(template)
	})
}

type Kind byte

const (
	Aes Kind = iota
	Des
	Des3
	Tea
	Blowfish
	TwoFish
	Rc4
	Rc2

	Rsa
	Ecc
	Dsa
	Pgp
	Sm4
	Sm2

	Base64
	Base32
	Gzip
)
