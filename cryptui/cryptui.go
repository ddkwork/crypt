package cryptui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"github.com/ddkwork/golibrary/src/fynelib/canvasobjectapi"
)

type (
	Interface interface{ canvasobjectapi.Interface }
	object    struct{}
)

func (o *object) CanvasObject(fyne.Window) fyne.CanvasObject {
	leftAppTabs := container.NewAppTabs(
		container.NewTabItem(typeCrypt.typeSymmetry(), o.CanvasObjectSymmetry()),
		container.NewTabItem(typeCrypt.typeAsymmetrical(), o.CanvasObjectAsymmetrical()),
		container.NewTabItem(typeCrypt.typeHash(), o.CanvasObjectHash()),
		container.NewTabItem(typeCrypt.typeEncoding(), o.CanvasObjectEncoding()),
		container.NewTabItem(typeCrypt.typeTool(), o.CanvasObjectTool()),
	)
	leftAppTabs.SetTabLocation(container.TabLocationLeading)
	return leftAppTabs
}

func New() Interface { return &object{} }

func (o *object) CanvasObjectSymmetry() fyne.CanvasObject {
	appTabs := container.NewAppTabs(
		container.NewTabItem(typeCrypt.aes(), o.aesCanvasObject()),
		container.NewTabItem(typeCrypt.des(), o.desCanvasObject()),
		container.NewTabItem(typeCrypt.des3(), o.des3CanvasObject()),
		container.NewTabItem(typeCrypt.tea(), o.teaCanvasObject()),
		container.NewTabItem(typeCrypt.blowfish(), o.blofishCanvasObject()),
		container.NewTabItem(typeCrypt.twoFish(), o.twofishCanvasObject()),
		container.NewTabItem(typeCrypt.rc4(), o.rc4CanvasObject()),
	)
	appTabs.SetTabLocation(container.TabLocationTop)
	return appTabs
}

func (o *object) CanvasObjectAsymmetrical() fyne.CanvasObject {
	appTabs := container.NewAppTabs(
		container.NewTabItem(typeCrypt.rsa(), o.CanvasObjectRsa()),
		container.NewTabItem(typeCrypt.ecc(), o.CanvasObjectEcc()),
		container.NewTabItem(typeCrypt.dsa(), o.CanvasObjectEcc()),
		container.NewTabItem(typeCrypt.pgp(), o.CanvasObjectEcc()),
	)
	appTabs.SetTabLocation(container.TabLocationTop)
	return appTabs
}

func (o *object) CanvasObjectHash() fyne.CanvasObject {
	appTabs := container.NewAppTabs(
		container.NewTabItem(typeCrypt.hmacSha(), o.hmacCanvasObject()),
		container.NewTabItem(typeCrypt.hash(), o.hashCanvasObject()),
	)
	appTabs.SetTabLocation(container.TabLocationTop)
	return appTabs
}

func (o *object) CanvasObjectEncoding() fyne.CanvasObject {
	appTabs := container.NewAppTabs(
		container.NewTabItem(typeCrypt.base64(), o.Base64CanvasObject()),
		container.NewTabItem(typeCrypt.base32(), o.Base32CanvasObject()),
		container.NewTabItem(typeCrypt.gzip(), o.gzipCanvasObject()),
	)
	appTabs.SetTabLocation(container.TabLocationTop)
	return appTabs
}

func (o *object) CanvasObjectTool() fyne.CanvasObject {
	f := clone()
	return f.Form()
}
