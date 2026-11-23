//go:build darwin

package main

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	"github.com/egoist/mygo"
)

var (
	qlMu         sync.Mutex
	qlPaths      []string
	qlController objc.ID
	qlAttached   bool
)

var initQuickLook = sync.OnceValue(func() error {
	if _, err := purego.Dlopen("/System/Library/Frameworks/QuickLookUI.framework/QuickLookUI", purego.RTLD_GLOBAL|purego.RTLD_NOW); err != nil {
		return err
	}
	if objc.GetClass("QLPreviewPanel") == 0 {
		return errors.New("QLPreviewPanel unavailable")
	}
	cls, err := objc.RegisterClass(
		"GodwitQuickLookController",
		objc.GetClass("NSResponder"),
		nil,
		nil,
		[]objc.MethodDef{
			{
				Cmd: objc.RegisterName("acceptsPreviewPanelControl:"),
				Fn:  func(id objc.ID, sel objc.SEL, panel objc.ID) bool { return true },
			},
			{
				Cmd: objc.RegisterName("beginPreviewPanelControl:"),
				Fn: func(id objc.ID, sel objc.SEL, panel objc.ID) {
					panel.Send(objc.RegisterName("setDataSource:"), id)
				},
			},
			{
				Cmd: objc.RegisterName("endPreviewPanelControl:"),
				Fn: func(id objc.ID, sel objc.SEL, panel objc.ID) {
					panel.Send(objc.RegisterName("setDataSource:"), objc.ID(0))
				},
			},
			{
				Cmd: objc.RegisterName("numberOfPreviewItemsInPreviewPanel:"),
				Fn: func(id objc.ID, sel objc.SEL, panel objc.ID) int64 {
					qlMu.Lock()
					defer qlMu.Unlock()
					return int64(len(qlPaths))
				},
			},
			{
				Cmd: objc.RegisterName("previewPanel:previewItemAtIndex:"),
				Fn: func(id objc.ID, sel objc.SEL, panel objc.ID, index int64) objc.ID {
					qlMu.Lock()
					var path string
					if index >= 0 && int(index) < len(qlPaths) {
						path = qlPaths[index]
					}
					qlMu.Unlock()
					if path == "" {
						return 0
					}
					nsStr := qlString(path)
					return objc.ID(objc.GetClass("NSURL")).Send(objc.RegisterName("fileURLWithPath:"), nsStr)
				},
			},
		},
	)
	if err != nil {
		return err
	}
	qlController = objc.ID(cls).Send(objc.RegisterName("new"))
	return nil
})

func qlString(s string) objc.ID {
	str := objc.ID(objc.GetClass("NSString")).Send(objc.RegisterName("alloc"))
	str = str.Send(objc.RegisterName("initWithBytes:length:encoding:"), unsafe.StringData(s), uintptr(len(s)), uintptr(4))
	runtime.KeepAlive(s)
	return str.Send(objc.RegisterName("autorelease"))
}

// PreviewPath opens path in macOS Quick Look (QLPreviewPanel), falling back to
// OpenPath when Quick Look is unavailable.
func (p *platform) PreviewPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err := initQuickLook(); err != nil {
		return p.OpenPath(path)
	}
	qlMu.Lock()
	qlPaths = []string{path}
	qlMu.Unlock()
	mygo.RunOnMain(func() {
		if !qlAttached && p.win != nil {
			win := objc.ID(p.win.NativeHandle())
			next := win.Send(objc.RegisterName("nextResponder"))
			qlController.Send(objc.RegisterName("setNextResponder:"), next)
			win.Send(objc.RegisterName("setNextResponder:"), qlController)
			qlAttached = true
		}
		panel := objc.ID(objc.GetClass("QLPreviewPanel")).Send(objc.RegisterName("sharedPreviewPanel"))
		panel.Send(objc.RegisterName("setDataSource:"), qlController)
		panel.Send(objc.RegisterName("updateController"))
		panel.Send(objc.RegisterName("reloadData"))
		panel.Send(objc.RegisterName("makeKeyAndOrderFront:"), objc.ID(0))
	})
	return nil
}
