package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godwit-email/godwit/internal/smime"
)

func makeRawSMIME(from, to, id, subject, payload string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return []byte(fmt.Sprintf(
		"Message-ID: <%s>\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n",
		id, from, to, subject, b64,
	))
}

func callIndex(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func TestReaderSMIMEStartsBeforeNewBodyViewAndBuffersEarlyCompletion(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s1@x", "Secret 1", "cipher-1"))

	r := h.app.mail.reader
	openStarted := make(chan struct{})
	openDone := make(chan struct{})
	r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
		close(openStarted)
		defer close(openDone)
		return []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>early body</p>"), true, "bob@example.com", nil
	}

	h.plat.onNewView = func(message int64) {
		if message != msg.ID {
			return
		}
		select {
		case <-openStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("openSMIME did not start before NewBodyView")
		}
		// Pump the UI queue so openSMIME's completion runs BEFORE NewBodyView returns.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-openDone:
			default:
				time.Sleep(time.Millisecond)
				continue
			}
			h.drain()
			if b := r.bodies[msg.ID]; b != nil && b.smimePending != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("openSMIME completion was not buffered into smimePending before NewBodyView returned")
	}

	h.openThread(msg.ThreadID)
	wantNew := fmt.Sprintf("NewBodyView %d", msg.ID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("ShowSecureBody after NewBodyView", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0
	})

	calls := h.plat.Calls()
	ni, si := callIndex(calls, wantNew), callIndex(calls, wantShow)
	if ni < 0 || si < 0 || ni >= si {
		t.Fatalf("calls = %v; want %s before %s", calls, wantNew, wantShow)
	}
	b := r.bodies[msg.ID]
	if b == nil || b.smimeResult == nil || !b.smimeResult.encrypted || b.smimePending != nil {
		t.Fatalf("unexpected smime body state: %+v", b)
	}
}

func TestReaderSMIMEDeliversAfterNewBodyViewAndReusesMemoryCacheOnReexpand(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s2@x", "Secret 2", "cipher-2"))

	r := h.app.mail.reader
	var openCalls atomic.Int32
	allowOpen := make(chan struct{})
	openStarted := make(chan struct{})
	r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
		openCalls.Add(1)
		close(openStarted)
		select {
		case <-allowOpen:
		case <-ctx.Done():
			return nil, false, "", ctx.Err()
		}
		return []byte("Content-Type: text/plain; charset=utf-8\r\n\r\nlate body"), true, "bob@example.com", nil
	}

	h.plat.onNewView = func(message int64) {
		if message == msg.ID {
			select {
			case <-openStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("openSMIME did not start before NewBodyView")
			}
		}
	}

	h.openThread(msg.ThreadID)
	h.until("NewBodyView created", func() bool {
		return callIndex(h.plat.Calls(), fmt.Sprintf("NewBodyView %d", msg.ID)) >= 0
	})
	if callIndex(h.plat.Calls(), fmt.Sprintf("ShowSecureBody %d", msg.ID)) >= 0 {
		t.Fatal("ShowSecureBody fired before decryption completed")
	}

	close(allowOpen)
	h.until("ShowSecureBody after decryption completes", func() bool {
		return callIndex(h.plat.Calls(), fmt.Sprintf("ShowSecureBody %d", msg.ID)) >= 0
	})
	if openCalls.Load() != 1 {
		t.Fatalf("openCalls = %d, want 1", openCalls.Load())
	}

	// 折叠再重新展开，应命中内存缓存并紧随新 NewBodyView 后交付，且不再次调用 openCMS。
	h.plat.onNewView = nil
	r.toggle(msg.ID)
	h.tt.Frame()
	r.toggle(msg.ID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("second ShowSecureBody from memory cache", func() bool {
		return h.countCalls(wantShow) == 2
	})
	if openCalls.Load() != 1 {
		t.Fatalf("openCalls after re-expand = %d, want 1", openCalls.Load())
	}
}

func TestReaderSMIMENewBodyViewErrorAndSwitchStopsDecryption(t *testing.T) {
	t.Run("view_error", func(t *testing.T) {
		h, accs := mailHarness(t, nil, "alice@example.com")
		h.app.cards = smime.NewSession(h.app.ctx)
		msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s3@x", "Secret 3", "cipher-3"))

		r := h.app.mail.reader
		started := make(chan struct{})
		cancelled := make(chan struct{})
		r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, false, "", ctx.Err()
		}
		h.plat.onNewView = func(message int64) {
			if message == msg.ID {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("openSMIME did not start before NewBodyView")
				}
			}
		}
		h.plat.viewErr = errors.New("webview boom")

		h.openThread(msg.ThreadID)
		h.until("body error set", func() bool {
			b := r.bodies[msg.ID]
			return b != nil && b.err != nil
		})
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("smime decryption context not cancelled on NewBodyView error")
		}
		b := r.bodies[msg.ID]
		if b.smimePending != nil || h.countCalls(fmt.Sprintf("ShowSecureBody %d", msg.ID)) != 0 {
			t.Fatalf("unexpected secure delivery after NewBodyView error: %+v calls=%v", b, h.plat.Calls())
		}
	})

	t.Run("switch_during_view", func(t *testing.T) {
		h, accs := mailHarness(t, nil, "alice@example.com")
		h.app.cards = smime.NewSession(h.app.ctx)
		msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s4@x", "Secret 4", "cipher-4"))

		r := h.app.mail.reader
		started := make(chan struct{})
		cancelled := make(chan struct{})
		r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, false, "", ctx.Err()
		}
		h.plat.onNewView = func(message int64) {
			if message == msg.ID {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("openSMIME did not start before NewBodyView")
				}
				// 模拟在创建 NewBodyView 期间会话已被切走。
				r.reset([2]int64{})
			}
		}

		h.openThread(msg.ThreadID)
		h.until("NewBodyView attempted", func() bool {
			return callIndex(h.plat.Calls(), fmt.Sprintf("NewBodyView %d", msg.ID)) >= 0
		})
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("smime decryption context not cancelled on session switch during NewBodyView")
		}
		if h.countCalls(fmt.Sprintf("ShowSecureBody %d", msg.ID)) != 0 {
			t.Fatalf("stale ShowSecureBody emitted: %v", h.plat.Calls())
		}
	})
}
