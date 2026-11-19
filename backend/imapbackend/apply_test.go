package imapbackend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/godwit-email/godwit/backend"
	"github.com/godwit-email/godwit/backend/conn"
)

// 263Mail rejects quoted HEADER field names ("Message-ID") with NO and only
// matches Message-ID values with angle brackets; a go-imap bump that loses
// the atom encoding patch or a change dropping the brackets fails here.
func TestFindSearchHeaderUnquotedAndBracketed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("* OK [CAPABILITY IMAP4rev1] ready\r\n"))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return
			}
			tag := fields[0]
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, strings.ToUpper(tag)+" LOGIN "):
				c.Write([]byte(tag + " OK [CAPABILITY IMAP4rev1] logged in\r\n"))
			case strings.HasPrefix(upper, strings.ToUpper(tag)+" SELECT "),
				strings.HasPrefix(upper, strings.ToUpper(tag)+" EXAMINE "):
				c.Write([]byte("* 1 EXISTS\r\n* OK [UIDVALIDITY 2] UIDs valid\r\n" + tag + " OK [READ-ONLY] SELECT Completed\r\n"))
			case strings.Contains(upper, "UID SEARCH"):
				if strings.Contains(line, `HEADER "Message-ID"`) {
					c.Write([]byte(tag + " NO UID SEARCH search error: can't search that criteria\r\n"))
					continue
				}
				switch {
				case strings.Contains(line, `HEADER Message-ID "<a@x>"`) &&
					(!strings.Contains(upper, "LARGER") || strings.Contains(upper, "LARGER 49 SMALLER 51")):
					c.Write([]byte("* SEARCH 7\r\n" + tag + " OK UID SEARCH Completed\r\n"))
				default:
					c.Write([]byte("* SEARCH\r\n" + tag + " OK UID SEARCH Completed\r\n"))
				}
			case strings.Contains(upper, "UID FETCH 7 "):
				hdr := "Message-Id: <a@x>\r\n\r\n"
				fmt.Fprintf(c, "* 1 FETCH (UID 7 BODY[HEADER.FIELDS (MESSAGE-ID)] {%d}\r\n%s)\r\n%s OK UID FETCH Completed\r\n", len(hdr), hdr, tag)
			default:
				c.Write([]byte(tag + " OK done\r\n"))
			}
		}
	}()

	r := New(Config{
		Host:     "127.0.0.1",
		Port:     ln.Addr().(*net.TCPAddr).Port,
		Security: conn.None,
		Credentials: func(context.Context) (backend.Credentials, error) {
			return backend.Credentials{Username: "alice", Password: "secret"}, nil
		},
	})
	defer r.Close()

	want := []backend.MessageRef{backend.MessageRef(Encode(2, 7))}
	for _, size := range []int64{0, 50} {
		got, err := r.Find(t.Context(), "Sent", "a@x", size)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("Find(size=%d) = %v, %v; want %v", size, got, err, want)
		}
	}
	if got, err := r.Find(t.Context(), "Sent", "missing@x", 0); err != nil || len(got) != 0 {
		t.Fatalf("Find(missing) = %v, %v; want empty", got, err)
	}
}

func TestFetchReusesReadOnlySelect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var examines []string
	uid10Visible := false

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("* OK [CAPABILITY IMAP4rev1] ready\r\n"))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return
			}
			tag := fields[0]
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, strings.ToUpper(tag)+" LOGIN "):
				c.Write([]byte(tag + " OK [CAPABILITY IMAP4rev1] logged in\r\n"))
			case strings.HasPrefix(upper, strings.ToUpper(tag)+" EXAMINE "),
				strings.HasPrefix(upper, strings.ToUpper(tag)+" SELECT "):
				folder := strings.Trim(fields[2], `"`)
				mu.Lock()
				examines = append(examines, folder)
				if folder == "INBOX" && len(examines) >= 3 {
					uid10Visible = true
				}
				mu.Unlock()
				val := 1
				if folder == "Other" {
					val = 2
				}
				fmt.Fprintf(c, "* 1 EXISTS\r\n* OK [UIDVALIDITY %d] UIDs valid\r\n%s OK [READ-ONLY] EXAMINE Completed\r\n", val, tag)
			case strings.Contains(upper, "UID FETCH 1 "):
				body := "one"
				fmt.Fprintf(c, "* 1 FETCH (UID 1 BODY[1] {%d}\r\n%s)\r\n%s OK UID FETCH Completed\r\n", len(body), body, tag)
			case strings.Contains(upper, "UID FETCH 2 "):
				body := "two"
				fmt.Fprintf(c, "* 2 FETCH (UID 2 BODY[1] {%d}\r\n%s)\r\n%s OK UID FETCH Completed\r\n", len(body), body, tag)
			case strings.Contains(upper, "UID FETCH 3 "):
				body := "three"
				fmt.Fprintf(c, "* 1 FETCH (UID 3 BODY[1] {%d}\r\n%s)\r\n%s OK UID FETCH Completed\r\n", len(body), body, tag)
			case strings.Contains(upper, "UID FETCH 10 "):
				mu.Lock()
				vis := uid10Visible
				mu.Unlock()
				if vis {
					body := "ten"
					fmt.Fprintf(c, "* 2 FETCH (UID 10 BODY[1] {%d}\r\n%s)\r\n%s OK UID FETCH Completed\r\n", len(body), body, tag)
				} else {
					fmt.Fprintf(c, "%s OK UID FETCH Completed\r\n", tag)
				}
			default:
				c.Write([]byte(tag + " OK done\r\n"))
			}
		}
	}()

	r := New(Config{
		Host:     "127.0.0.1",
		Port:     ln.Addr().(*net.TCPAddr).Port,
		Security: conn.None,
		Credentials: func(context.Context) (backend.Credentials, error) {
			return backend.Credentials{Username: "alice", Password: "secret"}, nil
		},
	})
	defer r.Close()

	fetchOne := func(folder string, validity, uid uint32) string {
		rc, err := r.Fetch(t.Context(), backend.ContentRequest{
			Location: backend.Location{Folder: backend.FolderRef(folder), Ref: backend.MessageRef(Encode(validity, uid))},
			Part:     "1",
		})
		if err != nil {
			t.Fatalf("Fetch(%s, %d): %v", folder, uid, err)
		}
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("ReadAll(%s, %d): %v", folder, uid, err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("Close(%s, %d): %v", folder, uid, err)
		}
		return string(b)
	}

	if got := fetchOne("INBOX", 1, 1); got != "one" {
		t.Fatalf("got %q, want one", got)
	}
	if got := fetchOne("INBOX", 1, 2); got != "two" {
		t.Fatalf("got %q, want two", got)
	}
	if got := fetchOne("Other", 2, 3); got != "three" {
		t.Fatalf("got %q, want three", got)
	}
	// Back to INBOX: fresh EXAMINE reveals UID 10 without retrying twice, and
	// wait: test reused folder miss triggering one fresh EXAMINE retry.
	if got := fetchOne("INBOX", 1, 1); got != "one" {
		t.Fatalf("got %q, want one", got)
	}
	// Simulate UID 10 newly visible only after re-EXAMINE on INBOX: reset flag to false until next EXAMINE!
	mu.Lock()
	uid10Visible = false
	countBefore := len(examines)
	mu.Unlock()
	if got := fetchOne("INBOX", 1, 10); got != "ten" {
		t.Fatalf("got %q, want ten after fresh EXAMINE retry", got)
	}

	mu.Lock()
	gotExamines := slices.Clone(examines)
	mu.Unlock()
	// First two INBOX fetches -> 1 EXAMINE; Other -> 1 EXAMINE; third INBOX fetch -> 1 EXAMINE; UID 10 miss on reused INBOX -> 1 EXAMINE retry.
	want := []string{"INBOX", "Other", "INBOX", "INBOX"}
	if !slices.Equal(gotExamines, want) || countBefore != 3 {
		t.Fatalf("examines = %v (before=%d), want %v", gotExamines, countBefore, want)
	}
}
