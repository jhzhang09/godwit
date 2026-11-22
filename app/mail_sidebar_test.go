package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/godwit-email/godwit/core"
	"github.com/godwit-email/godwit/core/coretest"
	"github.com/godwit-email/godwit/internal/i18n"
)

func TestSidebarFolders(t *testing.T) {
	fs := []core.Folder{
		{ID: 1, Name: "INBOX", Role: "inbox", Delim: ".", Unread: 3},
		{ID: 2, Name: "[Gmail]/All Mail", Role: "archive", Delim: "/"}, // ListFolders resolves All Mail as the archive
		{ID: 3, Name: "[Gmail]/Starred", Role: "flagged", Delim: "/"},
		{ID: 4, Name: "[Gmail]/Important", Delim: "/"}, // no row of ours: shown as it is
		{ID: 5, Name: "[Gmail]/Spam", Role: "junk", Delim: "/"},
		{ID: 6, Name: "INBOX.Projects.Q4.Contracts", Delim: ".", Unread: 2},
		{ID: 7, Name: "INBOX.Projects.Expenses", Delim: ".", Unread: 1},
		{ID: 8, Name: "Projects Old", Delim: "."},
		{ID: 9, Name: "INBOX.Projects", Delim: "."},
		{ID: 10, Name: "flat", Delim: ""},
		{ID: 12, Name: "Projects", Delim: ".", Unread: 4}, // not INBOX.Projects, though it shows the same name
	}
	var got []string
	for _, f := range sidebarFolders(7, fs) {
		row := strings.Repeat("  ", f.depth-1) + f.name
		if f.ID == 0 && f.Role == "" {
			row += " (prefix)"
		}
		if f.kids {
			row += " +" + string(rune('0'+f.sum))
		}
		got = append(got, row)
	}
	want := []string{
		"收件箱 +6",
		"  Projects +3",
		"    Expenses",
		"    Q4 (prefix) +2",
		"      Contracts",
		"已标星", "草稿", "归档", "垃圾邮件", // drafts are local
		"Projects", "Projects Old",
		"[Gmail] (prefix) +0", "  Important", "flat",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("rows\n%q\nwant\n%q", got, want)
	}

	// Subfolders under role folders like 已归档/... must nest under 归档, while top-level 存档 stays at root.
	fs2 := []core.Folder{
		{ID: 1, Name: "INBOX", Role: "inbox", Delim: "/", Unread: 1},
		{ID: 2, Name: "INBOX/罗飞", Delim: "/", Unread: 2},
		{ID: 3, Name: "已归档", Role: "archive", Delim: "/"},
		{ID: 4, Name: "已归档/帮助邮箱", Delim: "/", Unread: 1},
		{ID: 5, Name: "存档", Delim: "/"},
	}
	var got2 []string
	for _, f := range sidebarFolders(8, fs2) {
		row := strings.Repeat("  ", f.depth-1) + f.name
		if f.kids {
			row += " +" + string(rune('0'+f.sum))
		}
		got2 = append(got2, row)
	}
	want2 := []string{"收件箱 +3", "  罗飞", "已标星", "草稿", "归档 +1", "  帮助邮箱", "存档"}
	if strings.Join(got2, "|") != strings.Join(want2, "|") {
		t.Fatalf("role subfolder tree\n%q\nwant\n%q", got2, want2)
	}
}

// TestSidebarFolderTree: an account's own folders nest on the server's
// delimiter, each level 16 further in; a parent folds, then counts the unread
// under it.
func TestSidebarFolderTree(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	srv := h.env.IMAP(accs[0].ID).User
	for _, m := range []string{"Projects/Q4/Contracts", "Projects/Q4/Invoices", "Projects/Expenses", "Clients", "Clients/Acme"} {
		if err := srv.Create(m, nil); err != nil {
			t.Fatal(err)
		}
	}
	h.put(accs[0], "Projects/Q4/Contracts", coretest.Msg("bob@example.com", accs[0].Email, "contract", "x"))
	h.put(accs[0], "Projects/Expenses", coretest.Msg("bob@example.com", accs[0].Email, "receipt", "x"))
	h.syncNow(accs[0])
	h.waitMail("the folder tree", func() bool { return h.tt.HasText("Contracts") })
	x := func(name string) float32 {
		r, ok := h.tt.Find(name)
		if !ok {
			t.Fatalf("no %s: %q", name, h.tt.Texts())
		}
		return r.X
	}
	if d1, d2 := x("Q4")-x("Projects"), x("Contracts")-x("Q4"); d1 != 16 || d2 != 16 || x("Projects") != x("已发送") {
		t.Fatalf("indents %v %v, Projects at %v and 已发送 at %v", d1, d2, x("Projects"), x("已发送"))
	}
	h.click("Projects") // only a prefix: the row folds it
	h.until("Projects folded", func() bool { return !h.tt.HasText("Contracts") && !h.tt.HasText("Expenses") })
	if ts := h.tt.Texts(); slices.Index(ts, "Projects") < 0 || ts[slices.Index(ts, "Projects")+1] != "2" {
		t.Fatalf("folded Projects does not count the unread under it: %q", ts)
	}
	h.click("Projects")
	h.until("Projects unfolded", func() bool { return h.tt.HasText("Contracts") })
	// The sidebar's foot (Settings, sync status) leaves its list room for fewer rows: scroll it until the row shows.
	for range 10 {
		if r, ok := h.tt.Find("Contracts"); ok && r.H > 0 {
			break
		}
		h.tt.Scroll(100, 400, 0, 30)
		h.tt.Frame()
	}
	h.click("Contracts")
	if v := h.app.route.View; v.FolderID == 0 {
		t.Fatalf("view %+v", v)
	}
	h.click("收起Clients") // a folder itself: its chevron folds it, the row opens it
	h.until("Clients folded", func() bool { return !h.tt.HasText("Acme") })
	h.click("Clients")
	if v := h.app.route.View; v.FolderID != h.folderNamed(accs[0], "Clients").ID {
		t.Fatalf("view %+v", v)
	}
}

func (h *harness) folderNamed(acc core.Account, name string) core.Folder {
	h.t.Helper()
	for _, f := range h.app.mail.folders[acc.ID] {
		if f.Name == name {
			return f
		}
	}
	h.t.Fatalf("no folder %s", name)
	return core.Folder{}
}

// TestSidebarSpacingAndLevel2Height checks that nested sidebar rows match
// top-level height (32px) and that dragging Accounts before Labels keeps
// the full section gap between them.
func TestSidebarSpacingAndLevel2Height(t *testing.T) {
	h, acc, m := labeledMail(t)
	h.autoLabel(m.ID, "otp")
	h.waitMail("label group", func() bool {
		return slices.ContainsFunc(h.app.labels, func(l core.Label) bool { return l.Slug == "otp" && l.Count > 0 })
	})
	st := h.app.settings
	st.SidebarOrder = "views,accounts,labels"
	st.SidebarAccountsOpen = map[int64]bool{acc.ID: false}
	h.app.changeSettings(st)
	h.until("reordered sections", func() bool {
		h.tt.Frame()
		return h.tt.HasText(i18n.T("mail.accounts")) && h.tt.HasText("标签")
	})

	// Level-2 inbox account row matches level-1 row height (32px).
	accInbox, ok := h.tt.Access(acc.Email + " · 收件箱")
	if !ok {
		t.Fatal("missing nested inbox row")
	}
	if accInbox.Bounds.H != 32 {
		t.Errorf("nested inbox row height = %v, want 32", accInbox.Bounds.H)
	}

	// Section gap between Accounts' last row and Labels header is >= 14px.
	otherAcc, ok := h.tt.Access(acc.Email + " · " + i18n.T("mail.accounts"))
	if !ok {
		t.Fatal("missing account row under Accounts")
	}
	lblHead, ok := h.tt.Find("标签")
	if !ok {
		t.Fatal("missing Labels section header")
	}
	if gap := lblHead.Y - (otherAcc.Bounds.Y + otherAcc.Bounds.H); gap < 14 {
		t.Errorf("gap between Accounts and Labels = %v, want >= 14", gap)
	}
}

func TestSidebarInboxSummaryAndAccountTree(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.resize(1440, 1200)
	srv := h.env.IMAP(accs[0].ID).User
	for _, m := range []string{"INBOX/OA", "INBOX/Team/Sub", "Archive/Help", "Docs"} {
		if err := srv.Create(m, nil); err != nil {
			t.Fatal(err)
		}
	}
	h.put(accs[0], "INBOX/OA", coretest.Msg("bob@example.com", accs[0].Email, "oa msg", "x"))
	h.syncNow(accs[0])
	h.waitMail("full inbox tree loaded", func() bool {
		return h.tt.HasText("OA") && h.tt.HasText("Help") && h.tt.HasText("Docs")
	})

	// Under 账户 -> account, 收件箱 sits above 已标星/草稿/已发送/归档 with its nested subfolders.
	accHeader, ok := h.tt.Find(accs[0].Email + " · " + i18n.T("mail.accounts"))
	if !ok {
		t.Fatal("missing account header under Accounts")
	}
	inboxRow, ok := h.tt.Find("收件箱")
	if !ok || inboxRow.Y <= accHeader.Y {
		t.Fatalf("expected 收件箱 under account header (%v), got %+v", accHeader, inboxRow)
	}
	oaRow, ok := h.tt.Find("OA")
	if !ok || oaRow.Y <= inboxRow.Y {
		t.Fatalf("expected OA under 收件箱 (%v), got %+v", inboxRow, oaRow)
	}
	sentRow, ok := h.tt.Find("已发送")
	if !ok || sentRow.Y <= oaRow.Y {
		t.Fatalf("expected 已发送 below OA (%v), got %+v", oaRow, sentRow)
	}

	// Folding 收件箱 under the account hides its subfolders while keeping 已发送/归档 visible.
	h.click("收起收件箱")
	h.until("account inbox folded", func() bool { return !h.tt.HasText("OA") && !h.tt.HasText("Team") })
	h.see("已发送")
	h.see("归档")
	h.see("Help")
	h.see("Docs")

	// Under 全部收件箱, the account summary row starts collapsed and expands ONLY inbox subfolders.
	summaryInbox, ok := h.tt.Find(accs[0].Email + " · 收件箱")
	if !ok {
		t.Fatal("missing inbox summary row under All Inboxes")
	}
	h.click(i18n.Tf("mail.folder.expand", accs[0].Email))
	h.until("inbox summary expanded", func() bool { return h.tt.HasText("OA") && h.tt.HasText("Team") && h.tt.HasText("Sub") })
	oaSummary, ok := h.tt.Find("OA")
	if !ok || !(summaryInbox.Y < oaSummary.Y && oaSummary.Y < accHeader.Y) {
		t.Fatalf("expected OA inside summary between %v and %v, got %+v", summaryInbox, accHeader, oaSummary)
	}
	// Only inbox subfolders appear under 全部收件箱 (Archive/Help and Docs stay strictly in Accounts).
	if helpRow, _ := h.tt.Find("Help"); helpRow.Y < accHeader.Y {
		t.Fatalf("Help should not appear under All Inboxes, got %+v", helpRow)
	}
	if docsRow, _ := h.tt.Find("Docs"); docsRow.Y < accHeader.Y {
		t.Fatalf("Docs should not appear under All Inboxes, got %+v", docsRow)
	}
	h.click("OA")
	if got := h.app.route.View.FolderID; got != h.folderNamed(accs[0], "INBOX/OA").ID {
		t.Fatalf("navigated to folder %d, want INBOX/OA", got)
	}
}
