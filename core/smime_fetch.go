package core

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godwit-email/godwit/backend"
	"github.com/godwit-email/godwit/core/events"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/smime"
)

var (
	smimePrefetchBudget  int64 = 1536 << 20
	smimePrefetchFastMax int64 = 1 << 20
	smimePrefetchMaxItem int64 = 5 << 20
	smimePriorityMaxItem int64 = 10 << 20
	smimePrefetchBatch         = 25
	smimePrefetchPause         = 3 * time.Second
	smimeConnIdleTTL           = 3 * time.Minute
	smimeFailedSkipTTL         = 30 * time.Minute
)

const (
	smimeP7MPredicate  = `(COALESCE(lower(a.content_type),'') IN ('application/pkcs7-mime','application/x-pkcs7-mime') OR COALESCE(lower(a.filename),'') = 'smime.p7m')`
	smimeP7SPredicate  = `(COALESCE(lower(a.content_type),'') IN ('application/pkcs7-signature','application/x-pkcs7-signature') OR COALESCE(lower(a.filename),'') = 'smime.p7s')`
	smimePartPredicate = `(` + smimeP7MPredicate + ` OR ` + smimeP7SPredicate + `)`

	smimeTierUrgent = iota + 1
	smimeTierVisible
	smimeTierGlobal
)

type smimeConn struct {
	recv    backend.Receiver
	release func()
	timer   *time.Timer
	gen     uint64
}

type smimeCandidate struct {
	id        int64
	folderRef string
	date      int64
}

type smimeState struct {
	wake             chan struct{}
	touchCh          chan int64
	certWake         chan struct{}
	certStop         chan struct{}
	certDone         chan struct{}
	mu               sync.Mutex
	closed           bool
	touchActive      bool
	prefetchCancel   map[int64]context.CancelFunc
	interactiveMu    map[int64]*sync.Mutex
	prefetchMu       map[int64]*sync.Mutex
	interactiveConns map[int64]*smimeConn
	prefetchConns    map[int64]*smimeConn
	holdUntil        map[int64]time.Time
	backoffUntil     map[int64]time.Time
	backoffStep      map[int64]time.Duration
	failed           map[int64]time.Time
	urgentThreads    []int64
	visibleThreads   []int64
	prioGen          uint64
	gen              uint64
}

func (st *smimeState) lockFor(accountID int64, interactive bool) *sync.Mutex {
	st.mu.Lock()
	defer st.mu.Unlock()
	if interactive {
		if st.interactiveMu == nil {
			st.interactiveMu = map[int64]*sync.Mutex{}
		}
		m := st.interactiveMu[accountID]
		if m == nil {
			m = &sync.Mutex{}
			st.interactiveMu[accountID] = m
		}
		return m
	}
	if st.prefetchMu == nil {
		st.prefetchMu = map[int64]*sync.Mutex{}
	}
	m := st.prefetchMu[accountID]
	if m == nil {
		m = &sync.Mutex{}
		st.prefetchMu[accountID] = m
	}
	return m
}

func (st *smimeState) connPool(interactive bool) map[int64]*smimeConn {
	if interactive {
		if st.interactiveConns == nil {
			st.interactiveConns = map[int64]*smimeConn{}
		}
		return st.interactiveConns
	}
	if st.prefetchConns == nil {
		st.prefetchConns = map[int64]*smimeConn{}
	}
	return st.prefetchConns
}

func (st *smimeState) borrowConn(accountID int64, interactive bool) *smimeConn {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return nil
	}
	pool := st.connPool(interactive)
	c := pool[accountID]
	if c == nil {
		return nil
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	delete(pool, accountID)
	return c
}

func (st *smimeState) returnConn(accountID int64, interactive bool, c *smimeConn) {
	if c == nil {
		return
	}
	var prev *smimeConn
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		c.release()
		return
	}
	pool := st.connPool(interactive)
	prev = pool[accountID]
	if prev != nil && prev.timer != nil {
		prev.timer.Stop()
		prev.timer = nil
	}
	st.gen++
	gen := st.gen
	c.gen = gen
	c.timer = time.AfterFunc(smimeConnIdleTTL, func() { st.expireConn(accountID, interactive, gen) })
	pool[accountID] = c
	st.mu.Unlock()
	if prev != nil {
		prev.release()
	}
}

func (st *smimeState) expireConn(accountID int64, interactive bool, gen uint64) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	pool := st.connPool(interactive)
	c := pool[accountID]
	if c == nil || c.gen != gen {
		st.mu.Unlock()
		return
	}
	delete(pool, accountID)
	st.mu.Unlock()
	c.release()
}

func (st *smimeState) holdPrefetch(accountID int64, d time.Duration) {
	until := time.Now().Add(d)
	st.mu.Lock()
	if st.holdUntil == nil {
		st.holdUntil = map[int64]time.Time{}
	}
	if until.After(st.holdUntil[accountID]) {
		st.holdUntil[accountID] = until
	}
	st.mu.Unlock()
}

func (st *smimeState) waitDelay(ctx context.Context, accountID int64, checkBackoff bool) error {
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return ErrClosed
		}
		var until time.Time
		if h := st.holdUntil[accountID]; h.After(until) {
			until = h
		}
		if checkBackoff {
			if b := st.backoffUntil[accountID]; b.After(until) {
				until = b
			}
		}
		st.mu.Unlock()
		wait := time.Until(until)
		if wait <= 0 {
			return ctx.Err()
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}

func (st *smimeState) setPrefetchCancel(accountID int64, cancel context.CancelFunc) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return false
	}
	if st.prefetchCancel == nil {
		st.prefetchCancel = map[int64]context.CancelFunc{}
	}
	if cancel == nil {
		delete(st.prefetchCancel, accountID)
	} else {
		st.prefetchCancel[accountID] = cancel
	}
	return true
}

func (st *smimeState) cancelPrefetch(accountID int64) bool {
	st.mu.Lock()
	cancel := st.prefetchCancel[accountID]
	delete(st.prefetchCancel, accountID)
	st.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

func (st *smimeState) nextBackoff(accountID int64) time.Duration {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.backoffStep == nil {
		st.backoffStep = map[int64]time.Duration{}
	}
	if st.backoffUntil == nil {
		st.backoffUntil = map[int64]time.Time{}
	}
	d := st.backoffStep[accountID]
	switch {
	case d <= 0:
		d = 5 * time.Second
	case d < 15*time.Second:
		d = 15 * time.Second
	case d < 30*time.Second:
		d = 30 * time.Second
	default:
		d = 60 * time.Second
	}
	st.backoffStep[accountID] = d
	st.backoffUntil[accountID] = time.Now().Add(d)
	return d
}

func (st *smimeState) clearBackoff(accountID int64) {
	st.mu.Lock()
	delete(st.backoffStep, accountID)
	delete(st.backoffUntil, accountID)
	st.mu.Unlock()
}

func (st *smimeState) clearAllBackoff() {
	st.mu.Lock()
	clear(st.backoffStep)
	clear(st.backoffUntil)
	st.mu.Unlock()
}

func (st *smimeState) markFailed(id int64) {
	now := time.Now()
	st.mu.Lock()
	if st.failed == nil {
		st.failed = map[int64]time.Time{}
	}
	for k, exp := range st.failed {
		if !exp.After(now) {
			delete(st.failed, k)
		}
	}
	if len(st.failed) >= 256 {
		clear(st.failed)
	}
	st.failed[id] = now.Add(smimeFailedSkipTTL)
	st.mu.Unlock()
}

func (st *smimeState) failedIDs() []int64 {
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.failed) == 0 {
		return nil
	}
	out := make([]int64, 0, len(st.failed))
	for id, exp := range st.failed {
		if !exp.After(now) {
			delete(st.failed, id)
			continue
		}
		out = append(out, id)
	}
	return out
}

func (st *smimeState) enqueueTouch(id int64) bool {
	if st == nil || st.touchCh == nil {
		return false
	}
	st.mu.Lock()
	active := !st.closed && st.touchActive
	st.mu.Unlock()
	if !active {
		return false
	}
	select {
	case st.touchCh <- id:
	default:
	}
	return true
}

func (st *smimeState) snapshotPrio() (urgent, visible []int64, gen uint64) {
	st.mu.Lock()
	urgent = slices.Clone(st.urgentThreads)
	visible = slices.Clone(st.visibleThreads)
	gen = st.prioGen
	st.mu.Unlock()
	return urgent, visible, gen
}

func (st *smimeState) prioInterrupted(tier int, startGen uint64) bool {
	if tier == smimeTierUrgent {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.prioGen == startGen {
		return false
	}
	return len(st.urgentThreads) > 0 || (tier == smimeTierGlobal && len(st.visibleThreads) > 0)
}

func (st *smimeState) closeAll() {
	st.mu.Lock()
	st.closed = true
	st.touchActive = false
	certStop := st.certStop
	st.certStop = nil
	certDone := st.certDone
	cancels := make([]context.CancelFunc, 0, len(st.prefetchCancel))
	for id, fn := range st.prefetchCancel {
		cancels = append(cancels, fn)
		delete(st.prefetchCancel, id)
	}
	conns := make([]*smimeConn, 0, len(st.interactiveConns)+len(st.prefetchConns))
	for _, pool := range []map[int64]*smimeConn{st.interactiveConns, st.prefetchConns} {
		for id, c := range pool {
			if c.timer != nil {
				c.timer.Stop()
				c.timer = nil
			}
			conns = append(conns, c)
			delete(pool, id)
		}
	}
	st.mu.Unlock()
	for _, fn := range cancels {
		fn()
	}
	for _, c := range conns {
		c.release()
	}
	if certStop != nil {
		close(certStop)
	}
	if certDone != nil {
		<-certDone
	}
}

func (s *Service) initSMIME() {
	s.smime = &smimeState{
		wake:     make(chan struct{}, 1),
		touchCh:  make(chan int64, 64),
		certWake: make(chan struct{}, 1),
	}
	if s.opts.AutoSync {
		s.startSMIMEPrefetch()
		s.startSMIMECertIndexer()
	}
}

func (s *Service) closeSMIME() {
	s.clearDecryptedBodies()
	if s.smime != nil {
		s.smime.closeAll()
	}
}

func (s *Service) cachedSMIME(ctx context.Context, a attRow) (string, bool, error) {
	if a.cachePath == "" {
		return "", false, nil
	}
	if _, err := os.Stat(a.cachePath); err != nil {
		return "", false, nil
	}
	if s.smime != nil && s.smime.enqueueTouch(a.info.ID) {
		return a.cachePath, true, nil
	}
	return a.cachePath, true, s.touch(ctx, a.info.ID)
}

// prioritizeSMIMEThread 将当前打开的会话线程提到 S/MIME 密文预取队列最前面。
func (s *Service) prioritizeSMIMEThread(threadID int64) {
	st := s.smime
	if st == nil || threadID == 0 {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	next := make([]int64, 0, 4)
	next = append(next, threadID)
	for _, id := range st.urgentThreads {
		if id != threadID && len(next) < 4 {
			next = append(next, id)
		}
	}
	if !slices.Equal(st.urgentThreads, next) {
		st.urgentThreads = next
		st.prioGen++
	}
	st.mu.Unlock()
	s.wakeSMIMEPrefetch()
}

// prioritizeSMIMEThreads 将当前列表视图可见的会话提到预取队列前列。
func (s *Service) prioritizeSMIMEThreads(items []ThreadSummary) {
	st := s.smime
	if st == nil || len(items) == 0 {
		return
	}
	const maxVisible = 50
	next := make([]int64, 0, min(len(items), maxVisible))
	for _, it := range items {
		if it.ID == 0 {
			continue
		}
		next = append(next, it.ID)
		if len(next) >= maxVisible {
			break
		}
	}
	if len(next) == 0 {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	if !slices.Equal(st.visibleThreads, next) {
		st.visibleThreads = next
		st.prioGen++
	}
	st.mu.Unlock()
	s.wakeSMIMEPrefetch()
}

// pauseSMIMEPrefetch 暂停正在后台预取该账户 smime.p7m 密文的批次，让交互打开优先而不拆断连接。
func (s *Service) pauseSMIMEPrefetch(accountID int64) {
	if s.smime == nil {
		return
	}
	s.smime.holdPrefetch(accountID, smimePrefetchPause)
}

func (s *Service) wakeSMIMEPrefetch() {
	if s.smime == nil || s.smime.wake == nil {
		return
	}
	select {
	case s.smime.wake <- struct{}{}:
	default:
	}
}

func isSMIMEMissingPartErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no longer on the server") ||
		strings.Contains(msg, "not available on the server") ||
		strings.Contains(msg, "server folder changed") ||
		strings.Contains(msg, "not found")
}

// fetchSMIMEDirect 使用独立于 syncNow 账号锁的常驻只读 IMAP 连接下载 smime.p7m 原始密文，
// 避免查看加密邮件被全量文件夹同步阻塞。若服务器拒绝并发连接，则交回常规路径排队处理。
func (s *Service) fetchSMIMEDirect(ctx context.Context, a attRow) (string, bool, error) {
	path, handled, _, err := s.fetchSMIMEPart(ctx, a.info.ID, a.accountID, true, true)
	return path, handled, err
}

func (s *Service) fetchSMIMEPart(ctx context.Context, attachmentID, accountID int64, interactive, runEvict bool) (string, bool, bool, error) {
	st := s.smime
	if st == nil {
		return "", false, false, nil
	}
	if err := ctx.Err(); err != nil {
		return "", true, false, err
	}
	if interactive {
		st.holdPrefetch(accountID, smimePrefetchPause)
	} else if err := st.waitDelay(ctx, accountID, false); err != nil {
		return "", true, false, err
	}

	mu := st.lockFor(accountID, interactive)
	mu.Lock()
	defer mu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", true, false, err
	}
	a, err := s.loadAttachment(ctx, attachmentID)
	if err != nil {
		return "", true, false, err
	}
	if !smime.IsCMSPart(a.info.ContentType, a.info.Filename) || a.contentHash != "" {
		return "", false, false, nil
	}
	if p, ok, err := s.cachedSMIME(ctx, a); ok || err != nil {
		return p, true, false, err
	}
	if int64(a.info.Size) > attachLimit {
		return "", true, false, ErrTooLarge
	}
	if !a.onServer {
		return "", true, false, ErrNotOnServerYet
	}

	c := st.borrowConn(a.accountID, interactive)
	if c == nil && interactive {
		c = st.borrowConn(a.accountID, false)
	}
	var data []byte
	for {
		reused := c != nil
		if c == nil {
			recv, cancel, derr := s.dialSMIMEConn(ctx, st, a.accountID, interactive)
			if derr != nil {
				if errors.Is(derr, backend.ErrAuthFailed) || ctx.Err() != nil {
					return "", true, true, derr
				}
				if interactive {
					return "", false, true, nil
				}
				return "", true, true, derr
			}
			c = &smimeConn{recv: recv, release: cancel}
		}

		stopFetch := context.AfterFunc(ctx, func() { _ = c.recv.Close() })
		fetched, ferr := fetchPart(ctx, c.recv, a)
		alive := stopFetch()
		if ferr == nil && alive && ctx.Err() == nil {
			data = fetched
			break
		}
		c.release()
		c = nil
		if !alive || ctx.Err() != nil {
			return "", true, false, ctx.Err()
		}
		if errors.Is(ferr, ErrTooLarge) {
			s.db.Execute(ctx, "UPDATE attachments SET size = ? WHERE id = ?", attachLimit+1, attachmentID)
			return "", true, false, ferr
		}
		if !reused || isSMIMEMissingPartErr(ferr) {
			return "", true, false, ferr
		}
	}

	st.returnConn(a.accountID, interactive, c)
	path, err := s.saveAttachmentChecked(ctx, a, data)
	if errors.Is(err, ErrTooLarge) {
		s.db.Execute(ctx, "UPDATE attachments SET size = ? WHERE id = ?", attachLimit+1, attachmentID)
		return "", true, false, err
	}
	if err != nil {
		return "", true, false, err
	}
	if runEvict {
		evictCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = s.evict(evictCtx, cacheLimit, attachmentID)
		cancel()
	}
	return path, true, false, nil
}

func (s *Service) dialSMIMEConn(ctx context.Context, st *smimeState, accountID int64, interactive bool) (backend.Receiver, func(), error) {
	dialAttempt := func() (backend.Receiver, func(), error) {
		dialCtx, dialCancel := context.WithCancel(context.Background())
		stopDial := context.AfterFunc(ctx, dialCancel)
		recv, rel, derr := s.dialDownload(dialCtx, accountID)
		alive := stopDial()
		if derr != nil || !alive || ctx.Err() != nil {
			if rel != nil {
				rel()
			}
			dialCancel()
			if ctx.Err() != nil || !alive {
				return nil, nil, ctx.Err()
			}
			return nil, nil, derr
		}
		return recv, func() { rel(); dialCancel() }, nil
	}

	recv, rel, derr := dialAttempt()
	if derr == nil || !interactive || errors.Is(derr, backend.ErrAuthFailed) || ctx.Err() != nil {
		return recv, rel, derr
	}
	// 服务器并发连接数达上限时，再兜底中止后台预取腾出连接槽。
	if !st.cancelPrefetch(accountID) {
		return nil, nil, derr
	}
	t := time.NewTimer(300 * time.Millisecond)
	select {
	case <-t.C:
	case <-ctx.Done():
		t.Stop()
		return nil, nil, ctx.Err()
	}
	return dialAttempt()
}

func (s *Service) saveAttachmentChecked(ctx context.Context, a attRow, data []byte) (string, error) {
	if int64(len(data)) > attachLimit {
		return "", ErrTooLarge
	}
	path, err := filepath.Abs(filepath.Join(s.cacheDir(a.accountID), strconv.FormatInt(a.info.ID, 10)))
	if err != nil {
		return "", err
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if err := store.WriteFileAtomic(path, data); err != nil {
		return "", err
	}
	res, err := s.db.Execute(ctx, "UPDATE attachments SET cache_path = ?, last_used = ? WHERE id = ?", path, time.Now().Unix(), a.info.ID)
	if err != nil {
		os.Remove(path)
		return "", err
	}
	if res.Changes == 0 {
		os.Remove(path)
		return "", errors.New("attachment not found")
	}
	return path, nil
}

// startSMIMEPrefetch 在后台仅预取加密的 smime.p7m 原始密文附件，不解密也不落盘任何明文。
func (s *Service) startSMIMEPrefetch() {
	ctx, end, err := s.begin(context.Background(), 0)
	if err != nil {
		return
	}
	s.smime.mu.Lock()
	if s.smime.closed {
		s.smime.mu.Unlock()
		end()
		return
	}
	s.smime.touchActive = true
	s.smime.mu.Unlock()

	ch, unsub := s.bus.Subscribe()
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer unsub()
		defer workers.Done()
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if ev.Type == events.SyncFinished {
					s.smime.clearAllBackoff()
					s.wakeSMIMEPrefetch()
				} else if ev.Type == events.MessageReceived {
					s.wakeSMIMEPrefetch()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case id := <-s.smime.touchCh:
				tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_ = s.touch(tctx, id)
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		t := time.NewTimer(3 * time.Second)
		select {
		case <-t.C:
			s.wakeSMIMEPrefetch()
		case <-s.smime.wake:
			t.Stop()
			s.wakeSMIMEPrefetch()
		case <-ctx.Done():
			t.Stop()
			return
		}
		for {
			select {
			case <-s.smime.wake:
			case <-ctx.Done():
				return
			}
			rows, err := s.db.Query(ctx, "SELECT id FROM accounts WHERE COALESCE(kind, '') != ? AND status = 'ok' ORDER BY is_default DESC, position, id", KindLocalArchive)
			if err != nil {
				continue
			}
			var retryWait time.Duration
			for _, r := range rows.Values {
				if ctx.Err() != nil {
					return
				}
				if w := s.prefetchSMIMEAccount(ctx, store.Int(r[0])); w > 0 && (retryWait == 0 || w < retryWait) {
					retryWait = w
				}
			}
			if retryWait > 0 && ctx.Err() == nil {
				pt := time.NewTimer(retryWait)
				select {
				case <-pt.C:
					s.wakeSMIMEPrefetch()
				case <-s.smime.wake:
					pt.Stop()
					s.wakeSMIMEPrefetch()
				case <-ctx.Done():
					pt.Stop()
					return
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		end()
	}()
}

func smimePlaceholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func smimeNotInClause(col string, ids []int64, args *[]any) string {
	if len(ids) == 0 {
		return ""
	}
	for _, id := range ids {
		*args = append(*args, id)
	}
	return " AND " + col + " NOT IN (" + smimePlaceholders(len(ids)) + ")"
}

func (s *Service) querySMIMEBatch(ctx context.Context, accountID int64, used int64) (rows []smimeCandidate, tier int, gen uint64, err error) {
	st := s.smime
	tierBudget := (cacheLimit * 7) / 8
	if smimePrefetchBudget < cacheLimit {
		if b := smimePrefetchBudget + smimePrefetchBudget/4; b < tierBudget {
			tierBudget = b
		}
	}
	globalBudget := min(smimePrefetchBudget, (cacheLimit*3)/4)
	urgent, visible, prioGen := st.snapshotPrio()
	skip := st.failedIDs()

	queryThreads := func(threads []int64) ([]smimeCandidate, error) {
		if len(threads) == 0 || used >= tierBudget {
			return nil, nil
		}
		args := []any{accountID}
		for _, id := range threads {
			args = append(args, id)
		}
		args = append(args, smimePriorityMaxItem)
		skipClause := smimeNotInClause("a.id", skip, &args)
		args = append(args, smimePrefetchBatch)
		res, qerr := s.db.Query(ctx, `SELECT a.id, COALESCE(MIN(f.server_ref), ''), MAX(m.date)
			FROM attachments a
			JOIN messages m ON m.id = a.message_id
			JOIN message_locations l ON l.message_id = m.id
			JOIN folders f ON f.id = l.folder_id
			WHERE m.account_id = ? AND m.thread_id IN (`+smimePlaceholders(len(threads))+`)
				AND l.shown = 1 AND l.server_ref IS NOT NULL
				AND a.cache_path IS NULL AND a.part = '1'
				AND a.size > 0 AND a.size <= ?
				AND `+smimeP7MPredicate+skipClause+`
			GROUP BY a.id
			ORDER BY MAX(m.date) DESC, a.id DESC
			LIMIT ?`, args...)
		if qerr != nil {
			return nil, qerr
		}
		out := make([]smimeCandidate, 0, len(res.Values))
		for _, r := range res.Values {
			out = append(out, smimeCandidate{id: store.Int(r[0]), folderRef: store.Str(r[1]), date: store.Int(r[2])})
		}
		return out, nil
	}

	if items, qerr := queryThreads(urgent); qerr != nil {
		return nil, 0, prioGen, qerr
	} else if len(items) > 0 {
		return items, smimeTierUrgent, prioGen, nil
	}
	if items, qerr := queryThreads(visible); qerr != nil {
		return nil, 0, prioGen, qerr
	} else if len(items) > 0 {
		return items, smimeTierVisible, prioGen, nil
	}
	if used >= globalBudget {
		return nil, 0, prioGen, nil
	}

	queryGlobal := func(maxItem int64) ([]smimeCandidate, error) {
		args := []any{accountID, maxItem}
		skipClause := smimeNotInClause("a.id", skip, &args)
		args = append(args, smimePrefetchBatch)
		res, qerr := s.db.Query(ctx, `SELECT a.id, COALESCE(MIN(f.server_ref), ''), MAX(m.date)
			FROM attachments a
			JOIN messages m ON m.id = a.message_id
			JOIN message_locations l ON l.message_id = m.id
			JOIN folders f ON f.id = l.folder_id
			WHERE m.account_id = ? AND l.shown = 1 AND l.server_ref IS NOT NULL
				AND a.cache_path IS NULL AND a.part = '1'
				AND a.size > 0 AND a.size <= ?
				AND `+smimeP7MPredicate+skipClause+`
			GROUP BY a.id
			ORDER BY MIN(CASE WHEN f.role IN ('trash','junk','drafts') THEN 1 ELSE 0 END), MAX(m.date) DESC, a.id DESC
			LIMIT ?`, args...)
		if qerr != nil {
			return nil, qerr
		}
		out := make([]smimeCandidate, 0, len(res.Values))
		for _, r := range res.Values {
			out = append(out, smimeCandidate{id: store.Int(r[0]), folderRef: store.Str(r[1]), date: store.Int(r[2])})
		}
		return out, nil
	}

	fastMax := min(smimePrefetchFastMax, smimePrefetchMaxItem)
	if items, qerr := queryGlobal(fastMax); qerr != nil {
		return nil, 0, prioGen, qerr
	} else if len(items) > 0 {
		return items, smimeTierGlobal, prioGen, nil
	}
	if smimePrefetchMaxItem > fastMax {
		if items, qerr := queryGlobal(smimePrefetchMaxItem); qerr != nil {
			return nil, 0, prioGen, qerr
		} else if len(items) > 0 {
			return items, smimeTierGlobal, prioGen, nil
		}
	}
	return nil, 0, prioGen, nil
}

// sortBatchByFolder 按批次内最新日期为每个文件夹排序，使同一批次复用到同文件夹的只读 EXAMINE。
func sortBatchByFolder(items []smimeCandidate) {
	if len(items) <= 1 {
		return
	}
	folderNewest := make(map[string]int64, len(items))
	for _, it := range items {
		if it.date > folderNewest[it.folderRef] {
			folderNewest[it.folderRef] = it.date
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].folderRef != items[j].folderRef {
			ni, nj := folderNewest[items[i].folderRef], folderNewest[items[j].folderRef]
			if ni != nj {
				return ni > nj
			}
			return items[i].folderRef < items[j].folderRef
		}
		return items[i].date > items[j].date
	})
}

// prefetchSMIMEAccount 按优先级与最近时间分批预取 smime.p7m 密文，遇到交互查看让路并在退避后恢复。
func (s *Service) prefetchSMIMEAccount(ctx context.Context, accountID int64) (retryAfter time.Duration) {
	st := s.smime
	if st == nil {
		return 0
	}
	for ctx.Err() == nil {
		if err := st.waitDelay(ctx, accountID, true); err != nil {
			return 0
		}
		sumRows, err := s.db.Query(ctx, `SELECT COALESCE(SUM(a.size), 0)
			FROM attachments a JOIN messages m ON m.id = a.message_id
			WHERE m.account_id = ? AND a.cache_path IS NOT NULL AND a.part = '1' AND `+smimeP7MPredicate, accountID)
		if err != nil || len(sumRows.Values) == 0 {
			return 0
		}
		used := store.Int(sumRows.Values[0][0])
		items, tier, prioGen, err := s.querySMIMEBatch(ctx, accountID, used)
		if err != nil || len(items) == 0 {
			return 0
		}
		sortBatchByFolder(items)

		bctx, cancel := context.WithCancel(ctx)
		if !st.setPrefetchCancel(accountID, cancel) {
			cancel()
			return 0
		}

		var saved []int64
		var nextRetry time.Duration
		stop := false
		for _, it := range items {
			if st.prioInterrupted(tier, prioGen) {
				break
			}
			if err := st.waitDelay(bctx, accountID, false); err != nil {
				if ctx.Err() == nil {
					nextRetry = smimePrefetchPause
				}
				stop = true
				break
			}
			if bctx.Err() != nil {
				if ctx.Err() == nil {
					nextRetry = smimePrefetchPause
				}
				stop = true
				break
			}
			_, _, dialFailed, gerr := s.fetchSMIMEPart(bctx, it.id, accountID, false, false)
			if gerr == nil {
				st.clearBackoff(accountID)
				saved = append(saved, it.id)
				continue
			}
			if bctx.Err() != nil && ctx.Err() == nil {
				nextRetry = smimePrefetchPause
				stop = true
				break
			}
			if ctx.Err() != nil || errors.Is(gerr, ErrClosed) {
				stop = true
				break
			}
			if errors.Is(gerr, backend.ErrAuthFailed) {
				stop = true
				break
			}
			if dialFailed {
				log.Printf("smime prefetch: dial account %d: %v", accountID, gerr)
				nextRetry = st.nextBackoff(accountID)
				stop = true
				break
			}
			st.clearBackoff(accountID)
			st.markFailed(it.id)
			if !errors.Is(gerr, ErrTooLarge) && !errors.Is(gerr, ErrNotOnServerYet) && !isSMIMEMissingPartErr(gerr) {
				log.Printf("smime prefetch: skip account %d att %d: %v", accountID, it.id, gerr)
			}
		}
		if len(saved) > 0 && ctx.Err() == nil {
			evictCtx, evCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = s.evict(evictCtx, cacheLimit, saved...)
			evCancel()
		}
		st.setPrefetchCancel(accountID, nil)
		cancel()

		if nextRetry > 0 {
			return nextRetry
		}
		if stop {
			return 0
		}
		t := time.NewTimer(100 * time.Millisecond)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return 0
		}
	}
	return 0
}
