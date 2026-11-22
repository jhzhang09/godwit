package mail

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gorilla/css/scanner"
	"github.com/tdewolff/parse/v2"
	tcss "github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Mail styles itself with <style> blocks: classes, media queries for narrow
// windows, the dark scheme. sanitizeCSS keeps what can be shown safely, working
// on the parsed stylesheet and CSS tokens, not on text: the rules whose
// declarations pass the same whitelist as inline styles (cssProps; values of
// plain tokens, no url(), no position), each selector scoped under
// #godwit-body so the mail's styles cannot reach the app's own page, and
// @media. Every other at-rule (@import, @font-face, @keyframes…) goes.
//
// A (prefers-color-scheme) query does not reach the page as one: its rules are
// scoped under .godwit-dark or .godwit-light on #godwit-body, which the reader
// sets from the theme (web/src/reader/frame.ts), so the mail follows the theme,
// not the system.

const (
	cssRoot     = "#godwit-body" // where the reader puts a body
	maxCSSBytes = 256 << 10      // of stylesheet read from one message
	maxCSSRules = 3000           // rules kept from one message
)

var cssAllowed = func() map[string]bool {
	m := map[string]bool{"background-image": true} // gradients: its url() is not a plain token, so it never passes
	for _, p := range cssProps {
		m[p] = true
	}
	return m
}()

// styleSheet is a <style> element's sheet, and its media attribute.
type styleSheet struct{ text, media string }

// sanitizeCSS is the safe, scoped form of the stylesheets, "" when nothing
// stays, and whether the mail has styles of its own for the dark scheme. A
// block whose media cannot be kept is left out: its rules would hold where it
// does not; the others are kept.
func sanitizeCSS(sheets []styleSheet) (out string, darkAware bool) {
	var b strings.Builder
	rules := 0
	for _, sh := range sheets {
		text := sh.text
		if len(text) > maxCSSBytes {
			text = text[:maxCSSBytes]
		}
		sheet := parseSheet(text)
		if m := strings.TrimSpace(sh.media); m != "" && !strings.EqualFold(m, "all") {
			// as one @media around the sheet: its own @media, nested, go
			prelude, scheme, ok := mediaQuery(m)
			if !ok {
				continue
			}
			var inner strings.Builder
			for _, r := range sheet {
				writeRule(&inner, r, scheme, 1, &rules, &darkAware)
			}
			if inner.Len() > 0 {
				b.WriteString("@media " + prelude + "{" + inner.String() + "}\n")
			}
			continue
		}
		for _, r := range sheet {
			writeRule(&b, r, "", 0, &rules, &darkAware)
		}
	}
	return b.String(), darkAware
}

// cssRule is a rule of a stylesheet: a qualified one (at is "") with its
// selectors as prelude, or an at-rule with a block.
type cssRule struct {
	at, prelude string
	decls       []cssDecl
	rules       []*cssRule
}

type cssDecl struct {
	prop, value string
	important   bool
}

// parseSheet reads text as a browser does (CSS Syntax Level 3): what does not
// parse is left out, the rest kept. A sheet whose blocks the parser closes
// without saying so (it does on a stray ) or ] in a selector) is left out
// whole: which rules are inside which cannot be told.
func parseSheet(text string) []*cssRule {
	p := tcss.NewParser(parse.NewInputString(text), false)
	var top, open []*cssRule
	for {
		gt, _, data := p.Next()
		switch gt {
		case tcss.ErrorGrammar:
			if p.HasParseError() {
				continue // the parser goes on past it
			}
			if len(open) > 0 {
				return nil
			}
			return top
		case tcss.BeginRulesetGrammar, tcss.BeginAtRuleGrammar:
			r := &cssRule{prelude: tokenText(p.Values())}
			if gt == tcss.BeginAtRuleGrammar {
				r.at = string(data)
			}
			if len(open) == 0 {
				top = append(top, r)
			} else {
				parent := open[len(open)-1]
				parent.rules = append(parent.rules, r)
			}
			open = append(open, r)
		case tcss.EndRulesetGrammar, tcss.EndAtRuleGrammar:
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
		case tcss.DeclarationGrammar:
			if len(open) == 0 {
				continue
			}
			v := p.Values()
			n := len(v)
			important := n >= 2 && v[n-2].TokenType == tcss.DelimToken && string(v[n-2].Data) == "!" &&
				v[n-1].TokenType == tcss.IdentToken && strings.EqualFold(string(v[n-1].Data), "important")
			if important {
				v = v[:n-2]
			}
			r := open[len(open)-1]
			r.decls = append(r.decls, cssDecl{string(data), strings.TrimSpace(tokenText(v)), important})
		}
	}
}

// tokenText is ts written back; the parser has already collapsed whitespace.
func tokenText(ts []tcss.Token) string {
	var b strings.Builder
	for _, t := range ts {
		b.Write(t.Data)
	}
	return b.String()
}

// writeRule writes r when it is safe; scheme is "dark" or "light" inside a
// query for it.
func writeRule(b *strings.Builder, r *cssRule, scheme string, depth int, rules *int, dark *bool) {
	if *rules >= maxCSSRules {
		return
	}
	switch r.at {
	case "":
		decls := declarations(r.decls)
		if decls == "" {
			return
		}
		sels := scopeSelector(r.prelude, scheme)
		if len(sels) == 0 {
			return
		}
		*rules++
		if scheme == "dark" {
			*dark = true
		}
		b.WriteString(strings.Join(sels, ",") + "{" + decls + "}\n")
	case "@media": // the parser lowercases at-rule names
		if depth > 0 {
			return
		}
		prelude, scheme, ok := mediaQuery(r.prelude)
		if !ok {
			return
		}
		var inner strings.Builder
		for _, c := range r.rules {
			writeRule(&inner, c, scheme, depth+1, rules, dark)
		}
		if inner.Len() > 0 {
			b.WriteString("@media " + prelude + "{" + inner.String() + "}\n")
		}
	}
}

// tokens are s's CSS tokens; false when s does not tokenize or has a < (a
// stylesheet goes into a <style>, which it must not leave).
func tokens(s string) ([]*scanner.Token, bool) {
	var out []*scanner.Token
	sc := scanner.New(s)
	for {
		t := sc.Next()
		switch t.Type {
		case scanner.TokenEOF:
			return out, true
		case scanner.TokenError:
			return nil, false
		}
		if strings.ContainsRune(t.Value, '<') {
			return nil, false
		}
		out = append(out, t)
	}
}

func isIdent(t *scanner.Token, v string) bool {
	return t.Type == scanner.TokenIdent && strings.EqualFold(t.Value, v)
}

func isChar(t *scanner.Token, chars string) bool {
	return t.Type == scanner.TokenChar && strings.Contains(chars, t.Value)
}

func join(ts []*scanner.Token) string {
	var b strings.Builder
	for _, t := range ts {
		b.WriteString(t.Value)
	}
	return b.String()
}

// splitAt splits ts at the sep (one character) outside parentheses.
func splitAt(ts []*scanner.Token, sep string) [][]*scanner.Token {
	var out [][]*scanner.Token
	depth, start := 0, 0
	for i, t := range ts {
		switch {
		case t.Type == scanner.TokenFunction || isChar(t, "("):
			depth++
		case isChar(t, ")"):
			depth--
		case isChar(t, sep) && depth == 0:
			out = append(out, ts[start:i])
			start = i + 1
		}
	}
	return append(out, ts[start:])
}

func trimS(ts []*scanner.Token) []*scanner.Token {
	for len(ts) > 0 && ts[0].Type == scanner.TokenS {
		ts = ts[1:]
	}
	for len(ts) > 0 && ts[len(ts)-1].Type == scanner.TokenS {
		ts = ts[:len(ts)-1]
	}
	return ts
}

// selectorFuncs are the functional pseudo-classes a selector may use.
var selectorFuncs = map[string]bool{
	"not(": true, "is(": true, "where(": true,
	"nth-child(": true, "nth-last-child(": true, "nth-of-type(": true, "nth-last-of-type(": true,
}

func selectorToken(t *scanner.Token) bool {
	switch t.Type {
	case scanner.TokenIdent, scanner.TokenHash, scanner.TokenNumber, scanner.TokenPercentage,
		scanner.TokenDimension, scanner.TokenString, scanner.TokenS, scanner.TokenIncludes,
		scanner.TokenDashMatch, scanner.TokenPrefixMatch, scanner.TokenSuffixMatch, scanner.TokenSubstringMatch:
		return true
	case scanner.TokenFunction:
		return selectorFuncs[strings.ToLower(t.Value)]
	case scanner.TokenChar:
		return isChar(t, ".>+~*:[]=()|")
	}
	return false
}

// scopeSelector puts the selector s (one rule's, with its commas) under
// #godwit-body, for scheme if one. The mail's html and body are the page:
// #godwit-body itself. Selectors that are not safe, or cannot match here
// (body.dark: the body's class is not carried over), are left out.
func scopeSelector(s, scheme string) []string {
	ts, ok := tokens(s)
	if !ok {
		return nil
	}
	root := cssRoot
	if scheme != "" {
		root += ".godwit-" + scheme
	}
	var out []string
next:
	for _, g := range splitAt(ts, ",") {
		g = trimS(g)
		for _, t := range g {
			if !selectorToken(t) {
				continue next
			}
		}
		for len(g) > 0 && (isIdent(g[0], "html") || isIdent(g[0], "body")) {
			g = g[1:]
			if len(g) > 0 && g[0].Type != scanner.TokenS && !isChar(g[0], ">+~") {
				continue next // html.x, body:hover…
			}
			g = trimS(g)
		}
		if len(g) == 0 {
			out = append(out, root)
			continue
		}
		out = append(out, root+" "+join(g))
	}
	return out
}

// mediaQuery is the media query list of an @media prelude, with each
// (prefers-color-scheme: dark|light) feature made an always true one, and the
// scheme they ask for; false when it has anything else than plain features, or
// the schemes differ among its queries (some only for dark, some for all).
func mediaQuery(prelude string) (query, scheme string, ok bool) {
	ts, ok := tokens(prelude)
	if !ok {
		return "", "", false
	}
	var queries []string
	first := true
	for _, q := range splitAt(ts, ",") {
		q = trimS(q)
		var b strings.Builder
		qs := ""
		for i := 0; i < len(q); i++ {
			t := q[i]
			switch {
			case t.Type == scanner.TokenIdent, t.Type == scanner.TokenNumber, t.Type == scanner.TokenPercentage,
				t.Type == scanner.TokenDimension, t.Type == scanner.TokenS, isChar(t, "(),:/"):
			default:
				return "", "", false
			}
			if s, n := schemeFeature(q[i:]); n > 0 {
				qs = s
				i += n - 1
				b.WriteString("(min-width:0px)")
				continue
			}
			b.WriteString(t.Value)
		}
		if first {
			scheme, first = qs, false
		} else if qs != scheme {
			return "", "", false
		}
		queries = append(queries, b.String())
	}
	return strings.Join(queries, ","), scheme, true
}

// schemeFeature is the scheme ("dark" or "light") of the feature
// (prefers-color-scheme: dark|light) ts starts with, and the number of tokens
// it takes; 0 when ts does not start with one.
func schemeFeature(ts []*scanner.Token) (scheme string, n int) {
	var sig []*scanner.Token
	for _, t := range ts {
		n++
		if t.Type == scanner.TokenS {
			continue
		}
		if sig = append(sig, t); len(sig) == 5 {
			break
		}
	}
	if len(sig) < 5 || !isChar(sig[0], "(") || !isIdent(sig[1], "prefers-color-scheme") ||
		!isChar(sig[2], ":") || sig[3].Type != scanner.TokenIdent || !isChar(sig[4], ")") {
		return "", 0
	}
	if v := strings.ToLower(sig[3].Value); v == "dark" || v == "light" {
		return v, n
	}
	return "", 0
}

// valueFuncs are the functions a value may use.
var valueFuncs = map[string]bool{
	"rgb(": true, "rgba(": true, "hsl(": true, "hsla(": true, "calc(": true,
	"linear-gradient(": true, "radial-gradient(": true, "repeating-linear-gradient(": true, "repeating-radial-gradient(": true,
}

// safeValue reports whether v is made of plain tokens only.
func safeValue(v string) bool {
	ts, ok := tokens(v)
	if !ok || len(trimS(ts)) == 0 {
		return false
	}
	for _, t := range ts {
		switch t.Type {
		case scanner.TokenIdent, scanner.TokenNumber, scanner.TokenPercentage, scanner.TokenDimension,
			scanner.TokenHash, scanner.TokenString, scanner.TokenS:
		case scanner.TokenFunction:
			if !valueFuncs[strings.ToLower(t.Value)] {
				return false
			}
		case scanner.TokenChar:
			if !isChar(t, ",/+-.*%)(") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func declarations(ds []cssDecl) string {
	var b strings.Builder
	for _, d := range ds {
		if !cssAllowed[d.prop] || !safeValue(d.value) {
			continue
		}
		b.WriteString(d.prop + ":" + d.value)
		if d.important {
			b.WriteString(" !important")
		}
		b.WriteString(";")
	}
	return b.String()
}

// splitBackground takes the first http(s) url() out of the background or
// background-image declaration of a style attribute: addr is it ("" for none),
// rest the style without it. A background shorthand keeps its other values
// (position, size, repeat, colour), which an image shown at its natural size
// would be nothing without. Read as tokens: douceur drops the value of a
// declaration that has a url(), and a url() can hold a ;.
func splitBackground(style string) (rest, addr string) {
	ts, ok := tokens(style)
	if !ok {
		return style, ""
	}
	var out []string
	for _, d := range splitAt(ts, ";") {
		if d = trimS(d); len(d) == 0 {
			continue
		}
		colon := slices.IndexFunc(d, func(t *scanner.Token) bool { return isChar(t, ":") })
		if colon < 0 {
			continue
		}
		prop := strings.ToLower(strings.TrimSpace(join(d[:colon])))
		if addr != "" || (prop != "background" && prop != "background-image") {
			out = append(out, join(d)+";")
			continue
		}
		// Of the layers (a gif and its poster, say) the first with an address is the one shown; the
		// others go, with their url(), which the policy would drop the whole shorthand for.
		var keep []*scanner.Token
		for _, layer := range splitAt(d[colon+1:], ",") {
			var rest []*scanner.Token
			for _, t := range layer {
				if t.Type == scanner.TokenURI && addr == "" {
					if u := remoteAddr(t.Value); u != "" {
						addr = u
						continue
					}
				}
				rest = append(rest, t)
			}
			if addr != "" {
				keep = rest
				break
			}
		}
		switch {
		case addr == "":
			out = append(out, join(d)+";")
		case prop == "background":
			if r := strings.Join(strings.Fields(join(keep)), " "); r != "" {
				out = append(out, "background: "+r+";")
			}
		}
	}
	return strings.Join(out, " "), addr
}

// remoteAddr is the http(s) address of a url(…) token, "" for any other.
func remoteAddr(uri string) string {
	u := strings.Trim(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(uri, "url("), ")")), `'"`)
	if strings.HasPrefix(u, "//") {
		u = "https:" + u
	}
	if safeRemoteImage(u) {
		return u
	}
	return ""
}

type simpleSel struct {
	tag     string
	ids     []string
	classes []string
	child   bool
}

type inlineRule struct {
	chain                       []simpleSel
	ids, classes, tags, order int
	decls                       []cssDecl
}

// InlineQuoteCSS flattens safe, non-conditional <style> rules onto matching
// elements' inline style attributes so quoted HTML keeps its formatting after
// <style> tags are stripped by draft sanitization.
func InlineQuoteCSS(src string) string {
	if !strings.Contains(strings.ToLower(src), "<style") {
		return src
	}
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return src
	}
	var body *html.Node
	var styleNodes []*html.Node
	var sheets []string
	walkNodes(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.DataAtom {
		case atom.Body:
			body = n
		case atom.Style:
			styleNodes = append(styleNodes, n)
			media, _ := attr(n, "media")
			m := strings.ToLower(strings.TrimSpace(media))
			if m == "" || m == "all" || m == "screen" {
				sheets = append(sheets, nodeText(n))
			}
		}
	})
	if body == nil {
		return src
	}
	for _, n := range styleNodes {
		if n.Parent != nil {
			n.Parent.RemoveChild(n)
		}
	}
	var rules []inlineRule
	ruleCount := 0
	for _, text := range sheets {
		if len(text) > maxCSSBytes {
			text = text[:maxCSSBytes]
		}
		for _, r := range parseSheet(text) {
			if ruleCount >= maxCSSRules {
				break
			}
			if r.at != "" {
				continue
			}
			var decls []cssDecl
			for _, d := range r.decls {
				prop := strings.ToLower(d.prop)
				if cssAllowed[prop] && safeValue(d.value) {
					decls = append(decls, cssDecl{prop: prop, value: d.value, important: d.important})
				}
			}
			if len(decls) == 0 {
				continue
			}
			ruleCount++
			ts, ok := tokens(r.prelude)
			if !ok {
				continue
			}
			for _, g := range splitAt(ts, ",") {
				chain, ids, classes, tags, ok := parseSimpleSelector(trimS(g))
				if !ok {
					continue
				}
				rules = append(rules, inlineRule{
					chain:   chain,
					ids:     ids,
					classes: classes,
					tags:    tags,
					order:   len(rules),
					decls:   decls,
				})
			}
		}
	}
	if len(rules) == 0 {
		return render(body)
	}
	walkNodes(body, func(n *html.Node) {
		if n.Type != html.ElementNode || n.DataAtom == atom.Script || n.DataAtom == atom.Style {
			return
		}
		var matched []inlineRule
		for _, r := range rules {
			if matchChain(n, r.chain) {
				matched = append(matched, r)
			}
		}
		if len(matched) == 0 {
			return
		}
		slices.SortStableFunc(matched, func(a, b inlineRule) int {
			return cmp.Or(
				cmp.Compare(a.ids, b.ids),
				cmp.Compare(a.classes, b.classes),
				cmp.Compare(a.tags, b.tags),
				cmp.Compare(a.order, b.order),
			)
		})
		type mergedDecl struct {
			prop      string
			value     string
			important bool
			dead      bool
		}
		var merged []mergedDecl
		idx := make(map[string]int)
		for _, r := range matched {
			for _, d := range r.decls {
				if i, ok := idx[d.prop]; ok {
					if merged[i].important && !d.important {
						continue
					}
					merged[i].dead = true
				}
				idx[d.prop] = len(merged)
				merged = append(merged, mergedDecl{prop: d.prop, value: d.value, important: d.important})
			}
		}
		var parts []string
		for _, m := range merged {
			if m.dead {
				continue
			}
			s := m.prop + ": " + m.value
			if m.important {
				s += " !important"
			}
			parts = append(parts, s)
		}
		if len(parts) == 0 {
			return
		}
		prefix := strings.Join(parts, "; ")
		existing, _ := attr(n, "style")
		if clean := strings.TrimSpace(cleanStyle(existing)); clean != "" {
			setAttr(n, "style", prefix+"; "+clean)
		} else {
			setAttr(n, "style", prefix)
		}
	})
	return render(body)
}

func parseSimpleSelector(ts []*scanner.Token) (chain []simpleSel, ids, classes, tags int, ok bool) {
	if len(ts) == 0 {
		return nil, 0, 0, 0, false
	}
	var cur simpleSel
	hasCur := false
	pendingChild := false
	flush := func() {
		if !hasCur {
			return
		}
		ids += len(cur.ids)
		classes += len(cur.classes)
		if cur.tag != "" {
			tags++
		}
		chain = append(chain, cur)
		cur = simpleSel{}
		hasCur = false
	}
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		switch {
		case t.Type == scanner.TokenS:
			flush()
		case isChar(t, ">"):
			flush()
			if len(chain) == 0 || pendingChild {
				return nil, 0, 0, 0, false
			}
			pendingChild = true
		case t.Type == scanner.TokenIdent:
			if hasCur {
				return nil, 0, 0, 0, false
			}
			cur = simpleSel{tag: strings.ToLower(t.Value), child: pendingChild}
			pendingChild = false
			hasCur = true
		case t.Type == scanner.TokenHash:
			id := strings.TrimPrefix(t.Value, "#")
			if id == "" {
				return nil, 0, 0, 0, false
			}
			if !hasCur {
				cur = simpleSel{child: pendingChild}
				pendingChild = false
				hasCur = true
			}
			cur.ids = append(cur.ids, id)
		case isChar(t, "."):
			if i+1 >= len(ts) || ts[i+1].Type != scanner.TokenIdent {
				return nil, 0, 0, 0, false
			}
			if !hasCur {
				cur = simpleSel{child: pendingChild}
				pendingChild = false
				hasCur = true
			}
			cur.classes = append(cur.classes, ts[i+1].Value)
			i++
		default:
			return nil, 0, 0, 0, false
		}
	}
	if pendingChild {
		return nil, 0, 0, 0, false
	}
	flush()
	if len(chain) == 0 {
		return nil, 0, 0, 0, false
	}
	return chain, ids, classes, tags, true
}

func matchChain(n *html.Node, chain []simpleSel) bool {
	if len(chain) == 0 {
		return false
	}
	return matchAt(n, chain, len(chain)-1)
}

func matchAt(n *html.Node, chain []simpleSel, idx int) bool {
	if !matchSimple(n, chain[idx]) {
		return false
	}
	if idx == 0 {
		return true
	}
	if chain[idx].child {
		p := n.Parent
		return p != nil && p.Type == html.ElementNode && matchAt(p, chain, idx-1)
	}
	for p := n.Parent; p != nil && p.Type == html.ElementNode; p = p.Parent {
		if matchAt(p, chain, idx-1) {
			return true
		}
	}
	return false
}

func matchSimple(n *html.Node, s simpleSel) bool {
	if n == nil || n.Type != html.ElementNode {
		return false
	}
	if s.tag != "" && !strings.EqualFold(n.Data, s.tag) {
		return false
	}
	if len(s.ids) > 0 {
		id, _ := attr(n, "id")
		for _, want := range s.ids {
			if id != want {
				return false
			}
		}
	}
	if len(s.classes) > 0 {
		cls, _ := attr(n, "class")
		fields := strings.Fields(cls)
		for _, want := range s.classes {
			if !slices.Contains(fields, want) {
				return false
			}
		}
	}
	return true
}
