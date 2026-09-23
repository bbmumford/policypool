package policypool

import "strings"

// disablesForeignKeys reports whether query holds a statement that would leave
// foreign-key enforcement anything other than on.
//
// WHAT IT CONSUMES: the SQL text a caller hands a policy connection. WHAT
// CONSUMES IT: policyConn's ExecContext, QueryContext, PrepareContext and
// Prepare, which refuse the whole text before any of it reaches the driver.
//
// CONDITIONS. Every statement in the text is read, because a driver that takes
// a multi-statement string runs each one. A statement is an assignment when,
// after an optional EXPLAIN or EXPLAIN QUERY PLAN, it is
// PRAGMA [schema.]foreign_keys followed by "= value" or "(value)"; the bare
// PRAGMA foreign_keys is a read and passes. Tokens are read as the engine reads
// them: comments and the engine's five whitespace bytes separate tokens, quoted
// names and strings are unquoted, and keywords and the pragma name compare with
// ASCII case folding only.
//
// WHY AN ALLOWLIST OF ON. The engine reads every value it does not recognise as
// true as off, and a number by its low byte, so -1, 256, an empty string, full
// and banana all switch enforcement off (TestEngineObeysEveryOffSpelling pins
// each against modernc SQLite). A list of off spellings would pass every one of
// them, so an assignment passes only when its value is a single token spelling
// on, yes, true or 1, and any other shape is refused.
//
// WHY THE PREPARE ENTRIES ARE GUARDED TOO. The engine applies the assignment
// when the statement compiles, so preparing it, or compiling it under EXPLAIN,
// switches enforcement off without the statement ever running
// (TestEngineAppliesTheAssignmentWhenItCompiles).
func disablesForeignKeys(query string) bool {
	// A statement can only assign foreign_keys if both words appear verbatim:
	// quoting adds bytes around a name and never removes any from it. Every
	// query a pool serves passes through here, so the common case stays a scan.
	if !containsFoldASCII(query, "pragma") || !containsFoldASCII(query, "foreign_keys") {
		return false
	}
	var statement []sqlToken
	for rest := query; ; {
		token, next, ok := nextSQLToken(rest)
		if !ok || (token.kind == tokenPunct && token.text == ";") {
			if assignsForeignKeysOff(statement) {
				return true
			}
			if !ok {
				return false
			}
			statement = statement[:0]
		} else {
			statement = append(statement, token)
		}
		rest = next
	}
}

// assignsForeignKeysOff reads one statement's tokens, without the terminating
// semicolon, and reports whether it assigns foreign_keys a value that is not
// on. A statement that is not a foreign_keys pragma reports false.
func assignsForeignKeysOff(statement []sqlToken) bool {
	i := 0
	if i < len(statement) && statement[i].isKeyword("EXPLAIN") {
		i++
		if i+1 < len(statement) && statement[i].isKeyword("QUERY") && statement[i+1].isKeyword("PLAN") {
			i += 2
		}
	}
	if i >= len(statement) || !statement[i].isKeyword("PRAGMA") {
		return false
	}
	i++
	if i >= len(statement) || !statement[i].isName() {
		return false
	}
	name := statement[i]
	i++
	if i < len(statement) && statement[i].isPunct(".") {
		i++
		if i >= len(statement) || !statement[i].isName() {
			return false
		}
		name = statement[i]
		i++
	}
	if !equalFoldASCII(name.text, "foreign_keys") {
		return false
	}
	value := statement[i:]
	switch {
	case len(value) == 0:
		return false
	case len(value) == 2 && value[0].isPunct("="):
		return !value[1].spellsOn()
	case len(value) == 3 && value[0].isPunct("(") && value[2].isPunct(")"):
		return !value[1].spellsOn()
	default:
		return true
	}
}

type tokenKind uint8

const (
	tokenWord tokenKind = iota + 1
	tokenQuoted
	// tokenUnterminated is a quote with no closing quote. The engine rejects
	// the statement, so it never names anything and never spells on.
	tokenUnterminated
	tokenPunct
)

type sqlToken struct {
	kind tokenKind
	text string
}

func (t sqlToken) isKeyword(keyword string) bool {
	return t.kind == tokenWord && equalFoldASCII(t.text, keyword)
}

func (t sqlToken) isName() bool { return t.kind == tokenWord || t.kind == tokenQuoted }

func (t sqlToken) isPunct(text string) bool { return t.kind == tokenPunct && t.text == text }

func (t sqlToken) spellsOn() bool {
	if !t.isName() {
		return false
	}
	for _, on := range [...]string{"on", "yes", "true", "1"} {
		if equalFoldASCII(t.text, on) {
			return true
		}
	}
	return false
}

// nextSQLToken returns the first token of s and the text after it, skipping
// whitespace and comments. An unterminated block comment runs to the end of
// the text, as it does in the engine. ok is false when no token remains.
func nextSQLToken(s string) (token sqlToken, rest string, ok bool) {
	for {
		s = strings.TrimLeft(s, " \t\n\f\r")
		switch {
		case s == "":
			return sqlToken{}, "", false
		case strings.HasPrefix(s, "--"):
			end := strings.IndexByte(s, '\n')
			if end < 0 {
				return sqlToken{}, "", false
			}
			s = s[end+1:]
		case strings.HasPrefix(s, "/*"):
			end := strings.Index(s[2:], "*/")
			if end < 0 {
				return sqlToken{}, "", false
			}
			s = s[2+end+2:]
		default:
			return scanSQLToken(s)
		}
	}
}

func scanSQLToken(s string) (sqlToken, string, bool) {
	switch c := s[0]; {
	case c == '\'' || c == '"' || c == '`':
		return scanQuoted(s, c, true)
	case c == '[':
		return scanQuoted(s, ']', false)
	case isWordByte(c):
		end := 1
		for end < len(s) && isWordByte(s[end]) {
			end++
		}
		return sqlToken{kind: tokenWord, text: s[:end]}, s[end:], true
	default:
		return sqlToken{kind: tokenPunct, text: s[:1]}, s[1:], true
	}
}

// scanQuoted reads a quoted token opening at s[0] and closing at closer. When
// doubled is set, two closers in a row stand for one closer inside the token;
// a bracketed name has no such escape.
func scanQuoted(s string, closer byte, doubled bool) (sqlToken, string, bool) {
	for i := 1; i < len(s); i++ {
		if s[i] != closer {
			continue
		}
		if doubled && i+1 < len(s) && s[i+1] == closer {
			i++
			continue
		}
		text := s[1:i]
		if doubled {
			text = strings.ReplaceAll(text, string([]byte{closer, closer}), string(closer))
		}
		return sqlToken{kind: tokenQuoted, text: text}, s[i+1:], true
	}
	return sqlToken{kind: tokenUnterminated, text: s[1:]}, "", true
}

// isWordByte covers keywords, bare names and numbers. Bytes at or above 0x80
// continue a name, so a non-ASCII byte never splits one.
func isWordByte(c byte) bool {
	return c >= 0x80 || c == '_' || c == '$' ||
		('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// equalFoldASCII folds only A-Z. Unicode folding would read "yeſ" as "yes",
// a value the engine reads as off.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// containsFoldASCII reports whether s contains lower, which must already be
// lower case, under ASCII case folding.
func containsFoldASCII(s, lower string) bool {
	for i := 0; i+len(lower) <= len(s); i++ {
		if equalFoldASCII(s[i:i+len(lower)], lower) {
			return true
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
