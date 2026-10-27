// Command audit-log-mirror is the public witness of netsign.io's audit log.
//
// Run from a GitHub Actions schedule in its own public repository (or by
// anyone, anywhere: it needs Go and OpenSSL), it copies every signed
// checkpoint of https://netsign.io/audit-log into series-<n>/ -- but only
// after checking it, with code that shares nothing with the server:
//
//  1. the checkpoint note is signed by the pinned key (key.pem), as a C2SP
//     signed note, signature type 0x02 (ECDSA P-256, SHA-256), under the
//     series' origin;
//  2. the new tree extends the last mirrored one: an RFC 9162 consistency
//     proof between their roots, verified here;
//  3. a checkpoint already mirrored is never served differently (same size,
//     other note = a fork);
//  4. each RFC 3161 token over a checkpoint verifies with `openssl ts
//     -verify` against the pinned TSA roots (tsa-roots.pem).
//
// The log is a sequence of SERIES; normally only series 1 exists. A series
// is closed only after the server lost entries it had already published,
// with a signed, timestamped closing statement, and the next one starts with
// a genesis entry committing to that statement. The witness checks all of
// it -- the statement against what it mirrored, the genesis entry's exact
// bytes and their inclusion proof -- and then STOPS: switching series is a
// person's decision, made by re-running with -accept-series <n> after reading
// the incident. Until then every run fails, which is the alarm.
//
// Anything that fails stops the run with nothing written for it, and the
// workflow fails. Git history then shows every checkpoint the server ever
// published, in order, each with its tokens.
//
// Exit codes: 0 ok (mirrored, or nothing new, or waiting for a token), 1
// verification failure or a series change awaiting acceptance, 2 usage or
// local error, 3 server unreachable (not proof of anything; the workflow
// reports it as a warning).
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	baseOrigin       = "netsign.io/audit-log"
	genesisEventType = "system.audit_log_series_started"
	sigTypeECDSA     = 0x02
	maxBody          = 1 << 20
)

// originOf is a series' origin: series 1 is the log's original name.
func originOf(n int64) string {
	if n == 1 {
		return baseOrigin
	}
	return baseOrigin + "/" + strconv.FormatInt(n, 10)
}

type config struct {
	Base string `json:"base"` // e.g. https://netsign.io
}

type failure struct{ error }     // exit 1: the log is not what it claims
type unreachable struct{ error } // exit 3

func main() {
	dir := flag.String("dir", ".", "the mirror repository")
	accept := flag.Int64("accept-series", 0, "accept the switch to this series, after reviewing its incident (0: accept none)")
	flag.Parse()
	msg, err := run(*dir, &http.Client{Timeout: 30 * time.Second}, *accept)
	var f failure
	var u unreachable
	switch {
	case err == nil:
		fmt.Println(msg)
	case errors.As(err, &f):
		fmt.Fprintln(os.Stderr, "VERIFICATION FAILED:", err)
		os.Exit(1)
	case errors.As(err, &u):
		fmt.Fprintln(os.Stderr, "unreachable:", err)
		os.Exit(3)
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// witness is one run's state.
type witness struct {
	dir string
	pub *ecdsa.PublicKey
	g   *getter
	log []string // what this run did, for the commit message
}

func (w *witness) note(format string, args ...any) {
	w.log = append(w.log, fmt.Sprintf(format, args...))
}

func (w *witness) seriesDir(n int64) string { return filepath.Join(w.dir, fmt.Sprintf("series-%d", n)) }

// run mirrors everything new and returns a one-line summary, also written to
// .commit-message for the workflow's commit.
func run(dir string, client *http.Client, accept int64) (string, error) {
	var cfg config
	if err := readJSON(filepath.Join(dir, "config.json"), &cfg); err != nil {
		return "", err
	}
	base, err := url.Parse(cfg.Base)
	if err != nil || base.Scheme != "https" && !(base.Scheme == "http" && isLocal(base.Hostname())) {
		return "", fmt.Errorf("config.json: base %q must be an https URL", cfg.Base)
	}
	pub, err := readKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		return "", err
	}
	if _, err = os.Stat(filepath.Join(dir, "tsa-roots.pem")); err != nil {
		return "", fmt.Errorf("tsa-roots.pem: %w", err)
	}
	if _, err = exec.LookPath("openssl"); err != nil {
		return "", errors.New("openssl is needed to verify the RFC 3161 tokens")
	}
	w := &witness{dir: dir, pub: pub, g: &getter{base: strings.TrimSuffix(cfg.Base, "/"), client: client}}

	n, err := w.activeSeries()
	if err != nil {
		return "", err
	}
	for {
		status, err := w.seriesStatus()
		if err != nil {
			return "", err
		}
		// A closed series no longer serves the checkpoints after its last
		// good one (they are what was lost): the comparison of mirrored
		// checkpoints with what is served stops there. Whether the closing
		// statement is to be believed is followClosing's question.
		recheckUpTo := int64(math.MaxInt64)
		if status[n] == "closed" {
			note, err := w.g.text(fmt.Sprintf("/audit-log/s/%d/closing", n))
			if err != nil {
				return "", err
			}
			c, err := parseClosing(note, originOf(n))
			if err != nil {
				return "", failure{err}
			}
			recheckUpTo = c.lastGood
		}
		if err = w.mirrorSeries(n, recheckUpTo); err != nil {
			return "", err
		}
		next, err := w.followClosing(n, accept, status)
		if err != nil {
			return "", err
		}
		if next == 0 {
			break
		}
		n = next
	}
	msg := "no new checkpoint"
	if len(w.log) > 0 {
		msg = strings.Join(w.log, "; ")
	}
	return msg, os.WriteFile(filepath.Join(dir, ".commit-message"), []byte(msg+"\n"), 0o644)
}

// activeSeries is the series this mirror follows: the ACTIVE file, 1 when it
// does not exist yet.
func (w *witness) activeSeries() (int64, error) {
	raw, err := os.ReadFile(filepath.Join(w.dir, "ACTIVE"))
	if errors.Is(err, os.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("ACTIVE: %q", raw)
	}
	return n, nil
}

func isLocal(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }

// mirrorSeries copies every checkpoint of series n the server lists after
// the last mirrored one, each checked against the one before, then the
// tokens, then a sample of older checkpoints against what is served now.
func (w *witness) mirrorSeries(n, recheckUpTo int64) error {
	sdir := w.seriesDir(n)
	if err := os.MkdirAll(sdir, 0o755); err != nil {
		return err
	}
	prefix := fmt.Sprintf("/audit-log/s/%d", n)
	last, lastRoot, err := w.lastMirrored(n)
	if err != nil {
		return err
	}
	var added []int64
	for {
		var list struct {
			Checkpoints []struct {
				TreeSize int64 `json:"treeSize"`
			} `json:"checkpoints"`
			More bool `json:"more"`
		}
		if err = w.g.json(fmt.Sprintf("%s/checkpoints?after=%d", prefix, last), &list); err != nil {
			return err
		}
		for _, c := range list.Checkpoints {
			if c.TreeSize <= last {
				return failure{fmt.Errorf("%s: server listed checkpoint %d after %d", originOf(n), c.TreeSize, last)}
			}
			root, err := w.mirrorOne(n, c.TreeSize, last, lastRoot)
			if err != nil {
				return err
			}
			last, lastRoot = c.TreeSize, root
			added = append(added, c.TreeSize)
		}
		if !list.More {
			break
		}
	}
	if err = w.recheck(n, added, recheckUpTo); err != nil {
		return err
	}
	stamped, err := w.fetchTimestamps(n, recheckUpTo)
	if err != nil {
		return err
	}
	switch {
	case len(added) > 0:
		w.note("%s checkpoints %d..%d (%d new), %d timestamp(s)", originOf(n), added[0], added[len(added)-1], len(added), stamped)
	case stamped > 0:
		w.note("%s: %d timestamp(s) for mirrored checkpoints", originOf(n), stamped)
	}
	return nil
}

// mirrorOne fetches, verifies and writes checkpoint size of series n.
func (w *witness) mirrorOne(n, size, last int64, lastRoot [32]byte) ([32]byte, error) {
	origin := originOf(n)
	note, err := w.g.text(fmt.Sprintf("/audit-log/s/%d/checkpoint/%d", n, size))
	if err != nil {
		return [32]byte{}, err
	}
	gotSize, root, err := verifyNote(note, origin, w.pub)
	if err != nil {
		return root, failure{fmt.Errorf("%s checkpoint %d: %w", origin, size, err)}
	}
	if gotSize != size {
		return root, failure{fmt.Errorf("%s checkpoint %d says size %d", origin, size, gotSize)}
	}
	if last > 0 {
		var cons struct {
			From  int64    `json:"from"`
			To    int64    `json:"to"`
			Proof []string `json:"proof"`
		}
		if err = w.g.json(fmt.Sprintf("/audit-log/s/%d/consistency?from=%d&to=%d", n, last, size), &cons); err != nil {
			return root, err
		}
		proof, err := decodeProof(cons.Proof)
		if err != nil {
			return root, failure{err}
		}
		if cons.From != last || cons.To != size || !verifyConsistency(last, size, lastRoot, root, proof) {
			return root, failure{fmt.Errorf("%s checkpoint %d does NOT extend mirrored checkpoint %d: the log was rewritten or forked", origin, size, last)}
		}
	}
	sdir := w.seriesDir(n)
	path := filepath.Join(sdir, fmt.Sprintf("%d.txt", size))
	if old, err := os.ReadFile(path); err == nil && string(old) != note {
		return root, failure{fmt.Errorf("%s checkpoint %d is served differently from the mirrored copy", origin, size)}
	}
	if err = os.WriteFile(path, []byte(note), 0o644); err != nil {
		return root, err
	}
	return root, os.WriteFile(filepath.Join(sdir, "LATEST"), []byte(strconv.FormatInt(size, 10)+"\n"), 0o644)
}

// lastMirrored reads series-<n>/LATEST and re-verifies that checkpoint, so a
// damaged mirror stops here rather than vouching for what follows it.
func (w *witness) lastMirrored(n int64) (int64, [32]byte, error) {
	sdir := w.seriesDir(n)
	raw, err := os.ReadFile(filepath.Join(sdir, "LATEST"))
	if errors.Is(err, os.ErrNotExist) {
		// First run of series 1: trust on first use. A later series never
		// gets here: accepting it wrote its first checkpoint, anchored by its
		// genesis entry (followClosing).
		return 0, [32]byte{}, nil
	}
	if err != nil {
		return 0, [32]byte{}, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || size < 1 {
		return 0, [32]byte{}, fmt.Errorf("%s/LATEST: %q", sdir, raw)
	}
	note, err := os.ReadFile(filepath.Join(sdir, fmt.Sprintf("%d.txt", size)))
	if err != nil {
		return 0, [32]byte{}, err
	}
	got, root, err := verifyNote(string(note), originOf(n), w.pub)
	if err != nil || got != size {
		return 0, [32]byte{}, fmt.Errorf("mirrored %s checkpoint %d no longer verifies: %v", originOf(n), size, err)
	}
	return size, root, nil
}

// seriesStatus is /audit-log/series: each series' status by number.
func (w *witness) seriesStatus() (map[int64]string, error) {
	var all struct {
		Series []struct {
			Series int64  `json:"series"`
			Origin string `json:"origin"`
			Status string `json:"status"`
		} `json:"series"`
	}
	if err := w.g.json("/audit-log/series", &all); err != nil {
		return nil, err
	}
	status := map[int64]string{}
	for _, s := range all.Series {
		if s.Origin != originOf(s.Series) {
			return nil, failure{fmt.Errorf("/audit-log/series: series %d is named %q", s.Series, s.Origin)}
		}
		status[s.Series] = s.Status
	}
	return status, nil
}

// followClosing looks at whether series n was closed. It returns the series
// to continue with, or 0 to stop: n is still active, or its successor is
// verified but not accepted (then an error), or a token is still missing.
func (w *witness) followClosing(n, accept int64, status map[int64]string) (int64, error) {
	switch status[n] {
	case "active":
		// One history for everyone who asks: the unprefixed newest checkpoint
		// is the newest of the series this mirror follows.
		if last, _, err := w.lastMirrored(n); err == nil && last > 0 {
			latest, err := w.g.text("/audit-log/checkpoint")
			if err != nil {
				return 0, err
			}
			have, _ := os.ReadFile(filepath.Join(w.seriesDir(n), fmt.Sprintf("%d.txt", last)))
			if latest != string(have) {
				return 0, failure{fmt.Errorf("/audit-log/checkpoint differs from mirrored %s checkpoint %d", originOf(n), last)}
			}
		}
		for s := range status {
			if s > n {
				return 0, failure{fmt.Errorf("the server has %s while %s, which this mirror follows, is still active", originOf(s), originOf(n))}
			}
		}
		return 0, nil
	case "closed":
	default:
		return 0, failure{fmt.Errorf("the server no longer lists %s, which this mirror follows", originOf(n))}
	}

	// Series n was closed. Everything below is checked before anything is
	// written, and nothing is written unless a person accepted the switch.
	m := n + 1
	origin, successor := originOf(n), originOf(m)
	sdir := w.seriesDir(n)
	closingNote, err := w.g.text(fmt.Sprintf("/audit-log/s/%d/closing", n))
	if err != nil {
		return 0, err
	}
	c, err := parseClosing(closingNote, origin)
	if err != nil {
		return 0, failure{err}
	}
	if _, err = verifySigned(closingNote, origin, w.pub); err != nil {
		return 0, failure{fmt.Errorf("%s closing statement: %w", origin, err)}
	}
	if c.successor != successor || c.successorKeyID != keyIDHex(successor, w.pub) {
		return 0, failure{fmt.Errorf("%s closing statement names %s (key %s), want %s signed by key.pem", origin, c.successor, c.successorKeyID, successor)}
	}
	last, lastRoot, err := w.lastMirrored(n)
	if err != nil {
		return 0, err
	}
	var gap string
	switch {
	case last > c.lastPublished:
		return 0, failure{fmt.Errorf("%s closing statement says checkpoint %d was the last published, but this mirror holds %d", origin, c.lastPublished, last)}
	case last == c.lastPublished && lastRoot != c.lastPublishedRoot:
		return 0, failure{fmt.Errorf("%s closing statement's last published root is not the mirrored checkpoint %d's: a fork", origin, last)}
	case last < c.lastPublished:
		gap = fmt.Sprintf(" (it names checkpoint %d, which this mirror never received)", c.lastPublished)
	}
	if c.lastGood > 0 {
		note, err := os.ReadFile(filepath.Join(sdir, fmt.Sprintf("%d.txt", c.lastGood)))
		if err != nil {
			return 0, failure{fmt.Errorf("%s closing statement's last good checkpoint %d is not mirrored", origin, c.lastGood)}
		}
		if _, root, err := verifyNote(string(note), origin, w.pub); err != nil || root != c.lastGoodRoot {
			return 0, failure{fmt.Errorf("%s closing statement's last good root is not the mirrored checkpoint %d's", origin, c.lastGood)}
		}
	}
	tokens, err := w.verifiedTokens(fmt.Sprintf("/audit-log/s/%d/closing/timestamps", n), closingNote)
	if err != nil {
		return 0, err
	}
	if len(tokens) == 0 {
		w.note("%s was closed; waiting for a time-stamp token over its closing statement", origin)
		return 0, nil
	}

	// The successor must start with the genesis entry for exactly this
	// statement, proven at leaf 0 of its first checkpoint.
	var gen struct {
		EntryHash  string   `json:"entryHash"`
		Entry      []byte   `json:"entry"`
		LeafIndex  int64    `json:"leafIndex"`
		TreeSize   int64    `json:"treeSize"`
		Proof      []string `json:"proof"`
		Checkpoint string   `json:"checkpoint"`
		Pending    bool     `json:"pending"`
	}
	if err = w.g.json(fmt.Sprintf("/audit-log/s/%d/genesis", m), &gen); err != nil {
		return 0, err
	}
	if gen.Pending {
		w.note("%s was closed; waiting for %s's first checkpoint", origin, successor)
		return 0, nil
	}
	sum := sha256.Sum256(gen.Entry)
	if hex.EncodeToString(sum[:]) != gen.EntryHash || gen.LeafIndex != 0 {
		return 0, failure{fmt.Errorf("%s genesis entry does not hash to its entry hash", successor)}
	}
	var entry struct {
		Type   string `json:"type"`
		Detail struct {
			PreviousOrigin    string `json:"previousOrigin"`
			ClosingSha256     string `json:"closingSha256"`
			LastGoodSize      int64  `json:"lastGoodSize"`
			LastGoodRoot      string `json:"lastGoodRoot"`
			LastPublishedSize int64  `json:"lastPublishedSize"`
			LastPublishedRoot string `json:"lastPublishedRoot"`
			Incident          string `json:"incident"`
			Reanchored        int64  `json:"reanchored"`
		} `json:"detail"`
	}
	if err = json.Unmarshal(gen.Entry, &entry); err != nil {
		return 0, failure{fmt.Errorf("%s genesis entry: %w", successor, err)}
	}
	closingSum := sha256.Sum256([]byte(closingNote))
	d := entry.Detail
	b64 := base64.StdEncoding.EncodeToString
	if entry.Type != genesisEventType || d.PreviousOrigin != origin || d.ClosingSha256 != hex.EncodeToString(closingSum[:]) ||
		d.LastGoodSize != c.lastGood || d.LastGoodRoot != b64(c.lastGoodRoot[:]) ||
		d.LastPublishedSize != c.lastPublished || d.LastPublishedRoot != b64(c.lastPublishedRoot[:]) || d.Incident != c.incident {
		return 0, failure{fmt.Errorf("%s genesis entry does not commit to %s's closing statement", successor, origin)}
	}
	size, root, err := verifyNote(gen.Checkpoint, successor, w.pub)
	if err != nil || size != gen.TreeSize {
		return 0, failure{fmt.Errorf("%s first checkpoint: %v", successor, err)}
	}
	proof, err := decodeProof(gen.Proof)
	if err != nil {
		return 0, failure{err}
	}
	entryRaw, _ := hex.DecodeString(gen.EntryHash)
	if !verifyInclusion(leafHash(entryRaw), 0, size, proof, root) {
		return 0, failure{fmt.Errorf("%s genesis entry is not leaf 0 of its first checkpoint", successor)}
	}

	summary := fmt.Sprintf("%s was CLOSED (incident %s): last good checkpoint %d, last published %d%s; %d entries re-anchored in %s",
		origin, c.incident, c.lastGood, c.lastPublished, gap, d.Reanchored, successor)
	if accept != m {
		return 0, failure{fmt.Errorf("series change requested: %s. The closing statement, its time-stamp and %s's genesis entry all verify. Read the incident, then run again with -accept-series %d", summary, successor, m)}
	}

	// Accepted: record how n ended and how m began, then follow m.
	if err = os.WriteFile(filepath.Join(sdir, "CLOSED.txt"), []byte(closingNote), 0o644); err != nil {
		return 0, err
	}
	for host, resp := range tokens {
		if err = os.WriteFile(filepath.Join(sdir, "CLOSED."+host+".tsr"), resp, 0o644); err != nil {
			return 0, err
		}
	}
	mdir := w.seriesDir(m)
	if err = os.MkdirAll(mdir, 0o755); err != nil {
		return 0, err
	}
	if err = os.WriteFile(filepath.Join(mdir, "GENESIS.json"), gen.Entry, 0o644); err != nil {
		return 0, err
	}
	if err = os.WriteFile(filepath.Join(mdir, fmt.Sprintf("%d.txt", size)), []byte(gen.Checkpoint), 0o644); err != nil {
		return 0, err
	}
	if err = os.WriteFile(filepath.Join(mdir, "LATEST"), []byte(strconv.FormatInt(size, 10)+"\n"), 0o644); err != nil {
		return 0, err
	}
	if err = os.WriteFile(filepath.Join(w.dir, "ACTIVE"), []byte(strconv.FormatInt(m, 10)+"\n"), 0o644); err != nil {
		return 0, err
	}
	w.note("%s, accepted", summary)
	return m, nil
}

// recheck compares a sample of older mirrored checkpoints of series n with
// what the server serves now: the newest few and a few spread over the
// history.
func (w *witness) recheck(n int64, skip []int64, upTo int64) error {
	sizes, err := mirroredSizes(w.seriesDir(n))
	if err != nil {
		return err
	}
	fresh := map[int64]bool{}
	for _, s := range skip {
		fresh[s] = true
	}
	pick := map[int64]bool{}
	for i := len(sizes) - 1; i >= 0 && i >= len(sizes)-3; i-- {
		pick[sizes[i]] = true
	}
	if k := len(sizes); k > 0 {
		day := time.Now().UTC().YearDay()
		for j := 0; j < 3; j++ {
			pick[sizes[(day*7+j*k/3)%k]] = true
		}
	}
	for size := range pick {
		if fresh[size] || size > upTo {
			continue
		}
		served, err := w.g.text(fmt.Sprintf("/audit-log/s/%d/checkpoint/%d", n, size))
		if err != nil {
			return err
		}
		have, _ := os.ReadFile(filepath.Join(w.seriesDir(n), fmt.Sprintf("%d.txt", size)))
		if served != string(have) {
			return failure{fmt.Errorf("%s checkpoint %d is served differently from the mirrored copy", originOf(n), size)}
		}
	}
	return nil
}

func mirroredSizes(dir string) ([]int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var sizes []int64
	for _, e := range entries {
		if s, ok := strings.CutSuffix(e.Name(), ".txt"); ok {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				sizes = append(sizes, n)
			}
		}
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	return sizes, nil
}

var hostFile = regexp.MustCompile(`[^a-z0-9.-]+`)

// verifiedTokens fetches a list of RFC 3161 responses over data and checks
// each with OpenSSL against the pinned roots. It returns them by TSA host.
func (w *witness) verifiedTokens(path, data string) (map[string][]byte, error) {
	var resp struct {
		Timestamps []struct {
			TSA      string `json:"tsa"`
			Response []byte `json:"response"`
		} `json:"timestamps"`
	}
	if err := w.g.json(path, &resp); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "witness")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	dataFile := filepath.Join(tmp, "data")
	if err = os.WriteFile(dataFile, []byte(data), 0o600); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, ts := range resp.Timestamps {
		u, err := url.Parse(ts.TSA)
		if err != nil || u.Hostname() == "" {
			return nil, failure{fmt.Errorf("%s: TSA %q", path, ts.TSA)}
		}
		f := filepath.Join(tmp, "token.tsr")
		if err = os.WriteFile(f, ts.Response, 0o600); err != nil {
			return nil, err
		}
		if res, err := exec.Command("openssl", "ts", "-verify", "-data", dataFile, "-in", f, "-CAfile", filepath.Join(w.dir, "tsa-roots.pem")).CombinedOutput(); err != nil {
			return nil, failure{fmt.Errorf("%s: token from %s does not verify:\n%s", path, ts.TSA, res)}
		}
		out[hostFile.ReplaceAllString(strings.ToLower(u.Hostname()), "_")] = ts.Response
	}
	return out, nil
}

// fetchTimestamps gets the RFC 3161 tokens of the newest mirrored checkpoints
// of series n (up to upTo: a closed series' last good one), verifies each with OpenSSL against the pinned roots, and
// stores it beside its note as <size>.<tsa host>.tsr.
func (w *witness) fetchTimestamps(n, upTo int64) (int, error) {
	sdir := w.seriesDir(n)
	sizes, err := mirroredSizes(sdir)
	if err != nil {
		return 0, err
	}
	stored := 0
	for i := len(sizes) - 1; i >= 0 && i >= len(sizes)-50; i-- {
		size := sizes[i]
		if size > upTo {
			continue // lost with the closed series' database: nothing to ask
		}
		// The newest few are always asked (a second TSA may answer later);
		// older ones only while they have no token at all.
		if have, _ := filepath.Glob(filepath.Join(sdir, fmt.Sprintf("%d.*.tsr", size))); len(have) > 0 && i < len(sizes)-5 {
			continue
		}
		note, err := os.ReadFile(filepath.Join(sdir, fmt.Sprintf("%d.txt", size)))
		if err != nil {
			return stored, err
		}
		tokens, err := w.verifiedTokens(fmt.Sprintf("/audit-log/s/%d/checkpoint/%d/timestamps", n, size), string(note))
		if err != nil {
			return stored, err
		}
		for host, resp := range tokens {
			name := filepath.Join(sdir, fmt.Sprintf("%d.%s.tsr", size, host))
			if _, err = os.Stat(name); err == nil {
				continue // this TSA's token is already mirrored
			}
			if err = os.WriteFile(name, resp, 0o644); err != nil {
				return stored, err
			}
			stored++
		}
	}
	return stored, nil
}

// ---------------------------------------------------------------- HTTP

type getter struct {
	base   string
	client *http.Client
}

func (g *getter) get(path string) ([]byte, error) {
	resp, err := g.client.Get(g.base + path)
	if err != nil {
		return nil, unreachable{err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, unreachable{err}
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("GET %s: over %d bytes", path, maxBody)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return body, nil
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, unreachable{fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)}
	default:
		// A 404 for a checkpoint the server listed, a 400 for a proof it
		// should give: the log is not answering for itself.
		return nil, failure{fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(body))}
	}
}

func (g *getter) text(path string) (string, error) {
	b, err := g.get(path)
	return string(b), err
}

func (g *getter) json(path string, v any) error {
	b, err := g.get(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, v); err != nil {
		return failure{fmt.Errorf("GET %s: %w", path, err)}
	}
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------- notes

func readKey(path string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: not a PEM public key", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: not an ECDSA P-256 key", path)
	}
	return pub, nil
}

// keyID is the signed-note key ID of pub under a key name (the origin).
func keyID(name string, pub *ecdsa.PublicKey) uint32 {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{sigTypeECDSA})
	h.Write(der)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

func keyIDHex(name string, pub *ecdsa.PublicKey) string { return fmt.Sprintf("%08x", keyID(name, pub)) }

// verifySigned checks a note's one signature line, by pub under origin, and
// returns its body with the final newline.
func verifySigned(note, origin string, pub *ecdsa.PublicKey) (string, error) {
	body, sigs, ok := strings.Cut(note, "\n\n")
	if !ok {
		return "", errors.New("no signature block")
	}
	body += "\n"
	prefix := "— " + origin + " "
	if !strings.HasPrefix(sigs, prefix) || !strings.HasSuffix(sigs, "\n") || strings.Count(sigs, "\n") != 1 {
		return "", errors.New("want exactly one signature, by " + origin)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(strings.TrimPrefix(sigs, prefix), "\n"))
	if err != nil || len(blob) < 5 {
		return "", errors.New("malformed signature")
	}
	if binary.BigEndian.Uint32(blob) != keyID(origin, pub) {
		return "", errors.New("signed by another key than key.pem")
	}
	digest := sha256.Sum256([]byte(body))
	if !ecdsa.VerifyASN1(pub, digest[:], blob[4:]) {
		return "", errors.New("signature does not verify")
	}
	return body, nil
}

// verifyNote checks a checkpoint of the series named origin: canonical size,
// 32-byte root, exactly one signature line by the pinned key.
func verifyNote(note, origin string, pub *ecdsa.PublicKey) (int64, [32]byte, error) {
	var root [32]byte
	body, err := verifySigned(note, origin, pub)
	if err != nil {
		return 0, root, err
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != 3 || lines[0] != origin {
		return 0, root, errors.New("not a checkpoint of " + origin)
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 1 || strconv.FormatInt(size, 10) != lines[1] {
		return 0, root, fmt.Errorf("size %q", lines[1])
	}
	r, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(r) != 32 {
		return 0, root, errors.New("root is not 32 bytes of base64")
	}
	copy(root[:], r)
	return size, root, nil
}

type closing struct {
	lastGood, lastPublished         int64
	lastGoodRoot, lastPublishedRoot [32]byte
	successor, successorKeyID       string
	incident                        string
}

// parseClosing reads a closing statement of origin: seven lines, each in its
// place (the server's anchor/series.go writes them).
func parseClosing(note, origin string) (closing, error) {
	var c closing
	body, _, _ := strings.Cut(note, "\n\n")
	l := strings.Split(body, "\n")
	if len(l) != 7 || l[0] != origin || l[1] != "closed" {
		return c, errors.New("not a closing statement of " + origin)
	}
	sizeRoot := func(line, key string) (int64, [32]byte, error) {
		var root [32]byte
		f := strings.Split(line, " ")
		if len(f) != 3 || f[0] != key {
			return 0, root, fmt.Errorf("closing statement: want %s", key)
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || n < 0 || strconv.FormatInt(n, 10) != f[1] {
			return 0, root, fmt.Errorf("closing statement: %s size", key)
		}
		r, err := base64.StdEncoding.Strict().DecodeString(f[2])
		if err != nil || len(r) != 32 {
			return 0, root, fmt.Errorf("closing statement: %s root", key)
		}
		copy(root[:], r)
		return n, root, nil
	}
	var err error
	if c.lastGood, c.lastGoodRoot, err = sizeRoot(l[2], "last-good"); err != nil {
		return c, err
	}
	if c.lastPublished, c.lastPublishedRoot, err = sizeRoot(l[3], "last-published"); err != nil {
		return c, err
	}
	var ok bool
	if c.successor, ok = strings.CutPrefix(l[4], "successor "); !ok {
		return c, errors.New("closing statement: successor")
	}
	if c.successorKeyID, ok = strings.CutPrefix(l[5], "successor-key "); !ok {
		return c, errors.New("closing statement: successor-key")
	}
	if c.incident, ok = strings.CutPrefix(l[6], "incident "); !ok || c.incident == "" {
		return c, errors.New("closing statement: incident")
	}
	if c.lastGood > c.lastPublished {
		return c, errors.New("closing statement: last good after last published")
	}
	return c, nil
}

// ---------------------------------------------------------------- RFC 9162

func leafHash(data []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, data...))
}

func node(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func decodeProof(enc []string) ([][32]byte, error) {
	out := make([][32]byte, len(enc))
	for i, s := range enc {
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("proof hash %d is not 32 bytes of base64", i)
		}
		copy(out[i][:], b)
	}
	return out, nil
}

// verifyInclusion is RFC 9162 section 2.1.3.2.
func verifyInclusion(leaf [32]byte, index, size int64, proof [][32]byte, root [32]byte) bool {
	if index < 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// verifyConsistency is RFC 9162 section 2.1.4.2, for 0 < m <= n.
func verifyConsistency(m, n int64, oldRoot, newRoot [32]byte, proof [][32]byte) bool {
	if m < 1 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && oldRoot == newRoot
	}
	if len(proof) == 0 {
		return false
	}
	if m&(m-1) == 0 {
		proof = append([][32]byte{oldRoot}, proof...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = node(c, fr)
			sr = node(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = node(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return fr == oldRoot && sr == newRoot && sn == 0
}
