package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// testdata/ was recorded from the real netsign.io server code (a fake KMS
// behind its KMS signer, an OpenSSL TSA) by internal/app's TestE2EMirror:
//
//   - replay.json: every response the witness asked for while mirroring
//     series 1;
//   - replay-series.json: the same server after its database was lost and an
//     old backup restored, series 1 closed and series 2 opened, while the
//     witness refused the switch, accepted it, and followed series 2.
//
// The replay server below answers from them, and each test bends one answer
// the way a dishonest server would.
type replay struct {
	Responses map[string]string `json:"responses"`
	Key       string            `json:"key"`
	TSARoots  string            `json:"tsaRoots"`
}

func load(t *testing.T, name string) replay {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var r replay
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// merged is the server after the switch: what it answers now, falling back
// to what it answered before for what did not change (series 1's old
// checkpoints).
func merged(t *testing.T) replay {
	before, after := load(t, "replay.json"), load(t, "replay-series.json")
	m := maps.Clone(before.Responses)
	maps.Copy(m, after.Responses)
	after.Responses = m
	return after
}

var checkpointPath = regexp.MustCompile(`^/audit-log/s/([0-9]+)/checkpoint/([0-9]+)$`)
var listPath = regexp.MustCompile(`^/audit-log/s/([0-9]+)/checkpoints\?after=([0-9]+)$`)

// serve answers from r, listing each series' checkpoints from the recorded
// ones, after edit has had its say on each response.
func serve(t *testing.T, r replay, edit func(path, body string) string) string {
	t.Helper()
	sizes := map[string][]int64{}
	for p := range r.Responses {
		if m := checkpointPath.FindStringSubmatch(p); m != nil {
			n, _ := strconv.ParseInt(m[2], 10, 64)
			sizes[m[1]] = append(sizes[m[1]], n)
		}
	}
	for k := range sizes {
		sort.Slice(sizes[k], func(i, j int) bool { return sizes[k][i] < sizes[k][j] })
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.RequestURI()
		body, ok := r.Responses[path]
		if m := listPath.FindStringSubmatch(path); m != nil {
			after, _ := strconv.ParseInt(m[2], 10, 64)
			var list []map[string]int64
			for _, s := range sizes[m[1]] {
				if s > after {
					list = append(list, map[string]int64{"treeSize": s})
				}
			}
			b, _ := json.Marshal(map[string]any{"checkpoints": list, "more": false})
			body, ok = string(b), true
		}
		if edit != nil {
			body = edit(path, body)
		}
		if !ok || body == "" {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func mirrorDir(t *testing.T, r replay, base string) string {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "key.pem"), []byte(r.Key), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "tsa-roots.pem"), []byte(r.TSARoots), 0o644))
	setBase(t, dir, base)
	return dir
}

func setBase(t *testing.T, dir, base string) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"base":"`+base+`"}`), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func isFailure(err error) bool {
	var f failure
	return errors.As(err, &f)
}

func series1Sizes(r replay) []string {
	var out []int64
	for p := range r.Responses {
		if m := checkpointPath.FindStringSubmatch(p); m != nil && m[1] == "1" {
			n, _ := strconv.ParseInt(m[2], 10, 64)
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	var s []string
	for _, n := range out {
		s = append(s, strconv.FormatInt(n, 10))
	}
	return s
}

func TestMirrorsAndVerifiesEverything(t *testing.T) {
	r := load(t, "replay.json")
	dir := mirrorDir(t, r, serve(t, r, nil))
	sizes := series1Sizes(r)
	msg, err := run(dir, http.DefaultClient, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("netsign.io/audit-log checkpoints %s..%s (%d new), %d timestamp(s)", sizes[0], sizes[len(sizes)-1], len(sizes), len(sizes))
	if msg != want {
		t.Fatalf("%q, want %q", msg, want)
	}
	for _, s := range sizes {
		for _, f := range []string{s + ".txt", s + ".127.0.0.1.tsr"} {
			if _, err := os.Stat(filepath.Join(dir, "series-1", f)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if msg, err = run(dir, http.DefaultClient, 0); err != nil || msg != "no new checkpoint" {
		t.Fatal(msg, err)
	}
}

func TestRefusesWhatADishonestServerWouldServe(t *testing.T) {
	r := load(t, "replay.json")
	sizes := series1Sizes(r)
	mid, last := sizes[len(sizes)-2], sizes[len(sizes)-1]
	flipProof := func(path, body string) string {
		if !strings.HasPrefix(path, "/audit-log/s/1/consistency?from="+mid) {
			return body
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(body), &p)
		proof := p["proof"].([]any)
		h := []byte(proof[0].(string))
		if h[0] == 'A' {
			h[0] = 'B'
		} else {
			h[0] = 'A'
		}
		proof[0] = string(h)
		b, _ := json.Marshal(p)
		return string(b)
	}
	cases := map[string]struct {
		edit func(path, body string) string
		want string
	}{
		"a consistency proof that does not hold": {flipProof, "does NOT extend"},
		"a checkpoint body changed after signing": {func(path, body string) string {
			if path == "/audit-log/s/1/checkpoint/"+mid {
				return strings.Replace(body, "\n"+mid+"\n", "\n"+mid+"0\n", 1)
			}
			return body
		}, "checkpoint " + mid},
		"a newest checkpoint other than the listed one": {func(path, body string) string {
			if path == "/audit-log/checkpoint" {
				return r.Responses["/audit-log/s/1/checkpoint/"+mid]
			}
			return body
		}, "differs from mirrored"},
		"a token over other data": {func(path, body string) string {
			if path == "/audit-log/s/1/checkpoint/"+mid+"/timestamps" {
				return r.Responses["/audit-log/s/1/checkpoint/"+last+"/timestamps"]
			}
			return body
		}, "does not verify"},
		"a listed checkpoint that is not there": {func(path, body string) string {
			if path == "/audit-log/s/1/checkpoint/"+mid {
				return ""
			}
			return body
		}, "HTTP 404"},
		"a series it does not admit to": {func(path, body string) string {
			if path == "/audit-log/series" {
				return strings.Replace(body, `]}`, `,{"series":2,"origin":"netsign.io/audit-log/2","status":"active"}]}`, 1)
			}
			return body
		}, "still active"},
	}
	for name, c := range cases {
		dir := mirrorDir(t, r, serve(t, r, c.edit))
		_, err := run(dir, http.DefaultClient, 0)
		if !isFailure(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Pinned to another key: nothing the server signed verifies.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	r2 := r
	r2.Key = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := run(mirrorDir(t, r2, serve(t, r, nil)), http.DefaultClient, 0); !isFailure(err) || !strings.Contains(err.Error(), "another key") {
		t.Errorf("another key: %v", err)
	}
}

// Once a checkpoint is mirrored, the server cannot later serve another note
// at that size, nor a history that does not extend it.
func TestHoldsTheServerToWhatWasMirrored(t *testing.T) {
	r := load(t, "replay.json")
	sizes := series1Sizes(r)
	last := sizes[len(sizes)-1]
	base := serve(t, r, nil)
	dir := mirrorDir(t, r, base)
	if _, err := run(dir, http.DefaultClient, 0); err != nil {
		t.Fatal(err)
	}
	// Any other note at a mirrored size -- even a valid re-signature, which
	// ECDSA makes differ byte for byte -- stops the run. (The fixture holds
	// no private key, so the stand-in here is a damaged signature.)
	resigned := func(path, body string) string {
		if path == "/audit-log/s/1/checkpoint/"+last || path == "/audit-log/checkpoint" {
			return strings.Replace(body, "— netsign.io/audit-log ", "— netsign.io/audit-log X", 1)
		}
		return body
	}
	setBase(t, dir, serve(t, r, resigned))
	if _, err := run(dir, http.DefaultClient, 0); !isFailure(err) {
		t.Fatalf("a different note for a mirrored size: %v", err)
	}
	// The local copy is checked too: an edited mirror stops the next run.
	note := filepath.Join(dir, "series-1", last+".txt")
	b, _ := os.ReadFile(note)
	must(t, os.WriteFile(note, []byte(strings.Replace(string(b), "\n"+last+"\n", "\n1"+last+"\n", 1)), 0o644))
	setBase(t, dir, base)
	if _, err := run(dir, http.DefaultClient, 0); err == nil || !strings.Contains(err.Error(), "no longer verifies") {
		t.Fatalf("an edited mirror: %v", err)
	}
}

// The handover, as the server performed it: refused until accepted (and
// only for the right series), then followed.
func TestSeriesHandoverNeedsAPerson(t *testing.T) {
	before := load(t, "replay.json")
	dir := mirrorDir(t, before, serve(t, before, nil))
	if _, err := run(dir, http.DefaultClient, 0); err != nil {
		t.Fatal(err)
	}
	after := merged(t)
	setBase(t, dir, serve(t, after, nil))
	for _, accept := range []int64{0, 3} {
		_, err := run(dir, http.DefaultClient, accept)
		if !isFailure(err) || !strings.Contains(err.Error(), "series change requested") || !strings.Contains(err.Error(), "-accept-series 2") {
			t.Fatalf("accept=%d: %v", accept, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "ACTIVE")); err == nil {
			t.Fatal("the switch was recorded without being accepted")
		}
	}
	msg, err := run(dir, http.DefaultClient, 2)
	if err != nil || !strings.Contains(msg, "CLOSED (incident 2026-11-03-db-restore)") || !strings.Contains(msg, "accepted") {
		t.Fatal(msg, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ACTIVE")); strings.TrimSpace(string(b)) != "2" {
		t.Fatalf("ACTIVE = %q", b)
	}
	for _, f := range []string{"series-1/CLOSED.txt", "series-1/CLOSED.127.0.0.1.tsr", "series-2/GENESIS.json", "series-2/LATEST"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	// What a reader of the repository checks by hand: the genesis entry's
	// bytes hash to leaf 0 of series 2, and name the closing statement.
	g, _ := os.ReadFile(filepath.Join(dir, "series-2", "GENESIS.json"))
	closingNote, _ := os.ReadFile(filepath.Join(dir, "series-1", "CLOSED.txt"))
	sum := sha256.Sum256(closingNote)
	if !strings.Contains(string(g), hex.EncodeToString(sum[:])) {
		t.Fatal("GENESIS.json does not name CLOSED.txt's SHA-256")
	}
	if msg, err = run(dir, http.DefaultClient, 0); err != nil || msg != "no new checkpoint" {
		t.Fatalf("after the switch: %q %v", msg, err)
	}
}

func TestSeriesHandoverRefusesForgeries(t *testing.T) {
	before := load(t, "replay.json")
	after := merged(t)
	genesis := after.Responses["/audit-log/s/2/genesis"]
	var gen map[string]any
	_ = json.Unmarshal([]byte(genesis), &gen)
	reencode := func(mutate func(g map[string]any)) string {
		g := maps.Clone(gen)
		mutate(g)
		b, _ := json.Marshal(g)
		return string(b)
	}
	editEntry := func(g map[string]any, from, to string, rehash bool) {
		raw, _ := json.Marshal(g["entry"])
		var b []byte
		_ = json.Unmarshal(raw, &b)
		b = []byte(strings.Replace(string(b), from, to, 1))
		g["entry"] = b
		if rehash {
			sum := sha256.Sum256(b)
			g["entryHash"] = hex.EncodeToString(sum[:])
		}
	}
	cases := map[string]struct {
		edit func(path, body string) string
		want string
	}{
		"genesis bytes edited": {func(path, body string) string {
			if path == "/audit-log/s/2/genesis" {
				return reencode(func(g map[string]any) { editEntry(g, "2026-11-03-db-restore", "2026-11-04-db-restore", false) })
			}
			return body
		}, "does not hash"},
		"genesis bytes edited and rehashed": {func(path, body string) string {
			if path == "/audit-log/s/2/genesis" {
				return reencode(func(g map[string]any) { editEntry(g, "2026-11-03-db-restore", "2026-11-04-db-restore", true) })
			}
			return body
		}, "does not commit"},
		"genesis proven at another position": {func(path, body string) string {
			if path == "/audit-log/s/2/genesis" {
				return reencode(func(g map[string]any) {
					editEntry(g, `"reanchored":`, `"reanchored":1`, true) // a different, unproven entry
					delete(g, "proof")
				})
			}
			return body
		}, "genesis"},
		"closing statement edited": {func(path, body string) string {
			if path == "/audit-log/s/1/closing" {
				return strings.Replace(body, "incident 2026-11-03", "incident 2026-11-04", 1)
			}
			return body
		}, "closing statement"},
		"closing token over something else": {func(path, body string) string {
			if path == "/audit-log/s/1/closing/timestamps" {
				return strings.Replace(after.Responses["/audit-log/s/2/checkpoint/7/timestamps"], `"series":2`, `"series":1`, 1)
			}
			return body
		}, "does not verify"},
	}
	for name, c := range cases {
		dir := mirrorDir(t, before, serve(t, before, nil))
		if _, err := run(dir, http.DefaultClient, 0); err != nil {
			t.Fatal(err)
		}
		setBase(t, dir, serve(t, after, c.edit))
		_, err := run(dir, http.DefaultClient, 2)
		if !isFailure(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "ACTIVE")); err == nil {
			t.Errorf("%s: the switch was recorded", name)
		}
	}
}

func TestConsistencyVerifierMatchesRFC9162OnRecordedProofs(t *testing.T) {
	r := load(t, "replay.json")
	pub, err := readKeyPEM([]byte(r.Key))
	if err != nil {
		t.Fatal(err)
	}
	root := func(size string) [32]byte {
		_, h, err := verifyNote(r.Responses["/audit-log/s/1/checkpoint/"+size], baseOrigin, pub)
		must(t, err)
		return h
	}
	sizes := series1Sizes(r)
	for i := 1; i < len(sizes); i++ {
		from, to := sizes[i-1], sizes[i]
		var p struct{ Proof []string }
		_ = json.Unmarshal([]byte(r.Responses["/audit-log/s/1/consistency?from="+from+"&to="+to]), &p)
		proof, err := decodeProof(p.Proof)
		must(t, err)
		m, _ := strconv.ParseInt(from, 10, 64)
		n, _ := strconv.ParseInt(to, 10, 64)
		if !verifyConsistency(m, n, root(from), root(to), proof) {
			t.Fatalf("%s->%s: recorded proof does not verify", from, to)
		}
		if verifyConsistency(m, n, root(to), root(to), proof) {
			t.Fatalf("%s->%s: verified against the wrong old root", from, to)
		}
	}
}

func readKeyPEM(b []byte) (*ecdsa.PublicKey, error) {
	f := filepath.Join(os.TempDir(), fmt.Sprintf("key-%d.pem", os.Getpid()))
	defer os.Remove(f)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		return nil, err
	}
	return readKey(f)
}
