//go:build linux

package nikoserver

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A group's bucket: lan_relay_mbps, a second's worth at most and at first;
// a frame passes when the bucket holds it, else it is dropped; each counted.
func TestYggRelayBucket(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	relay := newYggRelay(8) // 1 MB/s
	relay.now = func() time.Time { return now }
	g := relay.group("u5")
	for i, c := range []struct {
		after time.Duration
		size  int
		pass  bool
	}{
		{0, 600_000, true},
		{0, 500_000, false}, // 400 kB left
		{100 * time.Millisecond, 500_000, true},
		{0, 1, false},
		{10 * time.Second, 1_000_000, true}, // a second's worth, no more
		{0, 1, false},
		{time.Second, 1_000_001, false},
		{0, 131_070, true},
	} {
		now = now.Add(c.after)
		if got := g.pass(c.size); got != c.pass {
			t.Fatalf("%d: %d bytes pass %v", i, c.size, got)
		}
	}
	if relay.frames.Load() != 4 || relay.dropped.Load() != 4 || relay.bytes.Load() != 600_000+500_000+1_000_000+131_070 ||
		g.up.Load() != int64(relay.bytes.Load()) {
		t.Fatalf("frames %d dropped %d bytes %d, the group's %d", relay.frames.Load(), relay.dropped.Load(), relay.bytes.Load(), g.up.Load())
	}
	// Each group its own bucket.
	if !relay.group("u6").pass(1_000_000) {
		t.Fatal("another group's bucket is not full")
	}
	// 0: nothing.
	off := newYggRelay(0)
	if off.burst != 0 || off.group("u5").pass(1) || off.dropped.Load() != 1 || off.frames.Load() != 0 {
		t.Fatal("lan_relay_mbps 0 relays, or its bucket holds something")
	}

	// 1 Mbit/s: a second is 125000 bytes, less than the largest frame; the
	// bucket holds that frame all the same, and fills to it at the rate.
	slow := newYggRelay(1)
	slow.now = func() time.Time { return now }
	s := slow.group("u5")
	for i, c := range []struct {
		after time.Duration
		size  int
		pass  bool
	}{
		{0, yggFrameMax, true},
		{0, 1, false},
		{time.Second, yggFrameMax, false}, // 125000
		{50 * time.Millisecond, yggFrameMax, true},
		{10 * time.Second, yggFrameMax + 1, false}, // never more than the frame
		{0, yggFrameMax, true},
	} {
		now = now.Add(c.after)
		if got := s.pass(c.size); got != c.pass {
			t.Fatalf("1 Mbit/s, %d: %d bytes pass %v", i, c.size, got)
		}
	}
	if slow.frames.Load() != 3 || slow.bytes.Load() != 3*yggFrameMax {
		t.Fatalf("1 Mbit/s: %d frames, %d bytes", slow.frames.Load(), slow.bytes.Load())
	}
	// Through a link: K's largest frame to G goes into the core; the next,
	// with the bucket empty, does not.
	link := newYggRelay(1).group("u1")
	largest := iwTraffic(nil, nil, keyK, keyG, 0, nil)
	largest = append(largest, make([]byte, yggFrameMax-len(largest))...)
	f, core, _, _ := testFilter(func() yggGroups { return yggGroups{keyK: link, keyG: link} })
	if err := f.testUp(&chunks{b: slices.Concat(iwFrame(largest), iwFrame(largest)), n: 32 << 10}); err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(core.Bytes(), iwFrame(largest)) || link.up.Load() != yggFrameMax || link.relay.dropped.Load() != 1 {
		t.Fatalf("1 Mbit/s, the largest frame: the core got %d bytes, the group %d, dropped %d", core.Len(), link.up.Load(), link.relay.dropped.Load())
	}
}

// The traffic line's answer: each group's relayed bytes as up, down 0,
// boot random at each start, as Hysteria2's.
func TestYggRelayTraffic(t *testing.T) {
	relay := newYggRelay(20)
	relay.take(map[string]bool{"u5": true, "u6": true})
	relay.group("u5").pass(1000)
	relay.group("u5").pass(234)
	tr := relay.traffic()
	if tr.V != 1 || len(tr.Boot) != 16 || tr.Boot == newYggRelay(20).boot || len(tr.Users) != 2 ||
		tr.Users["u5"] != (UserTraffic{Up: 1234}) || tr.Users["u6"] != (UserTraffic{}) {
		t.Fatalf("traffic %+v", tr)
	}
	b, _ := json.Marshal(tr)
	if want := `{"v":1,"boot":"` + tr.Boot + `","users":{"u5":{"up":1234,"down":0},"u6":{"up":0,"down":0}}}`; string(b) != want {
		t.Fatalf("%s, want %s", b, want)
	}
}

// A group gone from the users file goes from the traffic line once it has
// relayed nothing for the stale time since it left, across the watch's
// looks; one in the file never; one back keeps its count; one dropped and
// back starts from 0.
func TestYggRelayPruned(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	relay := newYggRelay(20)
	relay.now = func() time.Time { return now }
	relay.stale = time.Minute
	look := func(d time.Duration) map[string]UserTraffic {
		now = now.Add(d)
		relay.check()
		return relay.traffic().Users
	}
	in := func(names ...string) map[string]bool {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m
	}
	groups := relay.take(in("u5", "u6", "u7"))
	groups["u5"].pass(100)
	groups["u7"].pass(70)
	relay.take(in("u6")) // u5 and u7 leave
	if got := look(30 * time.Second); len(got) != 3 {
		t.Fatalf("within the stale time: %v", got)
	}
	// u7 still relays a frame (a run of frames read before the reload): its
	// stale time runs from then.
	now = now.Add(10 * time.Second)
	groups["u7"].pass(1)
	if got := look(20 * time.Second); len(got) != 2 || got["u7"].Up != 71 {
		t.Fatalf("a minute after u5 left: %v", got)
	}
	// u7 back: its count stays.
	relay.take(in("u6", "u7"))
	if got := look(time.Hour); len(got) != 2 || got["u7"].Up != 71 {
		t.Fatalf("u7 back: %v", got)
	}
	// u6, in the file, idle all along, stays; u5, dropped and back, from 0.
	if got := relay.traffic().Users; got["u6"] != (UserTraffic{}) {
		t.Fatalf("u6: %v", got)
	}
	if g := relay.take(in("u5", "u6", "u7"))["u5"]; g == groups["u5"] || g.up.Load() != 0 {
		t.Fatal("u5 back after it was dropped: not from 0")
	}
	// u6, idle in the file for an hour, leaves: the stale time runs from
	// then, not from its last frame.
	relay.take(in("u5", "u7"))
	for _, d := range []time.Duration{time.Second, 30 * time.Second, 28 * time.Second} {
		if got := look(d); got["u6"] != (UserTraffic{}) || len(got) != 3 {
			t.Fatalf("u6, an hour idle, just gone: %v", got)
		}
	}
	if got := look(time.Second); len(got) != 2 {
		t.Fatalf("u6, a minute gone: %v", got)
	}
}

// The stats socket of the Yggdrasil backend: the line traffic gets the
// groups' bytes; any other line, the end of the input, or nothing at all
// gets the snapshot, as before v0.16.0.
func TestYggStatsTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	stop, err := serveStatsTraffic(path, func() any { return YggdrasilSnapshot{Started: 7, DroppedFrames: 3, RelayedFrames: 2} },
		func() any { return HysteriaTraffic{V: 1, Boot: "b", Users: map[string]UserTraffic{"u5": {Up: 5}}} }, NewLogger("error", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ask := func(send string, closeWrite bool) (string, time.Duration) {
		t.Helper()
		start := time.Now()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if send != "" {
			io.WriteString(c, send)
		}
		if closeWrite {
			c.(*net.UnixConn).CloseWrite()
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("%q: %v", send, err)
		}
		if rest, _ := io.ReadAll(c); len(rest) != 0 {
			t.Fatalf("%q: more than a line", send)
		}
		return strings.TrimSpace(line), time.Since(start)
	}
	snapshot := `{"started":7,"dropped_frames":3,"relayed_frames":2,"relayed_bytes":0,"relay_dropped_frames":0}`
	traffic := `{"v":1,"boot":"b","users":{"u5":{"up":5,"down":0}}}`
	for _, c := range []struct {
		send       string
		closeWrite bool
		want       string
	}{
		{"traffic\n", false, traffic},
		{" traffic \r\n", false, traffic},
		{"traffic", true, traffic},
		{"\n", false, snapshot},
		{"stats\n", false, snapshot},
		{"traffic please\n", false, snapshot},
		{strings.Repeat("x", 300), false, snapshot},
		{"", true, snapshot},
	} {
		if got, took := ask(c.send, c.closeWrite); got != c.want || took > statsLineWait {
			t.Errorf("%q: %s in %v, want %s", c.send, got, took, c.want)
		}
	}
	// Nothing said: the snapshot after the wait.
	if got, took := ask("", false); got != snapshot || took < statsLineWait || took > 2*time.Second {
		t.Errorf("nothing: %s in %v", got, took)
	}
}

// yggdrasil.lan in the users file: a group of 1-32 of a-z, 0-9 and -, or
// none; a bad one, or a key listed twice with two groups, refuses the
// whole file, as a bad key does.
func TestYggUsersLAN(t *testing.T) {
	dir := t.TempDir()
	k1, k2, k3 := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	read := func(users ...string) (map[[32]byte]string, error) {
		path := filepath.Join(dir, "users.json")
		if err := os.WriteFile(path, []byte(`{"users":[`+strings.Join(users, ",")+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return readYggUsers(path)
	}
	user := func(name, key, lan string) string {
		if lan == "-" {
			return fmt.Sprintf(`{"name":%q,"enabled":true,"yggdrasil":{"public_key":%q}}`, name, key)
		}
		return fmt.Sprintf(`{"name":%q,"enabled":true,"yggdrasil":{"public_key":%q,"lan":%s}}`, name, key, lan)
	}
	longest := strings.Repeat("a-9", 10) + "zz"
	keys, err := read(user("u5-d1", k1, `"u5"`), user("u5-d2", k2, `"u5"`), user("u6-d1", k3, `""`),
		user("u7-d1", strings.Repeat("d4", 32), "-"), user("u8-d1", strings.Repeat("e5", 32), `"`+longest+`"`),
		`{"name":"off","enabled":false,"yggdrasil":{"public_key":"`+strings.Repeat("f6", 32)+`","lan":"BAD"}}`,
		user("u5-d1-again", k1, `"u5"`))
	if err != nil {
		t.Fatal(err)
	}
	key := func(h string) [32]byte { b, _ := hex.DecodeString(h); return [32]byte(b) }
	if len(keys) != 5 || keys[key(k1)] != "u5" || keys[key(k2)] != "u5" || keys[key(k3)] != "" ||
		keys[key(strings.Repeat("d4", 32))] != "" || keys[key(strings.Repeat("e5", 32))] != longest {
		t.Fatalf("keys %v", keys)
	}
	for name, lan := range map[string]string{
		"upper case":      `"U5"`,
		"33 characters":   `"` + strings.Repeat("a", 33) + `"`,
		"an underscore":   `"u_5"`,
		"a space":         `"u 5"`,
		"a dot":           `"u5.x"`,
		"a newline after": `"u5\n"`,
		"not ASCII":       `"u5é"`,
		"a number":        `5`,
		"an object":       `{"name":"u5"}`,
	} {
		if _, err := read(user("u5-d1", k1, `"u5"`), user("x", k2, lan)); err == nil {
			t.Errorf("lan %s: the file is taken", name)
		}
	}
	if _, err := read(user("u5-d1", k1, `"u5"`), user("u6-d1", k1, `"u6"`)); err == nil {
		t.Error("one key in two groups: the file is taken")
	}
	if _, err := read(user("u5-d1", k1, `"u5"`), user("u5-d1-again", k1, "-")); err == nil {
		t.Error("one key in a group and in none: the file is taken")
	}
}

// A reload: the filter sees the new groups at once; a key whose group
// changes keeps its links, one gone loses them; the node's key is in no
// group whatever the file says.
func TestYggUsersGroups(t *testing.T) {
	u := &yggUsers{node: keyN, relay: newYggRelay(20)}
	if u.group() != nil {
		t.Fatal("groups before the first reading")
	}
	u.set(map[[32]byte]string{keyK: "u5", keyG: "u5", keyA: "u6", keyN: "u5"})
	rule := yggRule{node: keyN, key: keyK, groups: u.group}
	g := u.group()
	if g[keyK] == nil || g[keyK] != g[keyG] || g[keyA] == g[keyK] || g[keyN] != nil {
		t.Fatalf("groups %v", g)
	}
	// Nor does the node's key make a group of its own.
	other := &yggUsers{node: keyN, relay: newYggRelay(20)}
	if other.set(map[[32]byte]string{keyK: "u5", keyN: "u9"}); len(other.relay.traffic().Users) != 1 {
		t.Fatalf("the node's key made a group: %v", other.relay.traffic().Users)
	}
	n, gk, ka := keyN, keyG, keyA
	if !rule.passes(rule.view(), true, yggTraffic, &keyK, &gk) || rule.passes(rule.view(), true, yggTraffic, &n, &gk) {
		t.Fatal("K to G, or N forged within u5")
	}
	conns := map[[32]byte]*closeConn{keyK: {}, keyG: {}, keyA: {}}
	for k, c := range conns {
		if !u.admit(k, c) {
			t.Fatal("not admitted")
		}
	}
	// K moves to u6, G leaves.
	dropped, grouped := u.set(map[[32]byte]string{keyK: "u6", keyA: "u6"})
	if dropped != 1 || grouped != 2 || conns[keyK].closed || !conns[keyG].closed || conns[keyA].closed {
		t.Fatalf("dropped %d, grouped %d; closed K %v G %v A %v", dropped, grouped, conns[keyK].closed, conns[keyG].closed, conns[keyA].closed)
	}
	if rule.passes(rule.view(), true, yggTraffic, &keyK, &gk) || !rule.passes(rule.view(), true, yggTraffic, &keyK, &ka) {
		t.Fatal("the new groups are not seen")
	}
	// K out of any group: its link stays, it reaches N only.
	if dropped, _ := u.set(map[[32]byte]string{keyK: "", keyA: "u6"}); dropped != 0 || conns[keyK].closed {
		t.Fatal("K's link closed as it left its group")
	}
	if rule.passes(rule.view(), true, yggTraffic, &keyK, &ka) || !rule.passes(rule.view(), true, yggTraffic, &keyK, &n) {
		t.Fatal("K without a group")
	}
	if u.admit(keyG, &closeConn{}) {
		t.Fatal("a key gone admitted")
	}
}

// closeConn is a net.Conn that notes its Close.
type closeConn struct {
	net.Conn
	closed bool
}

func (c *closeConn) Close() error { c.closed = true; return nil }
