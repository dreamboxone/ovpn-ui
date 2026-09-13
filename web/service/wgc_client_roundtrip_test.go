package service

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// wg-c and awg store server-minted secrets INSIDE the client object: the account's
// legacy keypair and, at User Limit K > 1, one keypair per device slot. The panel
// posts the whole client back on every save and the backend splices it in verbatim
// (AddInboundClient/UpdateInboundClient work on the raw settings JSON, not on
// model.Client), so any field the browser's model forgets to serialise is DELETED
// from the stored account.
//
// That is what happened to `devices`. The JS model had no such field, so every save
// posted the account back without it; ReconcileKeys rebuilt device 0 from the legacy
// privKey mirror and MINTED FRESH KEYS for devices 2..K, silently invalidating every
// config already downloaded for them. Invisible at the default User Limit of 1,
// which is why it survived.
//
// This test compares the Go struct's json tags against the keys the browser actually
// writes, so a field added on one side can never again be silently dropped by the
// other.

func TestWireguardClientModelsRoundTripEveryStoredField(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "assets", "js", "model", "inbound.js"))
	if err != nil {
		t.Fatalf("read inbound.js: %v", err)
	}
	js := string(src)

	cases := []struct {
		name     string
		goStruct any
		jsClass  string
	}{
		{"wg-c", wgcClient{}, "Inbound.WgcSettings.WgUser = class extends XrayCommonClass {"},
		{"awg", awgClient{}, "Inbound.AwgSettings.AwgUser = class extends XrayCommonClass {"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			written := jsToJsonKeys(t, js, tc.jsClass)
			for _, tag := range jsonTagsOf(tc.goStruct) {
				if !written[tag] {
					t.Errorf("the backend stores clients[].%s but the browser's model never writes it, so every save deletes it", tag)
				}
			}
		})
	}
}

// A field the browser writes but never reads back is just as lossy: the value is
// replaced by whatever the constructor defaults to. Checked separately so the
// failure message can say which half is missing.
func TestWireguardClientModelsReadBackWhatTheyWrite(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "assets", "js", "model", "inbound.js"))
	if err != nil {
		t.Fatalf("read inbound.js: %v", err)
	}
	js := string(src)

	for _, tc := range []struct{ name, jsClass string }{
		{"wg-c", "Inbound.WgcSettings.WgUser = class extends XrayCommonClass {"},
		{"awg", "Inbound.AwgSettings.AwgUser = class extends XrayCommonClass {"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := jsBlockAfter(t, js, tc.jsClass)
			written := jsToJsonKeys(t, js, tc.jsClass)
			// fromJson reads `j.<field>`; collect what it consumes.
			read := map[string]bool{}
			for _, m := range regexp.MustCompile(`\bj\.(\w+)`).FindAllStringSubmatch(body, -1) {
				read[m[1]] = true
			}
			for key := range written {
				switch key {
				case "id":
					continue // written as a mirror of email, deliberately not read back
				}
				if !read[key] {
					t.Errorf("toJson writes %q but fromJson never reads it, so the stored value is lost on the next edit", key)
				}
			}
		})
	}
}

// jsonTagsOf returns the json field names of a struct, skipping "-" and options.
func jsonTagsOf(v any) []string {
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if comma := strings.IndexByte(tag, ','); comma >= 0 {
			tag = tag[:comma]
		}
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// jsToJsonKeys returns the keys of the object literal a class's toJson() returns.
func jsToJsonKeys(t *testing.T, js, classMarker string) map[string]bool {
	t.Helper()
	body := jsBlockAfter(t, js, classMarker)
	idx := strings.Index(body, "toJson() {")
	if idx < 0 {
		t.Fatalf("no toJson() in %s", classMarker)
	}
	obj := jsBlockAfter(t, body[idx:], "return {")
	keys := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\w+):`).FindAllStringSubmatch(obj, -1) {
		keys[m[1]] = true
	}
	if len(keys) == 0 {
		t.Fatalf("parsed no keys out of toJson() in %s", classMarker)
	}
	return keys
}
