package locale

import (
	"os"
	"testing"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

// buildBundle loads en_US + fa_IR straight off disk into a fresh bundle so the
// test doesn't depend on the web package's embedded FS.
func buildBundle(t *testing.T) *i18n.Bundle {
	t.Helper()
	b := i18n.NewBundle(language.MustParse("en-US"))
	b.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	for _, f := range []string{"translate.en_US.toml", "translate.fa_IR.toml"} {
		data, err := os.ReadFile("../translation/" + f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := b.ParseMessageFileBytes(data, "translation/"+f); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
	}
	return b
}

// TestEnglishFallback proves the keystone fix: a non-English (Farsi) context asked
// for an en_US-only key (pages.core.title, which fa_IR does not translate) returns
// the English text — not a blank string, and not the raw key.
func TestEnglishFallback(t *testing.T) {
	b := buildBundle(t)
	i18nBundle = b
	localizerDefault = i18n.NewLocalizer(b, "en-US")
	LocalizerWeb = i18n.NewLocalizer(b, "fa-IR") // active locale lacks the key

	want, err := localizerDefault.Localize(&i18n.LocalizeConfig{MessageID: "pages.core.title"})
	if err != nil || want == "" {
		t.Fatalf("en_US is missing pages.core.title (want non-empty): %v", err)
	}

	got := I18n(Web, "pages.core.title")
	if got == "" {
		t.Fatal("fallback failed: got a blank string for an en-only key")
	}
	if got == "pages.core.title" {
		t.Fatal("fallback failed: returned the raw key, not English text")
	}
	if got != want {
		t.Fatalf("fallback mismatch: got %q, want English %q", got, want)
	}
	t.Logf("fa-IR context, en-only key -> English fallback %q", got)
}
