package bootstrap_test

import (
	"path/filepath"
	"testing"

	"github.com/gatework/wireless/internal/bootstrap"
)

// The shipped example must always load.
func TestLoad_example(t *testing.T) {
	t.Parallel()
	if _, err := bootstrap.Load(t.Context(), bootstrap.Options{ConfigPath: filepath.Join("..", "..", "examples", "wireless.yml"), Home: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
}
