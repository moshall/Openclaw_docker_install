package app_test

import (
	"reflect"
	"testing"

	"github.com/moshall/Openclaw_docker_install/internal/app"
)

func TestShouldFallbackToShell(t *testing.T) {
	t.Parallel()

	if !app.ShouldFallbackToShell(false, true) {
		t.Fatalf("expected non-tty stdin to fall back to shell")
	}
	if !app.ShouldFallbackToShell(true, false) {
		t.Fatalf("expected non-tty stdout to fall back to shell")
	}
	if app.ShouldFallbackToShell(true, true) {
		t.Fatalf("expected full tty session to allow TUI")
	}
}

func TestBuildShellCommand(t *testing.T) {
	t.Parallel()

	got := app.BuildShellCommand("/tmp/openclawctl.sh", "upgrade", true, "")
	want := []string{"/tmp/openclawctl.sh", "--wizard", "upgrade", "--dry-run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected command: got=%v want=%v", got, want)
	}
}

func TestBuildShellCommandWithConfigFile(t *testing.T) {
	t.Parallel()

	got := app.BuildShellCommand("/tmp/openclawctl.sh", "install", true, "/tmp/install.cfg")
	want := []string{"/tmp/openclawctl.sh", "--wizard", "install", "--config-file", "/tmp/install.cfg", "--dry-run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected command with config: got=%v want=%v", got, want)
	}
}

func TestActionOptionsExposeQuitEntry(t *testing.T) {
	t.Parallel()

	options := app.ActionOptions()
	if len(options) != 7 {
		t.Fatalf("expected 7 action options, got %d", len(options))
	}
	last := options[len(options)-1]
	if last.Key != "quit" {
		t.Fatalf("expected last option to be quit, got %q", last.Key)
	}
	if last.Label == "" || last.Description == "" {
		t.Fatalf("expected quit option to include label and description: %+v", last)
	}
}
