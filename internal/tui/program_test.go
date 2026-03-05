package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestProgramTabSwitchesFocus(t *testing.T) {
	t.Parallel()

	model := NewProgramModel(buildTestEditor(), true)
	next, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated := next.(ProgramModel)
	if updated.Focus != FocusFields {
		t.Fatalf("expected focus to move to fields, got %v", updated.Focus)
	}
}

func TestProgramSubmitRequiresCtrlS(t *testing.T) {
	t.Parallel()

	model := NewProgramModel(buildTestEditor(), true)
	next, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	updated := next.(ProgramModel)
	if !updated.Result.Canceled {
		t.Fatalf("expected plain s to not submit")
	}

	next, _ = updated.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	submitted := next.(ProgramModel)
	if submitted.Result.Canceled {
		t.Fatalf("expected ctrl+s to submit")
	}
	if submitted.Result.Action != "install" {
		t.Fatalf("expected submitted action install, got %q", submitted.Result.Action)
	}
}

func TestProgramEnterOnTextFieldStartsEditing(t *testing.T) {
	t.Parallel()

	model := NewProgramModel(buildTestEditor(), true)
	model.Focus = FocusFields
	next, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated := next.(ProgramModel)
	if !updated.Editor.Editing {
		t.Fatalf("expected enter to start editing on text field")
	}
}

func TestProgramViewDoesNotAccumulateFocusSuffix(t *testing.T) {
	t.Parallel()

	model := NewProgramModel(buildTestEditor(), true)
	model.Focus = FocusMenu
	_ = model.View()
	second := model.View()
	if strings.Count(second, "（菜单焦点）") != 1 {
		t.Fatalf("expected focus suffix to appear exactly once, got:\n%s", second)
	}
}

func buildTestEditor() *EditorModel {
	return NewEditorModel(
		[]Action{{Key: "install", Label: "安装"}},
		ColorProfileANSI256,
		map[string]Form{
			"install": {
				Title: "安装配置",
				Fields: []Field{
					{Key: "name", Label: "容器名", Type: FieldTypeText, Value: "openclaw_demo"},
				},
			},
		},
	)
}
