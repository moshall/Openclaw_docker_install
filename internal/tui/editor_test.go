package tui

import "testing"

func TestEditorMoveActionResetsFieldCursor(t *testing.T) {
	t.Parallel()

	editor := NewEditorModel(
		[]Action{
			{Key: "install", Label: "安装"},
			{Key: "upgrade", Label: "升级"},
		},
		ColorProfileTrueColor,
		map[string]Form{
			"install": {
				Title: "安装配置",
				Fields: []Field{
					{Key: "name", Label: "容器名", Type: FieldTypeText, Value: "openclaw_demo"},
					{Key: "host_port", Label: "端口", Type: FieldTypeText, Value: "4113"},
				},
			},
			"upgrade": {
				Title: "升级配置",
				Fields: []Field{
					{Key: "name", Label: "容器名", Type: FieldTypeText, Value: "openclaw_demo"},
				},
			},
		},
	)
	editor.SelectedField = 1

	editor.MoveAction(1)

	if editor.Layout.SelectedAction != 1 {
		t.Fatalf("expected selected action to move to second item, got %d", editor.Layout.SelectedAction)
	}
	if editor.SelectedField != 0 {
		t.Fatalf("expected field cursor reset to 0, got %d", editor.SelectedField)
	}
}

func TestEditorApplyTextValue(t *testing.T) {
	t.Parallel()

	editor := NewEditorModel(
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

	editor.BeginEdit()
	editor.ApplyEditValue("openclaw_prod")

	field := editor.CurrentField()
	if field.Value != "openclaw_prod" {
		t.Fatalf("expected field value updated, got %q", field.Value)
	}
	if editor.Editing {
		t.Fatalf("expected editing mode to end after apply")
	}
}

func TestEditorCycleSelectAndToggle(t *testing.T) {
	t.Parallel()

	editor := NewEditorModel(
		[]Action{{Key: "install", Label: "安装"}},
		ColorProfileANSI16,
		map[string]Form{
			"install": {
				Title: "安装配置",
				Fields: []Field{
					{Key: "channel", Label: "通道", Type: FieldTypeSelect, Value: "stable", Options: []string{"stable", "nightly"}},
					{Key: "easy", Label: "EasyClaw", Type: FieldTypeToggle, Value: "1"},
				},
			},
		},
	)

	editor.CycleCurrentField(1)
	if got := editor.CurrentField().Value; got != "nightly" {
		t.Fatalf("expected select field switched to nightly, got %q", got)
	}

	editor.MoveField(1)
	editor.CycleCurrentField(1)
	if got := editor.CurrentField().Value; got != "2" {
		t.Fatalf("expected toggle field switched to 2, got %q", got)
	}
}

