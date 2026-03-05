package tui

import "strings"

type FieldType string

const (
	FieldTypeText   FieldType = "text"
	FieldTypeSelect FieldType = "select"
	FieldTypeToggle FieldType = "toggle"
)

type Field struct {
	Key         string
	Label       string
	Type        FieldType
	Value       string
	Options     []string
	Description string
}

type Form struct {
	Title  string
	Fields []Field
}

type EditorModel struct {
	Layout        LayoutModel
	Forms         map[string]*Form
	SelectedField int
	Editing       bool
	EditBuffer    string
}

func NewEditorModel(actions []Action, profile ColorProfile, forms map[string]Form) *EditorModel {
	editor := &EditorModel{
		Layout: NewLayoutModel(actions, profile),
		Forms:  map[string]*Form{},
	}
	for key, form := range forms {
		formCopy := form
		editor.Forms[key] = &formCopy
	}
	editor.syncLayoutFromCurrentAction()
	return editor
}

func (m *EditorModel) MoveAction(delta int) {
	if len(m.Layout.Actions) == 0 {
		return
	}
	next := m.Layout.SelectedAction + delta
	for next < 0 {
		next += len(m.Layout.Actions)
	}
	m.Layout.SelectedAction = next % len(m.Layout.Actions)
	m.SelectedField = 0
	m.Editing = false
	m.EditBuffer = ""
	m.syncLayoutFromCurrentAction()
}

func (m *EditorModel) MoveField(delta int) {
	form := m.CurrentForm()
	if form == nil || len(form.Fields) == 0 {
		return
	}
	next := m.SelectedField + delta
	for next < 0 {
		next += len(form.Fields)
	}
	m.SelectedField = next % len(form.Fields)
	m.syncLayoutFromCurrentAction()
}

func (m *EditorModel) BeginEdit() {
	field := m.CurrentField()
	if field == nil {
		return
	}
	m.Editing = true
	m.EditBuffer = field.Value
	m.syncLayoutFromCurrentAction()
}

func (m *EditorModel) ApplyEditValue(value string) {
	field := m.CurrentField()
	if field == nil {
		return
	}
	field.Value = strings.TrimSpace(value)
	m.Editing = false
	m.EditBuffer = ""
	m.syncLayoutFromCurrentAction()
}

func (m *EditorModel) CycleCurrentField(delta int) {
	field := m.CurrentField()
	if field == nil {
		return
	}
	switch field.Type {
	case FieldTypeToggle:
		if field.Value == "1" {
			field.Value = "2"
		} else {
			field.Value = "1"
		}
	case FieldTypeSelect:
		if len(field.Options) == 0 {
			return
		}
		index := 0
		for i, option := range field.Options {
			if option == field.Value {
				index = i
				break
			}
		}
		next := index + delta
		for next < 0 {
			next += len(field.Options)
		}
		field.Value = field.Options[next%len(field.Options)]
	}
	m.syncLayoutFromCurrentAction()
}

func (m *EditorModel) CurrentForm() *Form {
	if len(m.Layout.Actions) == 0 {
		return nil
	}
	action := m.Layout.Actions[m.Layout.SelectedAction]
	form, ok := m.Forms[action.Key]
	if !ok {
		return nil
	}
	return form
}

func (m *EditorModel) CurrentField() *Field {
	form := m.CurrentForm()
	if form == nil || len(form.Fields) == 0 {
		return nil
	}
	if m.SelectedField < 0 {
		m.SelectedField = 0
	}
	if m.SelectedField >= len(form.Fields) {
		m.SelectedField = len(form.Fields) - 1
	}
	return &form.Fields[m.SelectedField]
}

func (m *EditorModel) syncLayoutFromCurrentAction() {
	form := m.CurrentForm()
	if form == nil {
		m.Layout.RightTitle = "参数编辑"
		m.Layout.RightBodyLines = []string{"当前操作无需额外参数。"}
		return
	}
	if form.Title != "" {
		m.Layout.RightTitle = form.Title
	} else {
		m.Layout.RightTitle = "参数编辑"
	}
	lines := make([]string, 0, len(form.Fields))
	for index, field := range form.Fields {
		prefix := "  "
		if index == m.SelectedField {
			prefix = "▶ "
		}
		value := formatFieldValue(field)
		lines = append(lines, prefix+field.Label+": "+value)
	}
	if len(lines) == 0 {
		lines = append(lines, "当前操作无需额外参数。")
	}
	m.Layout.RightBodyLines = lines
}

func formatFieldValue(field Field) string {
	if field.Type == FieldTypeToggle {
		if field.Value == "1" {
			return "是"
		}
		return "否"
	}
	if strings.TrimSpace(field.Value) == "" {
		return "未设置"
	}
	return field.Value
}

