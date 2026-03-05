package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

type FocusArea int

const (
	FocusMenu FocusArea = iota
	FocusFields
)

type RunResult struct {
	Action   string
	Values   map[string]string
	Canceled bool
}

type ProgramModel struct {
	Editor    *EditorModel
	DryRun    bool
	Focus     FocusArea
	Width     int
	Height    int
	ShowHelp  bool
	TextInput textinput.Model
	Result    RunResult
}

func NewProgramModel(editor *EditorModel, dryRun bool) ProgramModel {
	input := textinput.New()
	input.Placeholder = "输入后回车保存，Esc 取消"
	input.Prompt = "✍ "
	input.CharLimit = 512
	return ProgramModel{
		Editor:    editor,
		DryRun:    dryRun,
		Focus:     FocusMenu,
		ShowHelp:  true,
		TextInput: input,
		Result: RunResult{
			Action:   "quit",
			Values:   map[string]string{},
			Canceled: true,
		},
	}
}

func (m ProgramModel) Init() tea.Cmd {
	return nil
}

func (m ProgramModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if m.Editor != nil && m.Editor.Editing {
			switch msg.String() {
			case "enter":
				m.Editor.ApplyEditValue(m.TextInput.Value())
				m.TextInput.Blur()
				return m, nil
			case "esc":
				m.Editor.Editing = false
				m.Editor.EditBuffer = ""
				m.TextInput.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			m.TextInput, cmd = m.TextInput.Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "ctrl+c", "q":
			m.Result = RunResult{Action: "quit", Values: map[string]string{}, Canceled: true}
			return m, tea.Quit
		case "ctrl+s":
			m.Result = RunResult{
				Action:   m.currentActionKey(),
				Values:   m.currentValues(),
				Canceled: false,
			}
			return m, tea.Quit
		case "tab":
			if m.Focus == FocusMenu {
				m.Focus = FocusFields
			} else {
				m.Focus = FocusMenu
			}
		case "?":
			m.ShowHelp = !m.ShowHelp
		case "up", "k":
			if m.Focus == FocusMenu {
				m.Editor.MoveAction(-1)
			} else {
				m.Editor.MoveField(-1)
			}
		case "down", "j":
			if m.Focus == FocusMenu {
				m.Editor.MoveAction(1)
			} else {
				m.Editor.MoveField(1)
			}
		case "left", "h":
			if m.Focus == FocusFields {
				m.Editor.CycleCurrentField(-1)
			}
		case "right", "l":
			if m.Focus == FocusFields {
				m.Editor.CycleCurrentField(1)
			}
		case "enter":
			if m.Focus == FocusMenu {
				m.Focus = FocusFields
				return m, nil
			}
			field := m.Editor.CurrentField()
			if field == nil {
				return m, nil
			}
			switch field.Type {
			case FieldTypeText:
				return m.startTextEditing(field, nil)
			case FieldTypeSelect, FieldTypeToggle:
				m.Editor.CycleCurrentField(1)
			}
		default:
			if m.Focus == FocusFields && msg.Type == tea.KeyRunes {
				field := m.Editor.CurrentField()
				if field != nil && field.Type == FieldTypeText {
					return m.startTextEditing(field, &msg)
				}
			}
		}
	}
	return m, nil
}

func (m ProgramModel) startTextEditing(field *Field, initialMsg *tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.Editor.BeginEdit()
	m.TextInput.SetValue(field.Value)
	m.TextInput.CursorEnd()
	focusCmd := m.TextInput.Focus()
	if initialMsg != nil {
		var updateCmd tea.Cmd
		m.TextInput, updateCmd = m.TextInput.Update(*initialMsg)
		return m, tea.Batch(focusCmd, updateCmd)
	}
	return m, tea.Batch(focusCmd, textinput.Blink)
}

func (m ProgramModel) View() string {
	if m.Editor == nil {
		return "TUI 初始化失败"
	}
	width := m.Width
	if width <= 0 {
		width = 120
	}
	height := m.Height
	if height <= 0 {
		height = 32
	}

	m.Editor.Layout.Status = m.statusText()
	m.Editor.Layout.PreviewLines = m.previewLines()
	m.Editor.Layout.RightTitle = m.rightTitleWithFocus()

	view := m.Editor.Layout.View(width, height)
	if m.Editor.Editing {
		inputCard := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1).
			Render("编辑字段\n" + m.TextInput.View())
		view = lipgloss.JoinVertical(lipgloss.Left, view, inputCard)
	}
	if m.ShowHelp {
		helpCard := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1).
			Render("快捷键: Tab 切焦点 | ↑↓ / j k 移动 | Enter 编辑/切换 | ←→ 切换选项 | Ctrl+S 提交 | q 退出")
		view = lipgloss.JoinVertical(lipgloss.Left, view, helpCard)
	}
	return view
}

func RunEditor(editor *EditorModel, dryRun bool) (RunResult, error) {
	model := NewProgramModel(editor, dryRun)
	program := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := program.Run()
	if err != nil {
		return RunResult{}, err
	}
	out, ok := finalModel.(ProgramModel)
	if !ok {
		return RunResult{}, fmt.Errorf("unexpected program model type: %T", finalModel)
	}
	return out.Result, nil
}

func (m ProgramModel) statusText() string {
	if m.Editor.Editing {
		return "编辑中"
	}
	if m.Focus == FocusMenu {
		return "焦点: 操作菜单"
	}
	return "焦点: 参数编辑"
}

func (m ProgramModel) rightTitleWithFocus() string {
	title := "参数编辑"
	if m.Editor != nil {
		if form := m.Editor.CurrentForm(); form != nil {
			if trimmed := strings.TrimSpace(form.Title); trimmed != "" {
				title = trimmed
			}
		}
	}
	if m.Focus == FocusMenu {
		return title + "（菜单焦点）"
	}
	return title + "（表单焦点）"
}

func (m ProgramModel) previewLines() []string {
	lines := []string{
		"即将执行: bash openclawctl.sh --wizard " + m.currentActionKey(),
	}
	if m.DryRun {
		lines = append(lines, "模式: dry-run")
	}
	values := m.currentValues()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, values[key]))
		if len(lines) >= 8 {
			lines = append(lines, "...")
			break
		}
	}
	return lines
}

func (m ProgramModel) currentActionKey() string {
	if m.Editor == nil || len(m.Editor.Layout.Actions) == 0 {
		return "quit"
	}
	return m.Editor.Layout.Actions[m.Editor.Layout.SelectedAction].Key
}

func (m ProgramModel) currentValues() map[string]string {
	values := map[string]string{}
	if m.Editor == nil {
		return values
	}
	form := m.Editor.CurrentForm()
	if form == nil {
		return values
	}
	for _, field := range form.Fields {
		values[field.Key] = field.Value
	}
	return values
}
