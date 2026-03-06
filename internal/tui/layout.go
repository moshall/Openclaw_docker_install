package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type ColorProfile string

const (
	ColorProfileTrueColor ColorProfile = "truecolor"
	ColorProfileANSI256   ColorProfile = "ansi256"
	ColorProfileANSI16    ColorProfile = "ansi16"
)

type Action struct {
	Key         string
	Label       string
	Description string
}

type LayoutModel struct {
	Actions        []Action
	SelectedAction int
	Status         string
	PreviewLines   []string
	RightTitle     string
	RightBodyLines []string
	theme          theme
}

type theme struct {
	header      lipgloss.Style
	card        lipgloss.Style
	cardTitle   lipgloss.Style
	menuNormal  lipgloss.Style
	menuActive  lipgloss.Style
	contentText lipgloss.Style
	statusText  lipgloss.Style
}

func DetectColorProfile(termName, colorTerm string) ColorProfile {
	lowerColorTerm := strings.ToLower(strings.TrimSpace(colorTerm))
	switch {
	case strings.Contains(lowerColorTerm, "truecolor"), strings.Contains(lowerColorTerm, "24bit"):
		return ColorProfileTrueColor
	case strings.Contains(strings.ToLower(strings.TrimSpace(termName)), "256color"):
		return ColorProfileANSI256
	default:
		return ColorProfileANSI16
	}
}

func NewLayoutModel(actions []Action, profile ColorProfile) LayoutModel {
	return LayoutModel{
		Actions:      actions,
		Status:       "idle",
		PreviewLines: []string{"暂无命令预览"},
		RightTitle:   "参数编辑",
		theme:        newTheme(profile),
	}
}

func (m LayoutModel) View(width, height int) string {
	if width < 80 {
		width = 80
	}
	_ = height

	header := m.theme.header.Render("OpenClaw 安装助手 · 增强模式")
	status := m.theme.statusText.Render("状态: " + m.Status)

	bodyLines := []string{m.theme.cardTitle.Render("菜单（↑↓ 选择）")}
	for index, action := range m.Actions {
		prefix := "  "
		if index == m.SelectedAction {
			prefix = "▶ "
		}
		line := prefix + action.Label
		if index == m.SelectedAction {
			bodyLines = append(bodyLines, m.theme.menuActive.Render(line))
			continue
		}
		bodyLines = append(bodyLines, m.theme.menuNormal.Render(line))
	}

	bodyLines = append(bodyLines, "")
	bodyLines = append(bodyLines, m.theme.cardTitle.Render("当前操作"))
	selectedActionLabel := "未选择操作"
	selectedActionDesc := "请选择菜单项查看说明。"
	if m.SelectedAction >= 0 && m.SelectedAction < len(m.Actions) {
		selectedAction := m.Actions[m.SelectedAction]
		selectedActionLabel = selectedAction.Label
		if trimmed := strings.TrimSpace(selectedAction.Description); trimmed != "" {
			selectedActionDesc = trimmed
		}
	}
	bodyLines = append(bodyLines, m.theme.menuActive.Render("▶ "+selectedActionLabel))
	bodyLines = append(bodyLines, m.theme.contentText.Render(selectedActionDesc))

	formTitle := strings.TrimSpace(m.RightTitle)
	if formTitle == "" {
		formTitle = "参数编辑"
	}
	bodyLines = append(bodyLines, "")
	bodyLines = append(bodyLines, m.theme.cardTitle.Render("参数表单 · "+formTitle))
	if len(m.RightBodyLines) == 0 {
		bodyLines = append(bodyLines, m.theme.contentText.Render("当前操作无需额外参数。"))
	} else {
		for _, line := range m.RightBodyLines {
			bodyLines = append(bodyLines, m.theme.contentText.Render(line))
		}
	}

	bodyLines = append(bodyLines, "")
	previewLines := []string{m.theme.cardTitle.Render("命令预览")}
	if len(m.PreviewLines) == 0 {
		previewLines = append(previewLines, m.theme.contentText.Render("暂无命令预览"))
	} else {
		for _, line := range m.PreviewLines {
			previewLines = append(previewLines, m.theme.contentText.Render(line))
		}
	}
	bodyLines = append(bodyLines, strings.Join(previewLines, "\n"))

	panel := m.theme.card.Width(width - 1).Render(strings.Join(bodyLines, "\n"))
	return lipgloss.JoinVertical(lipgloss.Left, header, status, panel)
}

func newTheme(profile ColorProfile) theme {
	accent := lipgloss.Color("5")
	headerAccent := lipgloss.Color("7")
	border := lipgloss.Color("8")
	switch profile {
	case ColorProfileTrueColor:
		accent = lipgloss.Color("#7C4DFF")
		headerAccent = lipgloss.Color("#F5F5F7")
		border = lipgloss.Color("#343641")
	case ColorProfileANSI256:
		accent = lipgloss.Color("99")
		headerAccent = lipgloss.Color("255")
		border = lipgloss.Color("239")
	}

	cardStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1)

	return theme{
		header: lipgloss.NewStyle().
			Bold(true).
			Foreground(headerAccent).
			Background(accent).
			Padding(0, 1),
		card:      cardStyle,
		cardTitle: lipgloss.NewStyle().Bold(true).Foreground(accent),
		menuNormal: lipgloss.NewStyle(),
		menuActive: lipgloss.NewStyle().
			Bold(true).
			Foreground(accent),
		contentText: lipgloss.NewStyle(),
		statusText:  lipgloss.NewStyle(),
	}
}
