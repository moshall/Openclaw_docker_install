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

	header := m.theme.header.Render("OpenClaw Control Center")

	leftWidth := 34
	rightWidth := width - leftWidth - 3
	if rightWidth < 40 {
		rightWidth = 40
		leftWidth = width - rightWidth - 3
	}

	menuLines := []string{"操作菜单"}
	for index, action := range m.Actions {
		prefix := "  "
		if index == m.SelectedAction {
			prefix = "▶ "
		}
		line := prefix + action.Label
		if index == m.SelectedAction {
			menuLines = append(menuLines, m.theme.menuActive.Render(line))
			continue
		}
		menuLines = append(menuLines, m.theme.menuNormal.Render(line))
	}
	leftPanel := m.theme.card.Width(leftWidth).Render(strings.Join(menuLines, "\n"))

	bodyLines := []string{m.RightTitle}
	if len(m.RightBodyLines) == 0 {
		bodyLines = append(bodyLines, m.theme.contentText.Render("选择左侧操作后，在此处编辑参数。"))
	} else {
		for _, line := range m.RightBodyLines {
			bodyLines = append(bodyLines, m.theme.contentText.Render(line))
		}
	}
	rightPanel := m.theme.card.Width(rightWidth).Render(
		m.theme.cardTitle.Render(m.RightTitle) + "\n" + strings.Join(bodyLines[1:], "\n"),
	)

	mainRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, " ", rightPanel)

	previewLines := []string{m.theme.cardTitle.Render("命令预览")}
	if len(m.PreviewLines) == 0 {
		previewLines = append(previewLines, m.theme.contentText.Render("暂无命令预览"))
	} else {
		for _, line := range m.PreviewLines {
			previewLines = append(previewLines, m.theme.contentText.Render(line))
		}
	}
	previewLines = append(previewLines, "")
	previewLines = append(previewLines, m.theme.statusText.Render("状态: "+m.Status))
	previewPanel := m.theme.card.Width(width - 1).Render(strings.Join(previewLines, "\n"))

	return lipgloss.JoinVertical(lipgloss.Left, header, mainRow, previewPanel)
}

func newTheme(profile ColorProfile) theme {
	accent := lipgloss.Color("5")
	headerAccent := lipgloss.Color("7")
	border := lipgloss.Color("8")
	text := lipgloss.Color("15")
	subtle := lipgloss.Color("7")
	switch profile {
	case ColorProfileTrueColor:
		accent = lipgloss.Color("#7C4DFF")
		headerAccent = lipgloss.Color("#F5F5F7")
		border = lipgloss.Color("#343641")
		text = lipgloss.Color("#EDEEF2")
		subtle = lipgloss.Color("#A0A7B4")
	case ColorProfileANSI256:
		accent = lipgloss.Color("99")
		headerAccent = lipgloss.Color("255")
		border = lipgloss.Color("239")
		text = lipgloss.Color("252")
		subtle = lipgloss.Color("246")
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
		menuNormal: lipgloss.NewStyle().
			Foreground(text),
		menuActive: lipgloss.NewStyle().
			Bold(true).
			Foreground(accent),
		contentText: lipgloss.NewStyle().
			Foreground(text),
		statusText: lipgloss.NewStyle().
			Foreground(subtle),
	}
}

