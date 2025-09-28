package http

import (
	"bytes"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/beemflow/beemflow/utils"
)

// TemplateRenderer handles HTML template rendering
type TemplateRenderer struct {
	templates map[string]*template.Template
	baseDir   string
}

// NewTemplateRenderer creates a new template renderer
func NewTemplateRenderer(baseDir string) *TemplateRenderer {
	return &TemplateRenderer{
		templates: make(map[string]*template.Template),
		baseDir:   baseDir,
	}
}

// LoadTemplate loads and parses a template
func (r *TemplateRenderer) LoadTemplate(name, filename string) error {
	templatePath := filepath.Join(r.baseDir, filename)
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return utils.Errorf("failed to parse template %s: %w", filename, err)
	}

	r.templates[name] = tmpl
	utils.Debug("Loaded template %s from %s", name, filename)
	return nil
}

// RenderTemplate renders a template with data
func (r *TemplateRenderer) RenderTemplate(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, exists := r.templates[name]
	if !exists {
		return utils.Errorf("template %s not found", name)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return utils.Errorf("failed to execute template %s: %w", name, err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}

// LoadOAuthTemplates loads all OAuth-related templates
func (r *TemplateRenderer) LoadOAuthTemplates() error {
	oauthTemplates := map[string]string{
		"consent":       "static/oauth/consent.html",
		"provider_auth": "static/oauth/provider_auth.html",
		"success":       "static/oauth/success.html",
		"providers":     "static/oauth/providers.html",
	}

	for name, filename := range oauthTemplates {
		if err := r.LoadTemplate(name, filename); err != nil {
			// In test environments, templates might not be available
			// Log warning but don't fail - OAuth features will be disabled
			utils.Warn("OAuth template %s not found, OAuth features will be limited: %v", filename, err)
		}
	}

	return nil
}
