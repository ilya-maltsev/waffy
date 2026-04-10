// Package profile defines the YAML profile format and parsing.
//
// Profiles are the intermediate representation between the learning engine
// (Python) and the compiled binary rule store (loaded by nginx).
package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ParamSource identifies where a parameter comes from.
type ParamSource string

const (
	SourceQuery  ParamSource = "query"
	SourceBody   ParamSource = "body"
	SourceHeader ParamSource = "header"
	SourceCookie ParamSource = "cookie"
)

// ParamType identifies the inferred type of a parameter.
type ParamType string

const (
	TypeString  ParamType = "string"
	TypeInteger ParamType = "integer"
	TypeFloat   ParamType = "float"
	TypeBoolean ParamType = "boolean"
	TypeEnum    ParamType = "enum"
	TypeUUID    ParamType = "uuid"
	TypeEmail   ParamType = "email"
	TypeIPv4    ParamType = "ipv4"
	TypeDate    ParamType = "iso_date"
	TypeBase64  ParamType = "base64"
	TypeHex     ParamType = "hex"
	TypeJWT     ParamType = "jwt"
)

// Constraints holds the validation constraints for a parameter.
type Constraints struct {
	MinLength int      `yaml:"min_length,omitempty"`
	MaxLength int      `yaml:"max_length,omitempty"`
	Regex     string   `yaml:"regex,omitempty"`
	Min       *int64   `yaml:"min,omitempty"`
	Max       *int64   `yaml:"max,omitempty"`
	Values    []string `yaml:"values,omitempty"` // For enum type
}

// ParamRule defines validation rules for a single parameter.
type ParamRule struct {
	Name        string      `yaml:"name"`
	Source      ParamSource `yaml:"source"`
	Required    bool        `yaml:"required"`
	Type        ParamType   `yaml:"type"`
	Constraints Constraints `yaml:"constraints,omitempty"`
	FreeText    bool        `yaml:"freetext,omitempty"` // Needs blacklist overlay
}

// LocationProfile defines the complete rule set for one location + method.
type LocationProfile struct {
	Location     string   `yaml:"location"`
	Method       string   `yaml:"method"`
	ContentTypes []string `yaml:"content_types,omitempty"`
	StrictMode   bool     `yaml:"strict_mode"`
	Parameters   []ParamRule `yaml:"parameters"`
}

// LoadProfile reads a single YAML profile file.
func LoadProfile(path string) (*LocationProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}

	var profile LocationProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}

	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate profile %s: %w", path, err)
	}

	return &profile, nil
}

// LoadProfileDir reads all YAML profiles from a directory.
func LoadProfileDir(dir string) ([]*LocationProfile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profile dir %s: %w", dir, err)
	}

	var profiles []*LocationProfile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		profile, err := LoadProfile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

// Validate checks that a profile is well-formed.
func (p *LocationProfile) Validate() error {
	if p.Location == "" {
		return fmt.Errorf("location is required")
	}
	if p.Method == "" {
		return fmt.Errorf("method is required")
	}

	for i, param := range p.Parameters {
		if param.Name == "" {
			return fmt.Errorf("parameter %d: name is required", i)
		}
		if param.Source == "" {
			return fmt.Errorf("parameter %d (%s): source is required", i, param.Name)
		}
		if param.Type == TypeEnum && len(param.Constraints.Values) == 0 {
			return fmt.Errorf("parameter %d (%s): enum type requires values", i, param.Name)
		}
	}

	return nil
}
