package config

import (
	"os"
	"path/filepath"
)

// getHomeDir returns the user's home directory, with fallback to current directory
func getHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return homeDir
}

// Default directories and file paths for beemflow.
// These default to the user's home directory for security and consistency.
var (
	// DefaultConfigDir is the base directory for storing beemflow artifacts.
	DefaultConfigDir = filepath.Join(getHomeDir(), ".beemflow")
	// DefaultBlobDir is the default directory for filesystem blobs.
	DefaultBlobDir = filepath.Join(DefaultConfigDir, "files")
	// DefaultLocalRegistryPath is the default path for the local registry file.
	DefaultLocalRegistryPath = filepath.Join(DefaultConfigDir, "registry.json")
	// DefaultSQLiteDSN is the default data source name for SQLite storage.
	DefaultSQLiteDSN = filepath.Join(DefaultConfigDir, "flow.db")
	// DefaultFlowsDir is the default directory for flow definitions.
	DefaultFlowsDir = "flows"
)

// DefaultLocalRegistryFullPath returns the full path to the default local registry file.
func DefaultLocalRegistryFullPath() string {
	return DefaultLocalRegistryPath
}

// DefaultConfigDirFullPath returns the full path to the default config directory.
func DefaultConfigDirFullPath() string {
	return DefaultConfigDir
}
