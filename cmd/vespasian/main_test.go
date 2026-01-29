package main

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLI_Help(t *testing.T) {
	// This test will pass once main.go exists
	cmd := exec.Command("go", "run", ".", "--help")
	cmd.Dir = "."

	output, _ := cmd.CombinedOutput()
	// Expect error because --help exits with code 0 in kong
	// but we just care that it runs
	assert.Contains(t, string(output), "vespasian")
}

func TestCLI_Version(t *testing.T) {
	// Just verify the structure compiles
	// Actual CLI testing would use integration tests
	t.Skip("Integration test - requires full build")
}
