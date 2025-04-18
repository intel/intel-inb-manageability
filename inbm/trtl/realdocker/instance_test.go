// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewInstance(t *testing.T) {
	i := NewInstance(1, "name", nil)
	assert.Equal(t, "name", i.GetName())
	assert.Equal(t, 1, i.GetVersion())
}
