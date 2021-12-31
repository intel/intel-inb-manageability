package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParsesConfigurationValues(t *testing.T) {
	v, err := ParseConfigValue("../testdata/trtl.xml", NumberImagesHeld)
	assert.Equal(t, "2", v)
	assert.NoError(t, err)
}

func TestErrorsOnMalformedXML(t *testing.T) {
	v, err := ParseConfigValue("../testdata/badData.xml", NumberImagesHeld)
	assert.Equal(t, "", v)
	assert.Error(t, err, "unable to parse XML file.")
}

func TestErrorsOnInvalidXML(t *testing.T) {
	v, err := ParseConfigValue("../testdata/goodData.xml", NumberImagesHeld)
	assert.Equal(t, "", v)
	assert.Error(t, err, "unable to parse XML file.")
}

func TestErrorsOnNonexistingXML(t *testing.T) {
	v, err := ParseConfigValue("../testdata/missing.xml", NumberImagesHeld)
	assert.Equal(t, "", v)
	assert.Error(t, err)
}
