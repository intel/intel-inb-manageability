package factory

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSecurityOptions(t *testing.T) {
	x, err := SecurityOptionsParse("apparmor=X seccomp=Y")
	assert.Equal(t, x, SecurityOptions{AppArmor: "X", SecComp: "Y"})
	assert.Equal(t, err, nil)
	assert.Equal(t, x.AsStringArray(), []string{"apparmor=X", "seccomp=Y"})

	x, err = SecurityOptionsParse("apparmor=X seccomp=Z")
	assert.Equal(t, x, SecurityOptions{AppArmor: "X", SecComp: "Z"})
	assert.Equal(t, err, nil)
	assert.Equal(t, x.AsStringArray(), []string{"apparmor=X", "seccomp=Z"})

	x, err = SecurityOptionsParse("seccomp=Z apparmor=Q")
	assert.Equal(t, x, SecurityOptions{AppArmor: "Q", SecComp: "Z"})
	assert.Equal(t, err, nil)
	assert.Equal(t, x.AsStringArray(), []string{"apparmor=Q", "seccomp=Z"})

	x, err = SecurityOptionsParse("xyzzyseccomp=Z apparmor=Qqrstuvwx")
	assert.NotNil(t, err)

	// default case, no option
	x, err = SecurityOptionsParse("")
	assert.Equal(t, err, nil)
	assert.Equal(t, x.AsStringArray(), []string{})
}
