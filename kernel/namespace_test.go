package kernel

import (
	"testing"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

func TestNamespace_Bootstrap(t *testing.T) {
	md := NewMockDialer()

	// Setup Mock Factotum
	md.Handlers["factotum:9003"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		return &p9.Fcall{Type: p9.Rversion} // Dummy response
	})

	ns, err := BootstrapNamespace("factotum:9003", md)
	assert.NoError(t, err)
	assert.NotNil(t, ns)

	// Verify route
	client, path := ns.Route("/dev/factotum")
	assert.NotNil(t, client)
	assert.Equal(t, "/", path) // Mounted at /dev/factotum, so rel path of /dev/factotum is /

	client2, path2 := ns.Route("/dev/factotum/ctl")
	assert.Equal(t, client, client2)
	assert.Equal(t, "/ctl", path2)

	// Verify miss
	client3, _ := ns.Route("/other")
	assert.Nil(t, client3)
}

func TestNamespace_Build(t *testing.T) {
	md := NewMockDialer()

	md.Handlers["vfs-service:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall { return &p9.Fcall{Type: p9.Rversion} })
	md.Handlers["factotum:9003"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall { return &p9.Fcall{Type: p9.Rversion} })

	manifest := `
	mount / tcp!vfs-service!9002
	mount /dev/factotum tcp!factotum!9003
	`

	ns := NewNamespace()
	err := ns.Build(manifest, md)
	assert.NoError(t, err)

	// Route / -> VFS
	c1, p1 := ns.Route("/lib/namespace")
	assert.NotNil(t, c1)
	assert.Equal(t, "/lib/namespace", p1)

	// Route /dev/factotum -> Factotum
	c2, p2 := ns.Route("/dev/factotum/key")
	assert.NotNil(t, c2)
	assert.Equal(t, "/key", p2)
}
