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
	result := ns.Route("/dev/factotum")
	assert.NotEmpty(t, result)
	assert.NotNil(t, result[0].Client)
	assert.Equal(t, "/", result[0].RelPath)

	result2 := ns.Route("/dev/factotum/ctl")
	assert.NotEmpty(t, result2)
	assert.Equal(t, result[0].Client, result2[0].Client)
	assert.Equal(t, "/ctl", result2[0].RelPath)

	// Verify miss
	result3 := ns.Route("/other")
	assert.Empty(t, result3)
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
	r1 := ns.Route("/lib/namespace")
	assert.NotEmpty(t, r1)
	assert.NotNil(t, r1[0].Client)
	assert.Equal(t, "/lib/namespace", r1[0].RelPath)

	// Route /dev/factotum -> Factotum
	r2 := ns.Route("/dev/factotum/key")
	assert.NotEmpty(t, r2)
	assert.NotNil(t, r2[0].Client)
	assert.Equal(t, "/key", r2[0].RelPath)
}

func TestNamespace_Union(t *testing.T) {
	// md := NewMockDialer() // Unused
	// Mock Clients
	c1 := &Client{addr: "c1"}
	c2 := &Client{addr: "c2"}
	c3 := &Client{addr: "c3"}

	ns := NewNamespace()
	ns.Mount("/bin", c1, MREPL)

	// 1. Initial State: /bin -> [c1]
	routes := ns.Route("/bin")
	assert.Len(t, routes, 1)
	assert.Equal(t, c1, routes[0].Client)

	// 2. Bind After: bind -a /ext/bin /bin -> [c1, c2]
	// Need to mount /ext first to have a source?
	// Bind(old, new). Old must resolve.
	ns.Mount("/ext/bin", c2, MREPL)

	err := ns.Bind("/ext/bin", "/bin", MAFTER)
	assert.NoError(t, err)

	routes = ns.Route("/bin")
	assert.Len(t, routes, 2)
	assert.Equal(t, c1, routes[0].Client)
	assert.Equal(t, c2, routes[1].Client)

	// 3. Bind Before: bind -b /home/bin /bin -> [c3, c1, c2]
	ns.Mount("/home/bin", c3, MREPL)
	err = ns.Bind("/home/bin", "/bin", MBEFORE)
	assert.NoError(t, err)

	routes = ns.Route("/bin")
	assert.Len(t, routes, 3)
	assert.Equal(t, c3, routes[0].Client)
	assert.Equal(t, c1, routes[1].Client)
	assert.Equal(t, c2, routes[2].Client)

	// 4. Verify Resolution passing through union
	// Route("/bin/ls") should return stack [c3+ls, c1+ls, c2+ls]
	// (RelPaths will be /ls, /ls, /ls assuming they were mounted at root of that path)
	lsRoutes := ns.Route("/bin/ls")
	assert.Len(t, lsRoutes, 3)
	assert.Equal(t, c3, lsRoutes[0].Client)
	assert.Equal(t, "/ls", lsRoutes[0].RelPath)
}
