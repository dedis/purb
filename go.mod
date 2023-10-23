module github.com/dedis/purb

go 1.21

replace github.com/fixbuf v1.0.3 => go.dedis.ch/fixbuf v1.0.3

replace go.dedis.ch/kyber/v3 v3.1.0 => ../kyber

require (
	github.com/stretchr/testify v1.8.4
	go.dedis.ch/kyber/v3 v3.1.0
	gopkg.in/dedis/onet.v2 v2.0.0-20181115163211-c8f3724038a7
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/daviddengcn/go-colortext v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
