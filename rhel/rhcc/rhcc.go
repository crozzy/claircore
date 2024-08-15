// Package rhcc implements an ecosystem for the Red Hat Container Catalog.
//
// This ecosystem treats an entire container as a package and matches advisories
// against it.
package rhcc

import (
	"github.com/quay/claircore"
)

var goldRepo = claircore.Repository{
	Name: "Red Hat Container Catalog",
	URI:  `https://catalog.redhat.com/software/containers/explore`,
}
