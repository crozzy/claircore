package claircore

// FileKind is used to detemine what kind of file was found.
type FileKind string

const (
	FileKindWhiteout = FileKind("whiteout")
)

// File represents interesing files that are found in the layer.
type File struct {
	// Path is where in the layer filesystem the file is located.
	Path string
	// Kind is what kind of file was found.
	Kind FileKind
}
