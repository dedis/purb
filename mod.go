package purb

type Purb interface {
	Decode(
		blob []byte,
	) (bool, []byte, error)

	Encode(
		data []byte,
	) error

	ToBytes() []byte

	VisualRepresentation(verbose bool) string
}
