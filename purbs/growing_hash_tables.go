package purbs

type GrowingHashTables struct {
	EntryLength		int32
	Data			[]byte
}

func newGrowingHashTables(entryLength int32) *GrowingHashTables {
	ght := new(GrowingHashTables)
	ght.EntryLength = entryLength



	return ght
}

func (*GrowingHashTables) toBytes() []byte {
	return make([]byte, 0)
}

func (*GrowingHashTables) write(data []byte){

}