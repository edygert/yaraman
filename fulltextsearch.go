package main

var yaraKeywords = []interface{}{
	"all",
	"and",
	"any",
	"ascii",
	"at",
	"base64",
	"base64wide",
	"condition",
	"contains",
	"entrypoint",
	"false",
	"filesize",
	"for",
	"fullword",
	"global",
	"import",
	"in",
	"include",
	"int16",
	"int16be",
	"int32",
	"int32be",
	"int8",
	"int8be",
	"matches",
	"meta",
	"nocase",
	"not",
	"of",
	"or",
	"private",
	"rule",
	"strings",
	"them",
	"true",
	"uint16",
	"uint16be",
	"uint32",
	"uint32be",
	"uint8",
	"uint8be",
	"wide",
	"xor",
}

func initializeBleve() {
	/*
		var m *indexMapping = index.Mapping()

		err := m.AddCustomTokenFilter("yara_stop_filter", map[string]interface{}{
			"type":   bleve.stop_tokens_filter.Name,
			"tokens": yaraKeywords,
		})
		if err != nil {
			errorLog.Fatal(err)
		}

		mapping := bleve.NewIndexMapping()
		index, err := bleve.New("example.bleve", mapping)
		if err != nil {
			fmt.Println(err)
			return
		}
	*/
}

func closeBleve() {

}

func indexYaraRule() {

}
