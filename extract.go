package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
)

// Proposed standardized list of yara metadata fields per
// https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml
// The tags are the names of the metadata fields as they appear in the
// yara files (both CCCS and others). Alternative names for the fields
// are specified as a | separated list. These names are used to map the yara
// metadata values to fields in this structure to provide field specific
// searching.
type yaraMetadataType struct {
	// TODO: autogenerate ID, fingerprint
	ID            string    `meta:"id"`
	Fingerprint   string    `meta:"fingerprint"`
	Version       string    `meta:"version"`
	YaraVersion   string    `meta:"yara_version"`
	CreationDate  time.Time `meta:"creation_date|date"`
	FirstImported time.Time `meta:"first_imported"`
	LastModified  time.Time `meta:"last_modified"`
	Status        string    `meta:"status"`
	Sharing       string    `meta:"sharing"`
	Source        []string  `meta:"source"`
	Author        []string  `meta:"author"`
	Description   []string  `meta:"description|desc|comment"`
	Category      string    `meta:"category"`
	CategoryInfo  []string  `meta:"info|exploit|technique|tool|malware"`
	MalwareType   []string  `meta:"malware_type|maltype"`
	MitreATT      []string  `meta:"mitre_att"`
	ActorType     []string  `meta:"actor_type"`
	Actor         string    `meta:"actor"`
	MitreGroup    string    `meta:"mitre_group"`
	Report        []string  `meta:"report|vt_report|eureka_report"`
	Reference     []string  `meta:"reference|url_ref|ref"`
	Hash          []string  `meta:"hash|md5|sha|ref_hash|sample_hash|sample|test_sample|original_sample|unpacked_sample|infected_sample"`
	Credit        []string  `meta:"credit"`
	Score         string    `meta:"score"`
	OtherMetadata []string  `meta:"sample_filetype"`
}

type yaraDocType struct {
	// file path where ruleset is stored
	Path string
	// full path and filename of ruleset
	Ruleset string
	// name of rule in ruleset
	Rule string
	// rulename split into tags plus regular yara tags
	RuleTags string
	Metadata yaraMetadataType
	Body     string
}

const (
	camelCasePattern = `[A-Z]*([^A-Z]|$)+`
	abbrevPattern    = `^[A-Z0-9]{2,}`
)

type yaraCallbackFunc func(rule *ast.Rule)

var (
	camelRE  = regexp.MustCompile(camelCasePattern)
	abbrevRE = regexp.MustCompile(abbrevPattern)
)

func splitRuleName(name string) []string {
	result := []string{}

	// Split rule names into words to be used as tags
	// by dividing and conquering.
	// 1. Split into sections separated by "_"
	// 2. Split into words beginning with uppercase letters followed by one or
	//    more non-uppercase letters or a series of non-uppercase letters.
	// 3. Examine each resulting word for 2+ uppercase letters at the beginning
	//    of the word. If found, split the word into two parts. If not found,
	//    leave the word as is. This handles acronyms like "API".
	// 4. Loop over results. If entry is a single uppercase letter, combine it
	//    with the next entry if there is one. This handles things like SBox.
	reader := strings.NewReader(name)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		s := scanner.Text()
		tmp := []string{}
		sections := strings.Split(s, "_")
		for _, section := range sections {
			words := camelRE.FindAllString(section, -1)
			for _, word := range words {
				parts := abbrevRE.FindAllString(word, -1)
				if len(parts) > 0 {
					if len(parts[0]) == len(word) {
						tmp = append(tmp, word)
					} else {
						tmp = append(tmp, word[:len(parts[0])-1], word[len(parts[0])-1:])
					}
				} else {
					tmp = append(tmp, word)
				}
			}
		}

		// Rejoin orphaned single uppercase letters with the immediately following
		// string if any.
		for i := 0; i < len(tmp); {
			if i < len(tmp)-1 && len(tmp[i]) == 1 && unicode.IsUpper(rune(tmp[i][0])) {
				result = append(result, strings.ToLower(tmp[i]+tmp[i+1]))
				i++
			} else {
				if len(tmp[i]) > 1 {
					result = append(result, strings.ToLower(tmp[i]))
				}
			}
			i++
		}
	}
	return result
}

func setMetadataField(meta *yaraMetadataType, fieldName string, value interface{}) {
	// TODO: Loop over meta fields looking for a field with a meta tag name == fieldName
	// and set that field to value.
	field := reflect.ValueOf(meta).Elem().FieldByName(fieldName)
	switch field.Type().String() {
	case "string":
		if sval, ok := value.(string); ok {
			field.SetString(sval)
		}
	case "time.Time":
	case "int64":
		if ival, ok := value.(int64); ok {
			field.SetInt(ival)
		}
	}
}

// Based on: https://medium.com/capital-one-tech/learning-to-use-go-reflection-822a0aed74b7
func examiner(t reflect.Type, depth int) {
	fmt.Printf("%s%s: %s, %v\n", strings.Repeat("\t", depth), t.Name(), t.Kind(), t)

	switch t.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Ptr, reflect.Slice:
		fmt.Printf("%s Contained type: \n", strings.Repeat("\t", depth+1))
		examiner(t.Elem(), depth+1)

	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fmt.Printf("%s%d:%s, type: %s, kind: %s\n",
				strings.Repeat("\t", depth+1), i+1, field.Name, field.Type.Name(), field.Type.Kind())
			if field.Tag != "" {
				fmt.Printf("%sTag: %s\n", strings.Repeat("\t", depth+2), field.Tag.Get("cccs"))
				//				setMetadataField(&yaraMetadataType{}, field.Name, fmt.Sprintf("%s %d", "Test", i))
			}
			if field.Type.Kind().String() == "struct" {
				examiner(field.Type, depth+1)
			}
		}
	}
}

func makeYaraDoc(rule *ast.Rule) {
	//	examiner(reflect.TypeOf(yaraDocType{}), 0)
}

func parseRuleset(reader io.Reader, yaraCallback yaraCallbackFunc) error {
	ruleset, err := gyp.Parse(reader)
	if err != nil {
		return err
	}

	for _, rule := range ruleset.Rules {
		yaraCallback(rule)
		fmt.Println()
		//		fmt.Printf("\nRule: %s - %v: %v\n\n", rule.Identifier, splitRuleName(rule.Identifier), rule.Tags)
		for _, meta := range rule.Meta {
			fmt.Println(meta.Key)
			continue
			switch v := meta.Value.(type) {
			case int64:
				fmt.Printf("%s: %d\n", meta.Key, meta.Value.(int64))
			case bool:
				fmt.Printf("%s: %d\n", meta.Key, meta.Value.(bool))
			case string:
				fmt.Printf("%s: %s\n", meta.Key, meta.Value.(string))
			default:
				panic(fmt.Sprintf(`unexpected meta type: "%T"`, v))
			}
			//				fmt.Printf("%s: %s\n", meta.Key, s)
		}
	}
	return nil
}

func parseRulesetFile(filename string, yaraCallback yaraCallbackFunc) error {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	err = parseRuleset(file, yaraCallback)
	if err != nil {
		log.Fatalf("Error parsing %s: %v:", filename, err)
	}
	return nil
}

func parseRulesetFromString(yaraData string, yaraCallback yaraCallbackFunc) error {
	err := parseRuleset(strings.NewReader(yaraData), yaraCallback)
	if err != nil {
		log.Fatalf("Error parsing %s: %v:", yaraData[:30], err)
	}
	return nil
}
