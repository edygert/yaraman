package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	jsonpb "github.com/golang/protobuf/jsonpb"
)

// Ruleset is defined as the full path and file name of a file
// containing 1 or more yara rules.
type yaraRulesetType struct {
	ID          string `json:"id"`
	RulesetName string `json:"ruleset"`
	// These tags are extracted from the ruleset path. Each part of the
	// path is a separate tag.
	RulesetTags []string `json:"ruleset_tags"`
	Imports     []string `json:"imports"`
	Includes    []string `json:"includes"`
}

// Build one of these per YARA rule for submission to bleve.
type yaraRuleType struct {
	ID      string `json:"id"`
	Global  bool   `json:"global"`
	Private bool   `json:"private"`
	// This is the location from which the ruleset was read.
	// RulesetName is the full path and name of the file the
	// ruleset was read from.
	RulesetName  string   `json:"ruleset"`
	RuleName     string   `json:"rule"`
	RuleNameTags []string `json:"rule_name_tags"`
	RuleTags     []string `json:"rule_tags"`
	UserTags     []string `json:"user_tags"`

	// allow for multiple values per metadata key
	Metadata map[string][]string `json:"metadata"`
	Body     string              `json:"body"`
}

const (
	camelCasePattern = `[A-Z]*([^A-Z]|$)+`
	abbrevPattern    = `^[A-Z0-9]{2,}`
)

type ruleCallbackFunc func(ctx *YaramanContext, rulesetName string, rule *ast.Rule)
type rulesetCallbackFunc func(ctx *YaramanContext, rulesetName string, ruleset *ast.RuleSet)

var (
	camelRE  = regexp.MustCompile(camelCasePattern)
	abbrevRE = regexp.MustCompile(abbrevPattern)

	// Map to standardize yara meta tags to CCCS (mostly). Some
	// entries are mapped because they were found to be in use.
	// https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml
	//
	// For example, description and desc both map to "description"
	// if a tag is not in this map, just use it as-as.
	// When matching against the string key, do not just do a
	// map lookup but iterate over the keys and match the prefix.
	// e.g. hash* will always map to "hash". Always iterate over
	// every prefix and match the longest one. This is to ensure
	// that ref_hash maps to hash not reference, etc.
	// Setting the value to space leaves the metatag as-is.
	normalizedMetaTags = map[string]string{}
)

func readNormalizedMetaTags(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) == 0 {
			continue
		}
		if len(parts) == 1 {
			normalizedMetaTags[parts[0]] = parts[0]
			continue
		}
		normalizedMetaTags[parts[0]] = parts[1]
	}
	return nil
}

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
// This function is ugly because so many YARA rule names are ugly.
func splitRuleName(name string) []string {
	result := []string{}

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

// lookupMetaFieldname converts a variety of non-standard
// metadata field names to consistent names
func lookupMetaFieldname(fromName string) string {
	bestSoFar := ""
	for k, v := range normalizedMetaTags {
		if strings.HasPrefix(fromName, k) {
			// if v is "" then name should be kept as-is
			if fromName == k && v == "" {
				return fromName
			}
			if len(v) >= len(bestSoFar) {
				bestSoFar = v
			}
		}
	}
	if bestSoFar == "" {
		return fromName
	}
	if fromName != bestSoFar {
		logger.Trace().Str("from_name", fromName).Str("to_name", bestSoFar).Msg("metadata map")
	}
	return bestSoFar
}

func ruleToJSON(rule *ast.Rule, out io.Writer) error {
	marshaler := jsonpb.Marshaler{
		Indent: "",
	}
	err := marshaler.Marshal(out, rule.AsProto())
	if err != nil {
		return err
	}
	out.Write([]byte("\n"))
	return nil
}

func makeID(rulesetName string, ruleName string) string {
	h := md5.New()
	io.WriteString(h, rulesetName+ruleName)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func extractMetadata(metadata []*ast.Meta) map[string][]string {
	result := map[string][]string{}
	for _, meta := range metadata {
		normalizedKey := lookupMetaFieldname(strings.ToLower(meta.Key))
		if normalizedKey == "creation_date" ||
			normalizedKey == "last_modified" ||
			normalizedKey == "release_date" {
			normalizedDate := normalizeDate(meta.String())
			if normalizedDate != "" {
				if result[normalizedKey] == nil {
					result[normalizedKey] = []string{}
				}
				result[normalizedKey] = append(result[normalizedKey], normalizedDate)
				logger.Trace().Str("original_date", meta.String()).Str("normalized_date", normalizedDate).Msg("metadata date")
			}
			continue
		}
		if result[normalizedKey] == nil {
			result[normalizedKey] = []string{}
		}
		result[normalizedKey] = append(result[normalizedKey], meta.String())
	}
	return result
}

func makeJSON(rulesetName string, rule *ast.Rule) {
	ruleToJSON(rule, os.Stdout)
}

func makeRuleDoc(ctx *YaramanContext, rulesetName string, rule *ast.Rule) {
	var buf bytes.Buffer
	rule.WriteSource(&buf)

	newDoc := &yaraRuleType{
		ID:          makeID(rulesetName, rule.Identifier),
		Global:      rule.Global,
		Private:     rule.Private,
		RulesetName: rulesetName,
		RuleName:    rule.Identifier,
		// RuleNameTags are extracted from the rule names
		RuleNameTags: splitRuleName(rule.Identifier),
		// RuleTags are the tags specified by the rule creator
		RuleTags: append([]string{}, rule.Tags...),
		UserTags: []string{},
		Body:     buf.String(),
		Metadata: extractMetadata(rule.Meta),
	}
	logger.Trace().Str("ruleset_name", newDoc.RulesetName).
		Str("rulename", newDoc.RuleName).
		Strs("rulename_tags", newDoc.RuleNameTags).
		Strs("rule_tags", newDoc.RuleTags).Msg("yaradoc")
	for k, v := range newDoc.Metadata {
		logger.Trace().Strs(k, v).Msg("yaradoc metadata")
	}
}

func rulesetURLToRulesDir(ctx *YaramanContext, rulesetName string) (string, error) {
	if strings.HasPrefix(rulesetName, "http") {
		parsedURL, err := url.Parse(rulesetName)
		if err != nil {
			return "", err
		}

		// If the url contains the name of a repo, treat the whole
		// path as the name of a directory.
		if ctx.repoHosts.Contains(parsedURL.Host) {
			return ctx.rulesDir + string(os.PathSeparator) + parsedURL.Host + parsedURL.Path, nil
		}

		// otherwise treat all but the last part of the path as the
		// directory and the last part of the path as the filename.
		return parsedURL.Host + string(os.PathSeparator) + filepath.FromSlash(parsedURL.Path), nil
	}
	return "", nil
}

func makeRulesetDoc(ctx *YaramanContext, rulesetName string, ruleset *ast.RuleSet) {
	rulesetDoc := &yaraRulesetType{
		ID:          rulesetName,
		RulesetTags: []string{},
		Imports:     append([]string{}, ruleset.Imports...),
		Includes:    append([]string{}, ruleset.Includes...),
	}
	if rulesetDoc != nil {

	}
}

func parseRuleset(ctx *YaramanContext, rulesetName string, reader io.Reader, rulesetCallback rulesetCallbackFunc, ruleCallback ruleCallbackFunc) error {
	ruleset, err := gyp.Parse(reader)
	if err != nil {
		return err
	}

	rulesetCallback(ctx, rulesetName, ruleset)

	for _, rule := range ruleset.Rules {
		ruleCallback(ctx, rulesetName, rule)
	}
	return nil
}

func parseRulesetFile(ctx *YaramanContext, filename string, rulesetCallback rulesetCallbackFunc, ruleCallback ruleCallbackFunc) error {
	file, err := os.Open(filename)
	if err != nil {
		errorLogger.Error().AnErr("error", err).Str("filename", filename).Msg("Could not open file.")
	}
	defer file.Close()

	err = parseRuleset(ctx, filename, file, rulesetCallback, ruleCallback)
	if err != nil {
		errorLogger.Error().AnErr("error", err).Str("filename", filename).Msg("Error parsing ruleset")
	}
	return nil
}
