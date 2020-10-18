package main

import (
	"fmt"
	"reflect"
	"strings"
)

type tagEntryType struct {
	fieldName string
	metaName  string
}

var (
	fieldsToTags = map[string][]string{}
	tagsToFields = map[string]*tagEntryType{}
)

// Create maps between fields in yaraDocType and their tags
func processTags() {
	t := reflect.TypeOf(yaraRuleType{})
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		metaTag := field.Tag.Get("meta")
		if metaTag == "" {
			logger.Fatal().Msg("unexpected error: no meta tag")
		}
		tags := strings.Split(metaTag, "|")
		for _, tag := range tags {
			if fieldsToTags[field.Name] == nil {
				fieldsToTags[field.Name] = []string{tag}
			} else {
				fieldsToTags[field.Name] = append(fieldsToTags[field.Name], tag)
			}
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
				fmt.Printf("%sTag: %s\n", strings.Repeat("\t", depth+2), field.Tag.Get("meta"))
				//				setMetadataField(&yaraMetadataType{}, field.Name, fmt.Sprintf("%s %d", "Test", i))
			}
			if field.Type.Kind().String() == "struct" {
				examiner(field.Type, depth+1)
			}
		}
	}
}
