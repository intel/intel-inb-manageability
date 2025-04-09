// Package structinfo contains tools to inspect structs.

package structinfo

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
)

// DefaultStore is used for package scoped functions
var DefaultStore = NewStore()

// Store holds cached information about struct data
type Store struct {
	mu    sync.RWMutex
	cache map[reflect.Type]*typeData
}

type typeData struct {
	// mapping between JSON name to actual field name
	names    map[string]string
	embedded []*typeData
}

// NewStore creates a new Store object
func NewStore() *Store {
	return &Store{
		cache: make(map[reflect.Type]*typeData),
	}
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Lock()

	s.cache = make(map[reflect.Type]*typeData)
}

var zeroval reflect.Value

func (s *Store) analyze(rt reflect.Type) *typeData {
	data := &typeData{
		names: make(map[string]string),
	}

	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if sf.Anonymous { // embedded! got to recurse
			data.embedded = append(data.embedded, s.analyze(sf.Type))
			continue
		}

		if sf.PkgPath != "" { // unexported
			continue
		}

		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}

		if tag == "" || tag[0] == ',' {
			data.names[sf.Name] = sf.Name
			continue
		}

		flen := 0
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				break
			}
			flen = j
		}

		data.names[tag[:flen+1]] = sf.Name
	}

	// do a last-pass to import all embedded anonymous fields in the
	// data.names map
	storeAnonymous(data.names, data.embedded)

	return data
}

func storeAnonymous(names map[string]string, anonymous []*typeData) {
	for _, v := range anonymous {
		for j, n := range v.names {
			names[j] = n
		}
	}
}

// FieldValue returns the reflect.Value corresponding to the given
// JSON name from the given object. Note that this differs from
// querying the reflect.Value.FieldByName, because we're matching
// against the *JSON* name, not necessarily the Go struct field name
func (s *Store) FieldValue(rv reflect.Value, name string) (reflect.Value, error) {
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return zeroval, errors.New(`value must be of kind reflect.Struct`)
	}

	fn, err := s.FieldName(rv, name)
	if err != nil {
		// XXX is this kosher for go < 1.13 ?
		return zeroval, fmt.Errorf(`failed to find field name %s: %w`, name, err)
	}

	fv := rv.FieldByName(fn)
	// is this settable?
	if !fv.CanSet() {
		return zeroval, fmt.Errorf(`invalid: field %s (json: %s) is not settable`, name, fn)
	}

	return fv, nil
}

// JSONFieldsFromStruct returns the names of JSON fields associated
// with the given struct. Returns nil if v is not a struct
//
// (This method should probably be considered deprecated)
func JSONFieldsFromStruct(v reflect.Value) []string {
	fields, err := DefaultStore.JSONFieldNames(v)
	if err != nil {
		return nil
	}
	return fields
}

// StructFieldFromJSONName returns the struct field name on the
// given struct value. Empty value means the field is either not
// public, or does not exist.
//
// This can be used to map JSON field names to actual struct fields.
//
// (This method should probably be considered deprecated)
func StructFieldFromJSONName(v reflect.Value, name string) string {
	fn, err := DefaultStore.FieldName(v, name)
	if err != nil {
		return ""
	}

	return fn
}

// JSONFields returns the list of json field names associated
// with the value.
func (s *Store) JSONFieldNames(rv reflect.Value) ([]string, error) {
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return nil, errors.New(`value must be of kind reflect.Struct`)
	}

	rt := rv.Type()

	s.mu.RLock()
	data, ok := s.cache[rt]
	if !ok {
		s.mu.RUnlock()
		s.mu.Lock()
		// if haven't already done so, analyze this data
		data = s.analyze(rt)
		s.cache[rt] = data
		s.mu.Unlock()
		s.mu.RLock()
	}

	fields := make([]string, len(data.names))
	var i int
	for v := range data.names {
		fields[i] = v
		i++
	}
	s.mu.RUnlock()

	return fields, nil
}

// FieldName returns the name of the struct's field that matches
// the given JSON name
func (s *Store) FieldName(rv reflect.Value, name string) (string, error) {
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return "", errors.New(`value must be of kind reflect.Struct`)
	}

	rt := rv.Type()

	s.mu.RLock()
	data, ok := s.cache[rt]
	if !ok {
		s.mu.RUnlock()
		s.mu.Lock()
		// if haven't already done so, analyze this data
		data = s.analyze(rt)
		s.cache[rt] = data
		s.mu.Unlock()
		s.mu.RLock()
	}
	fn, ok := data.names[name]
	s.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf(`field name %s not found in type %s`, name, rt)
	}
	return fn, nil
}
