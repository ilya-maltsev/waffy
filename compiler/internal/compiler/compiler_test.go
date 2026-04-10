package compiler

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"testing"

	"github.com/waffy-waf/waffy/compiler/internal/profile"
)

// helper: compile profiles and return raw bytes
func compileToBytes(t *testing.T, profiles []*profile.LocationProfile) []byte {
	t.Helper()
	var buf bytes.Buffer
	c := New(profiles)
	if err := c.Compile(&buf); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	return buf.Bytes()
}

func makeProfile(location, method string, strict bool, params []profile.ParamRule) *profile.LocationProfile {
	return &profile.LocationProfile{
		Location:   location,
		Method:     method,
		StrictMode: strict,
		Parameters: params,
	}
}

func TestHeaderFormat(t *testing.T) {
	p := makeProfile("/api/users", "POST", true, []profile.ParamRule{
		{Name: "name", Source: profile.SourceBody, Required: true, Type: profile.TypeString},
	})

	data := compileToBytes(t, []*profile.LocationProfile{p})

	if len(data) < 64 {
		t.Fatalf("output too small: %d bytes", len(data))
	}

	var header StoreHeader
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &header); err != nil {
		t.Fatalf("read header: %v", err)
	}

	if header.Magic != Magic {
		t.Errorf("magic = 0x%08x, want 0x%08x", header.Magic, Magic)
	}
	if header.Version != Version {
		t.Errorf("version = %d, want %d", header.Version, Version)
	}
	if header.NLocations != 1 {
		t.Errorf("n_locations = %d, want 1", header.NLocations)
	}
	if header.IndexOffset != 64 {
		t.Errorf("index_offset = %d, want 64", header.IndexOffset)
	}
	if header.DataOffset != 64+16 { // 1 entry * 16 bytes
		t.Errorf("data_offset = %d, want %d", header.DataOffset, 64+16)
	}
	if header.TotalSize != uint64(len(data)) {
		t.Errorf("total_size = %d, want %d", header.TotalSize, len(data))
	}
}

func TestIndexEntryHash(t *testing.T) {
	p := makeProfile("/api/search", "GET", false, nil)
	data := compileToBytes(t, []*profile.LocationProfile{p})

	// Read index entry at offset 64
	idx := data[64:]
	entryHash := binary.LittleEndian.Uint32(idx[0:4])

	// Compute expected hash
	expected := locationHash("/api/search", MethodGET)

	if entryHash != expected {
		t.Errorf("index hash = 0x%08x, want 0x%08x", entryHash, expected)
	}
}

func TestHashMatchesFNV1a(t *testing.T) {
	// Verify our locationHash matches Go standard library fnv.New32a
	cases := []struct {
		location string
		method   byte
	}{
		{"/api/users", MethodPOST},
		{"/api/search", MethodGET},
		{"/", MethodGET},
		{"/api/v1/orders/status", MethodPUT},
	}

	for _, tc := range cases {
		h := fnv.New32a()
		h.Write([]byte(tc.location))
		h.Write([]byte{tc.method})
		expected := h.Sum32()

		got := locationHash(tc.location, tc.method)

		if got != expected {
			t.Errorf("locationHash(%q, 0x%02x) = 0x%08x, want 0x%08x",
				tc.location, tc.method, got, expected)
		}
	}
}

func TestHashMatchesCAlgorithm(t *testing.T) {
	// Replicate the C FNV-1a algorithm exactly to verify compatibility
	cHash := func(location string, method byte) uint32 {
		hash := uint32(2166136261)
		for _, b := range []byte(location) {
			hash ^= uint32(b)
			hash *= 16777619
		}
		hash ^= uint32(method)
		hash *= 16777619
		return hash
	}

	cases := []struct {
		location string
		method   byte
	}{
		{"/api/users", MethodPOST},
		{"/api/search", MethodGET},
		{"/health", MethodHEAD},
		{"/api/v1/users", MethodDELETE},
	}

	for _, tc := range cases {
		goHash := locationHash(tc.location, tc.method)
		cExpected := cHash(tc.location, tc.method)

		if goHash != cExpected {
			t.Errorf("hash mismatch for %q method=0x%02x: go=0x%08x, c=0x%08x",
				tc.location, tc.method, goHash, cExpected)
		}
	}
}

func TestMultipleLocations(t *testing.T) {
	profiles := []*profile.LocationProfile{
		makeProfile("/api/users", "POST", true, []profile.ParamRule{
			{Name: "name", Source: profile.SourceBody, Required: true, Type: profile.TypeString},
		}),
		makeProfile("/api/search", "GET", false, []profile.ParamRule{
			{Name: "q", Source: profile.SourceQuery, Required: true, Type: profile.TypeString},
		}),
	}

	data := compileToBytes(t, profiles)

	var header StoreHeader
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &header)

	if header.NLocations != 2 {
		t.Errorf("n_locations = %d, want 2", header.NLocations)
	}

	// Both index entries should have valid offsets within the file
	for i := uint32(0); i < header.NLocations; i++ {
		off := header.IndexOffset + uint64(i)*16
		entryOff := binary.LittleEndian.Uint64(data[off+4 : off+12])
		entrySize := binary.LittleEndian.Uint32(data[off+12 : off+16])

		if entryOff+uint64(entrySize) > header.TotalSize {
			t.Errorf("entry %d data exceeds file: offset=%d size=%d total=%d",
				i, entryOff, entrySize, header.TotalSize)
		}
	}
}

func TestLocationDataFormat(t *testing.T) {
	min := int64(0)
	max := int64(150)
	p := makeProfile("/api/v1/users", "POST", true, []profile.ParamRule{
		{
			Name:     "age",
			Source:   profile.SourceBody,
			Required: false,
			Type:     profile.TypeInteger,
			Constraints: profile.Constraints{
				Min: &min,
				Max: &max,
			},
		},
		{
			Name:     "role",
			Source:   profile.SourceBody,
			Required: false,
			Type:     profile.TypeEnum,
			Constraints: profile.Constraints{
				Values: []string{"user", "admin"},
			},
		},
	})
	p.ContentTypes = []string{"application/json"}

	data := compileToBytes(t, []*profile.LocationProfile{p})

	var header StoreHeader
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &header)

	// Read location data from the data section
	idx := data[header.IndexOffset:]
	locOffset := binary.LittleEndian.Uint64(idx[4:12])
	locSize := binary.LittleEndian.Uint32(idx[12:16])

	locData := data[locOffset : locOffset+uint64(locSize)]
	pos := 0

	// location_path: lps
	pathLen := int(binary.LittleEndian.Uint16(locData[pos:]))
	pos += 2
	path := string(locData[pos : pos+pathLen])
	pos += pathLen

	if path != "/api/v1/users" {
		t.Errorf("location = %q, want /api/v1/users", path)
	}

	// method (1 byte)
	method := locData[pos]
	pos++
	if method != MethodPOST {
		t.Errorf("method = 0x%02x, want 0x%02x", method, MethodPOST)
	}

	// strict_mode (1 byte)
	strict := locData[pos]
	pos++
	if strict != 1 {
		t.Errorf("strict_mode = %d, want 1", strict)
	}

	// n_content_types
	nCT := binary.LittleEndian.Uint16(locData[pos:])
	pos += 2
	if nCT != 1 {
		t.Errorf("n_content_types = %d, want 1", nCT)
	}

	// content type string
	ctLen := int(binary.LittleEndian.Uint16(locData[pos:]))
	pos += 2
	ct := string(locData[pos : pos+ctLen])
	pos += ctLen
	if ct != "application/json" {
		t.Errorf("content_type = %q, want application/json", ct)
	}

	// n_params
	nParams := binary.LittleEndian.Uint16(locData[pos:])
	pos += 2
	if nParams != 2 {
		t.Errorf("n_params = %d, want 2", nParams)
	}

	// First param: age (integer, min=0, max=150)
	nameLen := int(binary.LittleEndian.Uint16(locData[pos:]))
	pos += 2
	name := string(locData[pos : pos+nameLen])
	pos += nameLen
	if name != "age" {
		t.Errorf("param[0].name = %q, want age", name)
	}

	paramSource := locData[pos]
	pos++
	if paramSource != SrcBody {
		t.Errorf("param[0].source = 0x%02x, want 0x%02x", paramSource, SrcBody)
	}

	paramReq := locData[pos]
	pos++
	if paramReq != 0 {
		t.Errorf("param[0].required = %d, want 0", paramReq)
	}

	paramType := locData[pos]
	pos++
	if paramType != TypeInteger {
		t.Errorf("param[0].type = %d, want %d", paramType, TypeInteger)
	}

	// min_length, max_length (uint32 each)
	pos += 4 // min_length
	pos += 4 // max_length

	// min_value (int64)
	minVal := int64(binary.LittleEndian.Uint64(locData[pos:]))
	pos += 8
	if minVal != 0 {
		t.Errorf("param[0].min_value = %d, want 0", minVal)
	}

	// max_value (int64)
	maxVal := int64(binary.LittleEndian.Uint64(locData[pos:]))
	pos += 8
	if maxVal != 150 {
		t.Errorf("param[0].max_value = %d, want 150", maxVal)
	}
}

func TestEmptyProfilesError(t *testing.T) {
	var buf bytes.Buffer
	c := New(nil)
	err := c.Compile(&buf)
	if err == nil {
		t.Error("expected error for empty profiles, got nil")
	}
}

func TestMethodFlags(t *testing.T) {
	cases := []struct {
		method string
		flag   byte
	}{
		{"GET", 0x01},
		{"POST", 0x02},
		{"PUT", 0x04},
		{"DELETE", 0x08},
		{"PATCH", 0x10},
		{"HEAD", 0x20},
		{"OPTIONS", 0x40},
		{"UNKNOWN", 0x00},
	}

	for _, tc := range cases {
		got := methodFlag(tc.method)
		if got != tc.flag {
			t.Errorf("methodFlag(%q) = 0x%02x, want 0x%02x", tc.method, got, tc.flag)
		}
	}
}

func TestSourceFlags(t *testing.T) {
	cases := []struct {
		source profile.ParamSource
		flag   byte
	}{
		{profile.SourceQuery, 0x01},
		{profile.SourceBody, 0x02},
		{profile.SourceHeader, 0x04},
		{profile.SourceCookie, 0x08},
	}

	for _, tc := range cases {
		got := sourceFlag(tc.source)
		if got != tc.flag {
			t.Errorf("sourceFlag(%q) = 0x%02x, want 0x%02x", tc.source, got, tc.flag)
		}
	}
}

func TestTypeIDs(t *testing.T) {
	cases := []struct {
		typ profile.ParamType
		id  byte
	}{
		{profile.TypeString, 0},
		{profile.TypeInteger, 1},
		{profile.TypeFloat, 2},
		{profile.TypeBoolean, 3},
		{profile.TypeEnum, 4},
		{profile.TypeUUID, 5},
		{profile.TypeEmail, 6},
		{profile.TypeIPv4, 7},
		{profile.TypeDate, 8},
		{profile.TypeBase64, 9},
		{profile.TypeHex, 10},
		{profile.TypeJWT, 11},
	}

	for _, tc := range cases {
		got := typeID(tc.typ)
		if got != tc.id {
			t.Errorf("typeID(%q) = %d, want %d", tc.typ, got, tc.id)
		}
	}
}
