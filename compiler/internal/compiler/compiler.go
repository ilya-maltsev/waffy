// Package compiler transforms YAML profiles into the binary rule store
// format that the nginx module loads via mmap.
package compiler

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"

	"github.com/waffy-waf/waffy/compiler/internal/profile"
)

const (
	Magic   = 0x57414657 // "WAFFY"
	Version = 1

	// Source flags (match waffy_types.h)
	SrcQuery  = 0x01
	SrcBody   = 0x02
	SrcHeader = 0x04
	SrcCookie = 0x08

	// Type IDs (match waffy_types.h)
	TypeString  = 0
	TypeInteger = 1
	TypeFloat   = 2
	TypeBoolean = 3
	TypeEnum    = 4
	TypeUUID    = 5
	TypeEmail   = 6
	TypeIPv4    = 7
	TypeDate    = 8
	TypeBase64  = 9
	TypeHex     = 10
	TypeJWT     = 11

	// Method flags
	MethodGET     = 0x01
	MethodPOST    = 0x02
	MethodPUT     = 0x04
	MethodDELETE  = 0x08
	MethodPATCH   = 0x10
	MethodHEAD    = 0x20
	MethodOPTIONS = 0x40
)

// StoreHeader is the binary file header (64 bytes, packed).
type StoreHeader struct {
	Magic       uint32
	Version     uint32
	Flags       uint32
	NLocations  uint32
	IndexOffset uint64
	DataOffset  uint64
	TotalSize   uint64
	Checksum    uint64
	Reserved    [16]byte
}

// Compiler transforms profiles into binary rule store.
type Compiler struct {
	profiles []*profile.LocationProfile
}

// New creates a compiler with the given profiles.
func New(profiles []*profile.LocationProfile) *Compiler {
	return &Compiler{profiles: profiles}
}

// Compile writes the binary rule store to the writer.
func (c *Compiler) Compile(w io.Writer) error {
	if len(c.profiles) == 0 {
		return fmt.Errorf("no profiles to compile")
	}

	// Phase 1: Serialize each location's data
	var locationData [][]byte
	for _, p := range c.profiles {
		data, err := c.serializeLocation(p)
		if err != nil {
			return fmt.Errorf("serialize %s %s: %w", p.Method, p.Location, err)
		}
		locationData = append(locationData, data)
	}

	// Phase 2: Build index
	headerSize := uint64(64)
	indexEntrySize := uint64(16) // hash(4) + offset(8) + size(4)
	indexSize := indexEntrySize * uint64(len(c.profiles))
	dataOffset := headerSize + indexSize

	// Calculate data offsets
	var offsets []uint64
	currentOffset := dataOffset
	for _, data := range locationData {
		offsets = append(offsets, currentOffset)
		currentOffset += uint64(len(data))
	}
	totalSize := currentOffset

	// Phase 3: Write header
	header := StoreHeader{
		Magic:       Magic,
		Version:     Version,
		NLocations:  uint32(len(c.profiles)),
		IndexOffset: headerSize,
		DataOffset:  dataOffset,
		TotalSize:   totalSize,
	}

	if err := binary.Write(w, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Phase 4: Write index
	for i, p := range c.profiles {
		h := locationHash(p.Location, methodFlag(p.Method))

		if err := binary.Write(w, binary.LittleEndian, h); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, offsets[i]); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(len(locationData[i]))); err != nil {
			return err
		}
	}

	// Phase 5: Write location data
	for _, data := range locationData {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	return nil
}

func (c *Compiler) serializeLocation(p *profile.LocationProfile) ([]byte, error) {
	// Simple TLV-style serialization
	var buf []byte

	// Location path (length-prefixed)
	buf = appendString(buf, p.Location)
	// Method bitmask
	buf = append(buf, methodFlag(p.Method))
	// Strict mode
	if p.StrictMode {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	// Number of content types
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(p.ContentTypes)))
	for _, ct := range p.ContentTypes {
		buf = appendString(buf, ct)
	}
	// Number of parameters
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(p.Parameters)))

	for _, param := range p.Parameters {
		buf = c.serializeParam(buf, &param)
	}

	return buf, nil
}

func (c *Compiler) serializeParam(buf []byte, p *profile.ParamRule) []byte {
	// Name
	buf = appendString(buf, p.Name)
	// Source
	buf = append(buf, sourceFlag(p.Source))
	// Required
	if p.Required {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	// Type
	buf = append(buf, typeID(p.Type))
	// Min length
	buf = binary.LittleEndian.AppendUint32(buf, uint32(p.Constraints.MinLength))
	// Max length
	buf = binary.LittleEndian.AppendUint32(buf, uint32(p.Constraints.MaxLength))
	// Min value
	minVal := int64(0)
	if p.Constraints.Min != nil {
		minVal = *p.Constraints.Min
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(minVal))
	// Max value
	maxVal := int64(0)
	if p.Constraints.Max != nil {
		maxVal = *p.Constraints.Max
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(maxVal))
	// Regex pattern
	buf = appendString(buf, p.Constraints.Regex)
	// Enum values
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(p.Constraints.Values)))
	for _, v := range p.Constraints.Values {
		buf = appendString(buf, v)
	}

	return buf
}

// appendString appends a length-prefixed string to the buffer.
func appendString(buf []byte, s string) []byte {
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s)))
	buf = append(buf, s...)
	return buf
}

// locationHash computes FNV-1a hash matching the C implementation.
func locationHash(location string, method byte) uint32 {
	h := fnv.New32a()
	h.Write([]byte(location))
	h.Write([]byte{method})
	return h.Sum32()
}

func methodFlag(method string) byte {
	switch method {
	case "GET":
		return MethodGET
	case "POST":
		return MethodPOST
	case "PUT":
		return MethodPUT
	case "DELETE":
		return MethodDELETE
	case "PATCH":
		return MethodPATCH
	case "HEAD":
		return MethodHEAD
	case "OPTIONS":
		return MethodOPTIONS
	default:
		return 0
	}
}

func sourceFlag(source profile.ParamSource) byte {
	switch source {
	case profile.SourceQuery:
		return SrcQuery
	case profile.SourceBody:
		return SrcBody
	case profile.SourceHeader:
		return SrcHeader
	case profile.SourceCookie:
		return SrcCookie
	default:
		return SrcBody
	}
}

func typeID(t profile.ParamType) byte {
	switch t {
	case profile.TypeString:
		return TypeString
	case profile.TypeInteger:
		return TypeInteger
	case profile.TypeFloat:
		return TypeFloat
	case profile.TypeBoolean:
		return TypeBoolean
	case profile.TypeEnum:
		return TypeEnum
	case profile.TypeUUID:
		return TypeUUID
	case profile.TypeEmail:
		return TypeEmail
	case profile.TypeIPv4:
		return TypeIPv4
	case profile.TypeDate:
		return TypeDate
	case profile.TypeBase64:
		return TypeBase64
	case profile.TypeHex:
		return TypeHex
	case profile.TypeJWT:
		return TypeJWT
	default:
		return TypeString
	}
}
