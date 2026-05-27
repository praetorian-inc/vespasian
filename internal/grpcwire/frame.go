// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package grpcwire parses the gRPC length-prefixed framing and the protobuf
// wire format used inside it. Used by the classifier (confidence boost when
// observed bodies parse as valid framed protobuf) and by the gRPC generator
// (traffic-based RPC inference when reflection is unavailable).
//
// Reference: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
package grpcwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameHeaderLen is the fixed 5-byte gRPC framing header: 1 byte for the
// compression flag and 4 bytes for the message length (big-endian uint32).
const FrameHeaderLen = 5

// Frame is one length-prefixed gRPC message extracted from a wire body.
type Frame struct {
	Compressed bool
	Message    []byte
}

// ParseFrame reads one framed message from the head of b and returns the
// Frame plus the number of bytes consumed (header + body). Returns an error
// if the header or claimed body length exceeds len(b).
//
// The returned Message slice aliases b; callers that retain it must copy.
func ParseFrame(b []byte) (Frame, int, error) {
	if len(b) < FrameHeaderLen {
		return Frame{}, 0, fmt.Errorf("grpcwire: frame header truncated (have %d, need %d)", len(b), FrameHeaderLen)
	}
	length := binary.BigEndian.Uint32(b[1:5])
	end := uint64(FrameHeaderLen) + uint64(length)
	if end > uint64(len(b)) {
		return Frame{}, 0, fmt.Errorf("grpcwire: frame body truncated (need %d, have %d)", length, len(b)-FrameHeaderLen)
	}
	return Frame{
		Compressed: b[0] != 0,
		Message:    b[FrameHeaderLen:end],
	}, int(end), nil //nolint:gosec // G115: end was checked against uint64(len(b)) above
}

// ParseFrames walks b, returning every frame found. Stops on the first parse
// error and returns the frames parsed up to that point alongside the error.
func ParseFrames(b []byte) ([]Frame, error) {
	var frames []Frame
	for len(b) > 0 {
		f, n, err := ParseFrame(b)
		if err != nil {
			return frames, err
		}
		frames = append(frames, f)
		b = b[n:]
	}
	return frames, nil
}

// WireType is the 3-bit suffix of each protobuf tag, identifying how the
// value bytes are encoded.
type WireType int

// Wire-format constants as defined in the protobuf encoding spec.
const (
	WireVarint      WireType = 0
	Wire64Bit       WireType = 1
	WireLengthDelim WireType = 2
	WireStartGroup  WireType = 3 // deprecated in proto3, not handled
	WireEndGroup    WireType = 4 // deprecated in proto3, not handled
	Wire32Bit       WireType = 5
)

// Tag is a parsed protobuf field tag: the field number and the encoding type
// of its value.
type Tag struct {
	FieldNumber int
	WireType    WireType
}

// maxVarintBytes is the longest a base-128 varint can be while still fitting
// in a uint64 (10 bytes × 7 useful bits = 70 bits, > 64).
const maxVarintBytes = 10

// ParseVarint decodes a base-128 varint from the head of b. Returns the
// decoded value and the number of bytes consumed.
func ParseVarint(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := range b {
		if i >= maxVarintBytes {
			return 0, 0, errors.New("grpcwire: varint exceeds 10 bytes")
		}
		v |= uint64(b[i]&0x7F) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("grpcwire: varint truncated")
}

// ParseTag decodes a protobuf field tag (field number + wire type) from the
// head of b.
func ParseTag(b []byte) (Tag, int, error) {
	v, n, err := ParseVarint(b)
	if err != nil {
		return Tag{}, 0, err
	}
	return Tag{
		FieldNumber: int(v >> 3),
		WireType:    WireType(v & 0x07),
	}, n, nil
}

// WalkFields iterates over each field in a protobuf message body, invoking fn
// with the parsed tag and the raw value bytes:
//   - WireVarint:      the varint encoding (1–10 bytes)
//   - Wire64Bit:       8 fixed bytes
//   - WireLengthDelim: the inner payload only (length prefix stripped)
//   - Wire32Bit:       4 fixed bytes
//
// Returning false from fn stops iteration. Returns an error on malformed
// input or unsupported wire types (start/end group).
//
// Slices passed to fn alias message; callers that retain them must copy.
func WalkFields(message []byte, fn func(Tag, []byte) bool) error { //nolint:gocyclo // wire-type switch with per-case validation
	b := message
	for len(b) > 0 {
		tag, n, err := ParseTag(b)
		if err != nil {
			return err
		}
		b = b[n:]
		switch tag.WireType {
		case WireVarint:
			_, m, err := ParseVarint(b)
			if err != nil {
				return err
			}
			if !fn(tag, b[:m]) {
				return nil
			}
			b = b[m:]
		case Wire64Bit:
			if len(b) < 8 {
				return errors.New("grpcwire: 64-bit field truncated")
			}
			if !fn(tag, b[:8]) {
				return nil
			}
			b = b[8:]
		case WireLengthDelim:
			length, m, err := ParseVarint(b)
			if err != nil {
				return err
			}
			b = b[m:]
			if uint64(len(b)) < length {
				return errors.New("grpcwire: length-delimited field truncated")
			}
			if !fn(tag, b[:length]) {
				return nil
			}
			b = b[length:]
		case Wire32Bit:
			if len(b) < 4 {
				return errors.New("grpcwire: 32-bit field truncated")
			}
			if !fn(tag, b[:4]) {
				return nil
			}
			b = b[4:]
		default:
			return fmt.Errorf("grpcwire: unsupported wire type %d", tag.WireType)
		}
	}
	return nil
}
