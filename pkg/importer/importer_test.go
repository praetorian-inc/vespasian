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

package importer

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimitedReader_BasicRead(t *testing.T) {
	data := "hello world"
	lr := newLimitedReader(strings.NewReader(data), 100)

	buf := make([]byte, 100)
	n, err := lr.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, string(buf[:n]))
	assert.False(t, lr.hitLimit)
}

func TestLimitedReader_ExactLimit(t *testing.T) {
	data := "hello"
	lr := newLimitedReader(strings.NewReader(data), int64(len(data)))

	buf := make([]byte, 10)
	n, err := lr.Read(buf)

	// First read should return data and set hitLimit
	require.Equal(t, io.EOF, err)
	assert.Equal(t, len(data), n)
	assert.True(t, lr.hitLimit)
}

func TestLimitedReader_BelowLimit(t *testing.T) {
	data := "hello"
	lr := newLimitedReader(strings.NewReader(data), 3)

	buf := make([]byte, 10)
	n, err := lr.Read(buf)

	// Should only read 3 bytes and set hitLimit
	require.Equal(t, io.EOF, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, "hel", string(buf[:n]))
	assert.True(t, lr.hitLimit)
}

func TestLimitedReader_ZeroLimit(t *testing.T) {
	data := "hello world"
	lr := newLimitedReader(strings.NewReader(data), 0)

	buf := make([]byte, 10)
	n, err := lr.Read(buf)

	// With zero limit, should immediately return EOF
	require.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
	assert.True(t, lr.hitLimit)
}

func TestLimitedReader_NegativeRemaining(t *testing.T) {
	data := "hello world"
	lr := newLimitedReader(strings.NewReader(data), -1)

	buf := make([]byte, 10)
	n, err := lr.Read(buf)

	// With negative limit, should immediately return EOF
	require.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
	assert.True(t, lr.hitLimit)
}

func TestLimitedReader_MultipleReads(t *testing.T) {
	data := "hello world"
	lr := newLimitedReader(strings.NewReader(data), 100)

	buf1 := make([]byte, 5)
	n1, err1 := lr.Read(buf1)
	require.NoError(t, err1)
	assert.Equal(t, 5, n1)
	assert.False(t, lr.hitLimit)

	buf2 := make([]byte, 10)
	n2, err2 := lr.Read(buf2)
	// Second read gets remaining data
	require.NoError(t, err2)
	assert.Equal(t, 6, n2) // " world"
	assert.False(t, lr.hitLimit)
}

func TestLimitedReader_ReadAfterExhausted(t *testing.T) {
	data := "hello"
	lr := newLimitedReader(strings.NewReader(data), 3)

	buf := make([]byte, 10)

	// First read exhausts limit
	n1, err1 := lr.Read(buf)
	require.Equal(t, io.EOF, err1)
	assert.Equal(t, 3, n1)
	assert.True(t, lr.hitLimit)

	// Second read should still return EOF
	n2, err2 := lr.Read(buf)
	require.Equal(t, io.EOF, err2)
	assert.Equal(t, 0, n2)
	assert.True(t, lr.hitLimit)
}

func TestErrFileTooLarge(t *testing.T) {
	assert.NotNil(t, ErrFileTooLarge)
	assert.Contains(t, ErrFileTooLarge.Error(), "500MB")
}

func TestErrTooManyEntries(t *testing.T) {
	assert.NotNil(t, ErrTooManyEntries)
	assert.Contains(t, ErrTooManyEntries.Error(), "entry count")
}
