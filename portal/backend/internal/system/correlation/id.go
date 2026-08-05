/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package correlation provides shared correlation ID generation helpers.
package correlation

import (
	"encoding/hex"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// NewID returns a correlation ID using the provided entropy source and
// sequence counter for fallback generation.
func NewID(read func([]byte) (int, error), sequence *uint64) string {
	buf := make([]byte, 16)
	if _, err := read(buf); err != nil {
		return fallbackID(sequence)
	}
	return hex.EncodeToString(buf)
}

func fallbackID(sequence *uint64) string {
	next := atomic.AddUint64(sequence, 1)
	timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	pid := strconv.Itoa(os.Getpid())
	seq := strconv.FormatUint(next, 36)

	return "fb-" + timestamp + "-" + pid + "-" + seq
}
