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

package utils

import (
	"testing"
	"time"
)

func TestGetCurrentTimeMillis(t *testing.T) {
	before := time.Now().UnixMilli()
	got := GetCurrentTimeMillis()
	after := time.Now().UnixMilli()

	if got < before || got > after {
		t.Errorf("GetCurrentTimeMillis() = %d, want value between %d and %d", got, before, after)
	}

	// Guard against accidentally returning seconds: year 2000 in millis is ~946_684_800_000.
	// Any value below that is definitely seconds, not milliseconds.
	const year2000Millis = int64(946_684_800_000)
	if got < year2000Millis {
		t.Errorf("GetCurrentTimeMillis() = %d looks like Unix seconds, not milliseconds", got)
	}
}
