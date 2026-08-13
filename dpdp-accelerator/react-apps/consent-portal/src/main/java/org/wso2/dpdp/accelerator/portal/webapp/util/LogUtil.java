/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.dpdp.accelerator.portal.webapp.util;

/**
 * Log helpers for the nominee flow.
 *
 * <p>Acting events are the only record of a nominee reaching for an owner's
 * data, so the identifiers involved have to be logged. Those identifiers arrive
 * from request input and from token claims, which means they must not be written
 * into a log line verbatim: a value carrying CR or LF would forge additional log
 * entries and could hide the very event being recorded.
 */
public final class LogUtil {

    /** Bounds a single logged value, so an oversized input cannot flood the log. */
    private static final int MAX_LENGTH = 200;

    private LogUtil() {
    }

    /**
     * Renders an untrusted value safe to embed in a log line: line breaks and
     * control characters become underscores, and the result is truncated.
     */
    public static String sanitize(String value) {

        if (value == null) {
            return "null";
        }
        String bounded = value.length() > MAX_LENGTH ? value.substring(0, MAX_LENGTH) + "..." : value;
        StringBuilder out = new StringBuilder(bounded.length());
        for (int i = 0; i < bounded.length(); i++) {
            char character = bounded.charAt(i);
            out.append(Character.isISOControl(character) ? '_' : character);
        }
        return out.toString();
    }
}
