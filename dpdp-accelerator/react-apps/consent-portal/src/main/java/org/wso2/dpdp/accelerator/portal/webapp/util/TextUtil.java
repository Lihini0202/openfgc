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

import java.text.Normalizer;
import java.util.Locale;

/**
 * Text comparison helpers for values that participate in security decisions.
 */
public final class TextUtil {

    private TextUtil() {
    }

    /**
     * Reduces a value to a single comparable form: normalised to NFKC, then case
     * folded against {@link Locale#ROOT}.
     *
     * <p>Both halves matter. Two different Unicode sequences can render
     * identically, so comparing raw strings would treat visually identical values
     * as different; and folding case without a fixed locale would decide
     * differently depending on the JVM's default locale — the Turkish dotless
     * "i" being the usual way that surprises people.
     *
     * <p>This is the one place case folding is performed, so the rule is reviewed
     * once rather than at each call site.
     */
    public static String canonicalFold(String value) {

        if (value == null) {
            return "";
        }
        return Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    /** Case-insensitive equality under {@link #canonicalFold}. */
    public static boolean equalsFolded(String left, String right) {

        return canonicalFold(left).equals(canonicalFold(right));
    }
}
