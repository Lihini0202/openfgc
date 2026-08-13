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

package org.wso2.dpdp.accelerator.portal.webapp.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.wso2.dpdp.accelerator.portal.webapp.model.MaskToken;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates impersonation ("mask") tokens against the Identity Server's
 * published JWKS.
 *
 * <p>Discovery is performed lazily and retried on every call until it succeeds:
 * the Identity Server may start after this webapp, and refusing to serve without
 * it would make the whole portal depend on an integration only the nominee flow
 * needs. Until it succeeds every verification fails closed with
 * {@link VerifierUnavailableException}.
 */
public final class MaskTokenVerifier {

    /**
     * A token failed cryptographic or claim validation. The specific reason is
     * deliberately not carried to the caller — it is logged, never returned — so
     * a probing client cannot use error text to distinguish "bad signature" from
     * "wrong audience" from "expired".
     */
    public static class MaskUnverifiedException extends Exception {

        private static final long serialVersionUID = 1L;

        public MaskUnverifiedException(String message) {

            super(message);
        }
    }

    /**
     * The JWKS endpoint could not be reached. Distinct from
     * {@link MaskUnverifiedException} because it maps to 502, not 401: the token
     * may well be valid, we simply cannot check it right now. Never treated as
     * permission to proceed.
     */
    public static class VerifierUnavailableException extends Exception {

        private static final long serialVersionUID = 1L;

        public VerifierUnavailableException(String message, Throwable cause) {

            super(message, cause);
        }

        public VerifierUnavailableException(String message) {

            super(message);
        }
    }

    private static volatile MaskTokenVerifier instance;

    private final PortalConfig config;
    private final Object lock = new Object();
    private ConfigurableJWTProcessor<SecurityContext> processor;

    private MaskTokenVerifier(PortalConfig config) {

        this.config = config;
    }

    public static MaskTokenVerifier getInstance(PortalConfig config) {

        if (instance == null) {
            synchronized (MaskTokenVerifier.class) {
                if (instance == null) {
                    instance = new MaskTokenVerifier(config);
                }
            }
        }
        return instance;
    }

    private ConfigurableJWTProcessor<SecurityContext> resolve() throws VerifierUnavailableException {

        synchronized (lock) {
            if (processor != null) {
                return processor;
            }
            try {
                URL jwksUrl = new URL(config.getIdentityServerInternalBaseUrl() + "/oauth2/jwks");
                JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksUrl);
                ConfigurableJWTProcessor<SecurityContext> built = new DefaultJWTProcessor<>();
                // The Identity Server issues RFC 9068 access tokens typed
                // "at+jwt"; the Nimbus default accepts only "JWT" or no type.
                built.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                        new JOSEObjectType("at+jwt"), JOSEObjectType.JWT, null));
                built.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource));

                // Pinned issuer: a valid signature alone says only that some key
                // in the configured JWKS signed this, not that the token was
                // minted for this deployment.
                String issuer = config.getExpectedIssuer();
                JWTClaimsSet exactMatch = issuer == null || issuer.isEmpty()
                        ? null : new JWTClaimsSet.Builder().issuer(issuer).build();
                String audience = config.getMaskAudience();
                if (audience != null && !audience.isEmpty()) {
                    built.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                            audience, exactMatch, Set.of("sub", "exp")));
                } else {
                    // An unset audience means the deployment has not told us what
                    // to expect. Skipping that check is the only option, and it is
                    // a real weakening - the issuer pin below is what still ties
                    // the token to this deployment.
                    built.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                            (Set<String>) null, exactMatch, Set.of("sub", "exp"), null));
                }
                processor = built;
                return processor;
            } catch (MalformedURLException e) {
                throw new VerifierUnavailableException("Invalid JWKS URL for mask token verification", e);
            }
        }
    }

    /**
     * Authenticates a raw mask token and returns its verified claims.
     *
     * <p>Validated here: signature against the Identity Server's JWKS, audience
     * and expiry, plus the presence of both {@code sub} and a delegation claim
     * ({@code act} or {@code may_act}). A token carrying neither is not an
     * impersonation token and is rejected outright — it is never treated as an
     * ordinary token belonging to {@code sub}, which would silently hand the
     * caller the owner's whole account.
     */
    public MaskToken verify(String raw) throws MaskUnverifiedException, VerifierUnavailableException {

        String token = raw == null ? "" : raw.trim();
        if (token.isEmpty()) {
            throw new MaskUnverifiedException("empty mask token");
        }

        JWTClaimsSet claims;
        try {
            claims = resolve().process(token, null);
        } catch (VerifierUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new MaskUnverifiedException("mask token failed verification");
        }

        String owner = claims.getSubject() == null ? "" : claims.getSubject().trim();
        if (owner.isEmpty()) {
            throw new MaskUnverifiedException("mask token carries no subject");
        }

        String nominee = delegatedActor(claims);
        if (nominee.isEmpty()) {
            throw new MaskUnverifiedException("mask token carries no delegation claim");
        }
        // An owner acting "for themselves" through the impersonation path is
        // either a misconfiguration or an attempt to launder a normal token into
        // an acting one. Neither should reach a handler.
        if (nominee.equals(owner)) {
            throw new MaskUnverifiedException("mask token names the owner as its own actor");
        }

        Date expiry = claims.getExpirationTime();
        return new MaskToken(owner, nominee, parseScopeClaim(claims.getClaim("scope")),
                expiry == null ? Instant.EPOCH : expiry.toInstant(),
                stringClaim(claims, "org_id"));
    }

    /**
     * Reads the delegated actor from whichever claim the Identity Server
     * populated.
     *
     * <p>{@code may_act} appears on the subject token ("this actor MAY act as
     * sub"); {@code act} appears on the exchanged access token ("this actor DID
     * act as sub"). Either identifies the same nominee, and either is sufficient
     * evidence that the Identity Server authorised the delegation.
     */
    private static String delegatedActor(JWTClaimsSet claims) {

        String act = nestedSub(claims.getClaim("act"));
        return act.isEmpty() ? nestedSub(claims.getClaim("may_act")) : act;
    }

    private static String nestedSub(Object claim) {

        if (claim instanceof Map) {
            Object sub = ((Map<?, ?>) claim).get("sub");
            if (sub instanceof String) {
                return ((String) sub).trim();
            }
        }
        return "";
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {

        Object value = claims.getClaim(name);
        return value instanceof String ? ((String) value).trim() : "";
    }

    /**
     * Accepts both encodings the Identity Server may emit: a space-delimited
     * string or a JSON array of strings.
     */
    static Set<String> parseScopeClaim(Object raw) {

        Set<String> scopes = new LinkedHashSet<>();
        if (raw instanceof String) {
            for (String scope : ((String) raw).trim().split("\\s+")) {
                if (!scope.isEmpty()) {
                    scopes.add(scope);
                }
            }
        } else if (raw instanceof List) {
            for (Object entry : (List<?>) raw) {
                if (entry instanceof String && !((String) entry).trim().isEmpty()) {
                    scopes.add(((String) entry).trim());
                }
            }
        }
        return Collections.unmodifiableSet(scopes);
    }
}
