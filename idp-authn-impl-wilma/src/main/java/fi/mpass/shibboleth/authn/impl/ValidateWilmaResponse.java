/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.mpass.shibboleth.authn.impl;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Validates the Wilma authentication response.
 */
public class ValidateWilmaResponse extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateWilmaResponse.class);

    /** The key used for validating the response. */
    @Nonnull private final SecretKey macKey;

    /** The MAC algorithm to be used for the response validation. */
    @Nonnull @NotEmpty private final String algorithm;

    /**
     * Constructor.
     * @param sharedSecret The secret used for the validation.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public ValidateWilmaResponse(final String sharedSecret) throws UnsupportedEncodingException {
        this(sharedSecret, WilmaAuthenticationContext.MAC_ALGORITHM);
    }

    /**
     * Constructor.
     * @param sharedSecret The secret used for the validation.
     * @param macAlgorithm The MAC algorithm used for the validation.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public ValidateWilmaResponse(final String sharedSecret, final String macAlgorithm)
            throws UnsupportedEncodingException {
        super();
        algorithm = Constraint.isNotEmpty(macAlgorithm, "macAlgorithm cannot be null!");
        macKey = new SecretKeySpec(sharedSecret.getBytes("UTF-8"), algorithm);
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        log.trace("{}: Prerequisities fulfilled to start doPreExecute", getLogPrefix());

        final HttpServletRequest servletRequest = getHttpServletRequest();
        if (servletRequest == null) {
            log.error("{}: No HttpServletRequst available within profile context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_USER_ID) == null) {
            log.warn("{}: No user id available in the request with parameter {}", getLogPrefix(),
                    WilmaAuthenticationContext.PARAM_NAME_USER_ID);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_NONCE) == null) {
            log.warn("{}: No nonce available in the request with parameter {}", getLogPrefix(),
                    WilmaAuthenticationContext.PARAM_NAME_NONCE);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_CHECKSUM) == null) {
            log.warn("{}: No checksum available in the request with parameter {}", getLogPrefix(),
                    WilmaAuthenticationContext.PARAM_NAME_CHECKSUM);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (authenticationContext.getSubcontext(WilmaAuthenticationContext.class) == null) {
            log.warn("{}: No WilmaAuthenticationContext available in the context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        log.trace("{}: doPreExecute returning true", getLogPrefix());
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final HttpServletRequest servletRequest = getHttpServletRequest();
        final WilmaAuthenticationContext wilmaContext =
                authenticationContext.getSubcontext(WilmaAuthenticationContext.class);
        final String nonce = wilmaContext.getNonce();
        if (!getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_NONCE).equals(nonce)) {
            log.warn("{}: Invalid nonce in the incoming Wilma response!", getLogPrefix());
            log.debug("{} vs {}", nonce, getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_NONCE));
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        final String checksum = getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_CHECKSUM);
        final String query = servletRequest.getQueryString().substring(0,
                servletRequest.getQueryString().indexOf("&" + WilmaAuthenticationContext.PARAM_NAME_CHECKSUM + "="));
        final String url = servletRequest.getRequestURL().append("?").append(query).toString();
        try {
            final Mac mac = Mac.getInstance(algorithm);
            mac.init(macKey);
            byte[] digest = mac.doFinal(url.getBytes("UTF-8"));
            if (!Arrays.equals(Hex.decodeHex(checksum), digest)) {
                log.warn("{}: The checksum validation failed for user {}", getLogPrefix(),
                        getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_USER_ID));
                log.trace("{} (params) vs {}", checksum, new String(Hex.encodeHex(digest)));
                handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                        AuthnEventIds.NO_CREDENTIALS);
                return;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException | UnsupportedEncodingException
                | IllegalArgumentException | DecoderException e) {
            log.error("{}: Could not verify the checksum {}", getLogPrefix(), checksum, e);
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        log.trace("{}: Building authentication result for user {}", getLogPrefix(),
                getQueryParam(servletRequest, WilmaAuthenticationContext.PARAM_NAME_USER_ID));
        buildAuthenticationResult(profileRequestContext, authenticationContext);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(
                String.valueOf(getQueryParam(getHttpServletRequest(), WilmaAuthenticationContext.PARAM_NAME_USER_ID))));
        log.trace("{}: Subject successfully populated", getLogPrefix());
        return subject;
    }

    /**
     * Returns the given parameter from the query.
     * @param servletRequest The request containing the query.
     * @param paramName The parameter whose value is to be returned.
     * @return The value for the parameter, or null if it does not exist.
     */
    protected String getQueryParam(final HttpServletRequest servletRequest, final String paramName) {
        final String query = servletRequest.getQueryString();
        if (query.indexOf(paramName + "=") != -1) {
            final String cut = query.substring(query.indexOf(paramName + "=") + paramName.length() + 1);
            if (cut.indexOf("&") > 0) {
                return StringSupport.trimOrNull(cut.substring(0, cut.indexOf("&")));
            } else {
                return StringSupport.trimOrNull(cut);
            }
        }
        return null;
    }
}
