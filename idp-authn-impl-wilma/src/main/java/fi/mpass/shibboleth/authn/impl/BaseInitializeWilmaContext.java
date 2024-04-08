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

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.lang3.RandomStringUtils;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;

/**
 * Base class for constructing a new {@link WilmaAuthenticationContext} and attaching it to 
 * {@link AuthenticationContext}.
 */
@SuppressWarnings("rawtypes")
public abstract class BaseInitializeWilmaContext extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BaseInitializeWilmaContext.class);
    
    /** The secret key used for calculating the checksum. */
    @Nonnull private final SecretKeySpec signatureKey;

    /** The algorithm used for calculating the checksum. */
    @Nonnull @NotEmpty private final String algorithm;

    /**
     * Constructor.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param macAlgorithm The algorithm used for calculating the checksum.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public BaseInitializeWilmaContext(final String sharedSecret, final String macAlgorithm)
            throws UnsupportedEncodingException {
        Constraint.isNotEmpty(sharedSecret, "sharedSecret cannot be null!");
        algorithm = Constraint.isNotEmpty(macAlgorithm, "macAlgorithm cannot be null!");
        signatureKey = new SecretKeySpec(sharedSecret.getBytes("UTF-8"), algorithm);
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        if (authenticationContext.getAttemptedFlow() == null) {
            log.info("{} No attempted flow within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }
    
    /**
     * Constructs an URL where the user is redirected for authentication.
     * @param flowExecutionUrl The current flow execution URL, to be included in the redirect URL.
     * @param authenticationContext The context, also containing {@link WilmaAuthenticationContext}.
     * @return The redirect URL containing the checksum.
     */
    public String getRedirect(final String flowExecutionUrl, 
            final AuthenticationContext authenticationContext) {
        final HttpServletRequest httpRequest = getHttpServletRequest();
        final WilmaAuthenticationContext wilmaContext = 
                authenticationContext.getSubcontext(WilmaAuthenticationContext.class);
        final StringBuffer redirectToBuffer = new StringBuffer(httpRequest.getScheme() + "://" 
                + httpRequest.getServerName());
        if (httpRequest.getServerPort() != 443) {
            redirectToBuffer.append(":" + httpRequest.getServerPort());
        }
        redirectToBuffer.append(flowExecutionUrl).append(getAsParameter("&", "_eventId_proceed", "1"));
        redirectToBuffer.append(getAsParameter("&", WilmaAuthenticationContext.PARAM_NAME_NONCE, 
                wilmaContext.getNonce()));
        final URLCodec urlCodec = new URLCodec();
        try {
            final StringBuffer unsignedUrlBuffer = new StringBuffer(wilmaContext.getRedirectUrl());
            unsignedUrlBuffer.append(getAsParameter("?", WilmaAuthenticationContext.PARAM_NAME_REDIRECT_TO, 
                    urlCodec.encode(redirectToBuffer.toString())));
            if (authenticationContext.isForceAuthn()) {
                unsignedUrlBuffer.append(getAsParameter("&", WilmaAuthenticationContext.PARAM_NAME_FORCE_AUTH, "true"));
            }
            final String redirectUrl = unsignedUrlBuffer.toString() + getAsParameter("&", 
                    WilmaAuthenticationContext.PARAM_NAME_CHECKSUM,
                    calculateChecksum(Mac.getInstance(algorithm), unsignedUrlBuffer.toString(), signatureKey));
            return redirectUrl;
        } catch (EncoderException | NoSuchAlgorithmException e) {
            log.error("{}: Could not encode the following URL {}", getLogPrefix(), redirectToBuffer, e);
        }
        return null;    
    }

    /**
     * Constructs the parameter name and value with the given divider.
     * @param divider The divider to the other parameters in the URL.
     * @param name The name of the parameter.
     * @param value The value of the parameter.
     * @return The parameter and value in query fraction.
     */
    protected static String getAsParameter(final String divider, final String name, final String value) {
        return divider + name + "=" + value;
    }

    /**
     * Calculates the checksum for the given string, using the given Mac instance and secret key.
     * @param mac The Mac instance.
     * @param string The seed.
     * @param key The secret key used for calculating the checksum.
     * @return The checksum value.
     */
    public static String calculateChecksum(final Mac mac, final String string, final SecretKey key) {
        try {
            mac.init(key);
            final byte[] bytes = mac.doFinal(string.getBytes("UTF-8"));
            return new String(Hex.encodeHex(bytes));
        } catch (InvalidKeyException | UnsupportedEncodingException e) {
            LoggerFactory.getLogger(InitializeStaticWilmaContext.class).
                error("Could not sign the input data {} with the key", string);
        }
        return null;
    }
    
    /**
     * Calculates a random nonce to be used in the communication with a Wilma instance.
     * @return A random alphanumeric 24-digit nonce.
     */
    protected static String getRandomNonce() {
        return RandomStringUtils.randomAlphanumeric(24);
    }
}