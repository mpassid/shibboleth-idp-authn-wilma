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

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;

/**
 * Constructs a new {@link WilmaAuthenticationContext} and attaches it to {@link AuthenticationContext}.
 */
@SuppressWarnings("rawtypes")
public class InitializeStaticWilmaContext extends BaseInitializeWilmaContext {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(InitializeStaticWilmaContext.class);

    /** The endpoint where the user is forwarded for authentication. */
    @Nonnull @NotEmpty private final String endpoint;

    /**
     * Constructor, using a default MAC algorithm {@link WilmaAuthenticationContext.MAC_ALGORITHM}.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param wilmaEndpoint The endpoint where the authentication request is sent.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeStaticWilmaContext(final String sharedSecret, final String wilmaEndpoint)
            throws UnsupportedEncodingException {
        this(sharedSecret, wilmaEndpoint, WilmaAuthenticationContext.MAC_ALGORITHM);
    }
    
    /**
     * Constructor.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param wilmaEndpoint The endpoint where the authentication request is sent.
     * @param macAlgorithm The algorithm used for calculating the checksum.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeStaticWilmaContext(final String sharedSecret, final String wilmaEndpoint, 
            final String macAlgorithm) throws UnsupportedEncodingException {
        super(sharedSecret, macAlgorithm);
        endpoint = Constraint.isNotEmpty(wilmaEndpoint, "wilmaEndpoint cannot be null!");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final WilmaAuthenticationContext wilmaContext =
                authenticationContext.getSubcontext(WilmaAuthenticationContext.class, true);
        final String nonce = getRandomNonce();
        wilmaContext.setNonce(nonce);
        wilmaContext.setRedirectUrl(endpoint);
        log.debug("{}: Added nonce {} and redirectUrl to context", getLogPrefix(), nonce);
    }
}
