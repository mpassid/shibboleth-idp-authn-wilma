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
import java.util.function.Function;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;

/**
 * Constructs a new {@link WilmaAuthenticationContext} and attaches it to {@link AuthenticationContext}.
 */
public class InitializeWilmaContext extends BaseInitializeWilmaContext {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(InitializeWilmaContext.class);

    /** The lookup strategy for endpoint where the authentication is forwarded to. */
    @NonnullAfterInit private Function<ProfileRequestContext,String> endpointLookupStrategy;

    /**
     * Constructor, using a default MAC algorithm {@link WilmaAuthenticationContext.MAC_ALGORITHM}.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeWilmaContext(final String sharedSecret)
            throws UnsupportedEncodingException {
        this(sharedSecret, WilmaAuthenticationContext.MAC_ALGORITHM);
    }
    
    /**
     * Constructor.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param macAlgorithm The algorithm used for calculating the checksum.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeWilmaContext(final String sharedSecret, final String macAlgorithm)
            throws UnsupportedEncodingException {
        super(sharedSecret, macAlgorithm);
    }

    /**
     * Set the lookup strategy for endpoint where the authentication is forwarded to
     * 
     * @param strategy lookup strategy
     */
    public void setEndpointLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        checkSetterPreconditions();
        endpointLookupStrategy = Constraint.isNotNull(strategy, "EndpointLookupStrategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (endpointLookupStrategy == null) {
            throw new ComponentInitializationException("EndpointLookupStrategy cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final WilmaAuthenticationContext wilmaContext =
                authenticationContext.ensureSubcontext(WilmaAuthenticationContext.class);
        final String nonce = getRandomNonce();
        final String endpoint = endpointLookupStrategy.apply(profileRequestContext);
        if (endpoint == null) {
            log.error("{} Could not resolve endpoint to be used", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_POTENTIAL_FLOW);
            return;
        }
        wilmaContext.setNonce(nonce);
        wilmaContext.setRedirectUrl(endpoint);
        log.debug("{}: Added nonce {} and redirectUrl to context", getLogPrefix(), nonce);
    }
}
