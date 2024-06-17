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

package fi.mpass.shibboleth.authn.context;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

/**
 * This context stores attributes required for creating an authentication
 * request to a Wilma instance and for validating the response from there.
 */
public class WilmaAuthenticationContext extends BaseContext {

    /** The default MAC algorithm. */
    public static final String MAC_ALGORITHM = "HmacSHA256";

    /** The parameter name for redirectto. */
    public static final String PARAM_NAME_REDIRECT_TO = "redirectto";

    /** The parameter name for nonce. */
    public static final String PARAM_NAME_NONCE = "nonce";

    /** The parameter name for forceauth. */
    public static final String PARAM_NAME_FORCE_AUTH = "forceauth";

    /** The parameter name for checksum. */
    public static final String PARAM_NAME_CHECKSUM = "h";

    /** The parameter name for userid. */
    public static final String PARAM_NAME_USER_ID = "userid";

    /** The nonce included to the redirect URL. */
    @Nonnull @NotEmpty private String nonce;

    /** The base URL where the user is redirected for authentication. */
    @Nonnull @NotEmpty private String redirectUrl;

    /**
     * Get the nonce included to the redirect URL.
     * 
     * @return nonce
     */
    @Nonnull @NotEmpty public String getNonce() {
        return nonce;
    }

    /**
     * Set the nonce included to the redirect URL.
     * 
     * @param nonceParameter What to set.
     * @return nonce
     */
    @Nonnull @NotEmpty public String setNonce(@Nonnull @NotEmpty final String nonceParameter) {
        nonce = nonceParameter;
        return nonce;
    }

    /**
     * Get the base URL where the user is redirected for authentication.
     * 
     * @return redirectUrl the base URL where the user is redirected for authentication.
     */
    @Nonnull @NotEmpty public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Set the base URL where the user is redirected for authentication.
     * 
     * @param newRedirectUrl What to set.
     * @return redirectUrl
     */
    @Nonnull @NotEmpty public String setRedirectUrl(@Nonnull @NotEmpty final String newRedirectUrl) {
        redirectUrl = newRedirectUrl;
        return redirectUrl;
    }
}
