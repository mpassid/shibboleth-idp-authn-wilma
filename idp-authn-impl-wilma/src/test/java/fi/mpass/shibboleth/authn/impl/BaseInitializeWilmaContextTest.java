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

import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.opensaml.profile.action.EventIds;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.testing.BaseAuthenticationContextTest;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.shared.component.ComponentInitializationException;

/**
 * Unit tests to be shared for classes extending {@link BaseInitializeWilmaContext}.
 */
public abstract class BaseInitializeWilmaContextTest extends BaseAuthenticationContextTest {

    /** The action to be tested. */
    InitializeStaticWilmaContext action;
    
    /** The shared secret for calculating the checksum. */
    String sharedSecret;
    
    /** {@inheritDoc} 
     * @throws ComponentInitializationException */
    @BeforeMethod public void setUp() throws ComponentInitializationException {
        initializeMembers();
        sharedSecret = "mockSharedSecret";
    }
    
    /**
     * Initializes the servlet request.
     * @return
     */
    protected MockHttpServletRequest initializeServletRequest() {
        final MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setScheme("https");
        servletRequest.setServerName("mock-proxy.mpass.id");
        servletRequest.setServerPort(443);
        servletRequest.setRequestURI("/idp/profile/SAML2/Redirect/SSO");
        servletRequest.setQueryString("execution=e1s1");
        return servletRequest;
    }

    /**
     * Runs action without attempted flow.
     */
    @Test public void testMissingFlow() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }
        
    /**
     * Runs action with minimum prerequisites met.
     * @throws Exception
     */
    @Test public void testSuccessNotForced() throws Exception {
        testSuccess(false);
    }

    /**
     * Runs action with prerequisites met & forced authentication required.
     * @throws Exception
     */
    @Test public void testSuccessForced() throws Exception {
        testSuccess(true);
    }
    
    /**
     * Runs action with prerequisites met.
     * @param forcedAuth
     * @throws Exception
     */
    protected void testSuccess(final boolean forcedAuth) throws Exception {
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).setForceAuthn(forcedAuth);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        final WilmaAuthenticationContext wilmaContext = authnContext.getSubcontext(WilmaAuthenticationContext.class, false);
        Assert.assertNotNull(wilmaContext);
        final String redirectUrl = action.getRedirect("execution=e1s1", authnContext);
        Assert.assertNotNull(redirectUrl);
        if (forcedAuth) {
            Assert.assertTrue(redirectUrl.contains(WilmaAuthenticationContext.PARAM_NAME_FORCE_AUTH + "=true"));
        }
        final int checksumIndex = redirectUrl.indexOf("&" + WilmaAuthenticationContext.PARAM_NAME_CHECKSUM + "=");
        final String urlWithoutChecksum = redirectUrl.substring(0, checksumIndex);
        final String checksum = redirectUrl.substring(checksumIndex + 3);
        Assert.assertNotNull(checksum);
        Assert.assertTrue(validateChecksum(urlWithoutChecksum, checksum));
        System.out.println(redirectUrl);
    }
    
    /**
     * Validates the checksum of the given url. 
     * @param url The source for the checksum validation.
     * @param checksum The checksum.
     * @return true if valid, false otherwise.
     * @throws Exception
     */
    protected boolean validateChecksum(final String url, final String checksum) throws Exception {
        SecretKey macKey = new SecretKeySpec(sharedSecret.getBytes("UTF-8"), WilmaAuthenticationContext.MAC_ALGORITHM);
        Mac mac = Mac.getInstance(WilmaAuthenticationContext.MAC_ALGORITHM);
        mac.init(macKey);
        byte[] digest = mac.doFinal(url.getBytes("UTF-8"));
        return Arrays.equals(Hex.decodeHex(checksum), digest);
    }

}
