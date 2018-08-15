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

import java.util.Set;

import javax.security.auth.Subject;

import org.opensaml.profile.action.EventIds;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import fi.mpass.shibboleth.authn.impl.ValidateWilmaResponse;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateWilmaResponse}.
 */
public class ValidateWilmaResponseTest extends PopulateAuthenticationContextTest {

    /** The action to be tested. */
    private ValidateWilmaResponse action;

    /** The shared used for validating the response. */
    private String sharedSecret;

    /** The nonce in the response. */
    private String nonce;

    /** The authenticated user id in the response. */
    private String userid;

    /** The checksum in the response. */
    private String checksum;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        sharedSecret = "mockSharedSecret";
        nonce = "GILQC3JEqPf9rAnzIZJ6yy8b";
        userid = "6982e3763b008a87c2f91724ade223e27c7b4c2067fdd0fd5e3a01910f38be17";
        checksum = "2e5c07e73f9ac9977c3fda09ba779ce39205573596eed15039cdd6965f621a9d";
        action = new ValidateWilmaResponse(sharedSecret);
        action.setHttpServletRequest(initializeServletRequest(true, true, true));
    }

    /**
     * Initialize the servlet request for testing.
     * 
     * @param addNonce Whether or not to include nonce
     * @param addUserid Whether or not to include userid
     * @param addChecksum Whether or not to include checksum
     * @return
     */
    protected MockHttpServletRequest initializeServletRequest(final boolean addNonce, final boolean addUserid,
            final boolean addChecksum) {
        final MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setScheme("https");
        servletRequest.setServerName("mock-proxy.mpass.id");
        servletRequest.setServerPort(443);
        servletRequest.setRequestURI("/idp/profile/SAML2/Redirect/SSO");
        servletRequest.setQueryString(generateQuery(addNonce, addUserid, addChecksum));
        return servletRequest;
    }

    /**
     * Generate query to the servlet request.
     * 
     * @param addNonce Whether or not to include nonce
     * @param addUserid Whether or not to include userid
     * @param addChecksum Whether or not to include checksum
     * @return
     */
    protected String generateQuery(final boolean addNonce, final boolean addUserid, final boolean addChecksum) {
        final StringBuffer query = new StringBuffer("execution=e1s1");
        if (addNonce) {
            query.append("&" + WilmaAuthenticationContext.PARAM_NAME_NONCE + "=" + nonce);
        }
        if (addUserid) {
            query.append("&" + WilmaAuthenticationContext.PARAM_NAME_USER_ID + "=" + userid);
        }
        if (addChecksum) {
            query.append("&" + WilmaAuthenticationContext.PARAM_NAME_CHECKSUM + "=" + checksum);
        }
        return query.toString();
    }

    /**
     * Test without flow defined.
     * @throws Exception
     */
    @Test
    protected void testNoFlow() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without servlet request attached.
     * @throws Exception
     */
    @Test
    protected void testNoServlet() throws Exception {
        action.setHttpServletRequest(null);
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getSubcontext(WilmaAuthenticationContext.class, true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without {@link WilmaAuthenticationContext} attached.
     * @throws Exception
     */
    @Test
    protected void testNoWilmaContext() throws Exception {
        action.setHttpServletRequest(initializeServletRequest(true, true, true));
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without nonce included in the response.
     * @throws Exception
     */
    @Test
    protected void testNoNonce() throws Exception {
        action.setHttpServletRequest(initializeServletRequest(false, true, true));
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getSubcontext(WilmaAuthenticationContext.class, true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without userid included in the response.
     * @throws Exception
     */
    @Test
    protected void testNoUserid() throws Exception {
        action.setHttpServletRequest(initializeServletRequest(true, false, true));
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getSubcontext(WilmaAuthenticationContext.class, true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without checksum included in the response.
     * @throws Exception
     */
    @Test
    protected void testNoChecksum() throws Exception {
        action.setHttpServletRequest(initializeServletRequest(true, true, false));
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getSubcontext(WilmaAuthenticationContext.class, true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test without nonce included in the {@link WilmaAuthenticationContext}.
     * @throws Exception
     */
    @Test
    protected void testNoNonceInContext() throws Exception {
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getSubcontext(WilmaAuthenticationContext.class, true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Test with invalid checksum format.
     * @throws Exception
     */
    @Test
    protected void testInvalidChecksumFormat() throws Exception {
        MockHttpServletRequest servletRequest = initializeServletRequest(true, true, true);
        servletRequest.setQueryString(servletRequest.getQueryString() + "invalid");
        action.setHttpServletRequest(servletRequest);
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final WilmaAuthenticationContext wilmaContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(WilmaAuthenticationContext.class, true);
        wilmaContext.setNonce(nonce);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Test with invalid checksum.
     * @throws Exception
     */
    @Test
    protected void testInvalidChecksum() throws Exception {
        MockHttpServletRequest servletRequest = initializeServletRequest(true, true, true);
        final String query = servletRequest.getQueryString();
        servletRequest.setQueryString(query.substring(0, query.length() - 2) + "11");
        action.setHttpServletRequest(servletRequest);
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final WilmaAuthenticationContext wilmaContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(WilmaAuthenticationContext.class, true);
        wilmaContext.setNonce(nonce);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Test with valid response.
     * @throws Exception
     */
    @Test
    protected void testSuccess() throws Exception {
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final WilmaAuthenticationContext wilmaContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(WilmaAuthenticationContext.class, true);
        wilmaContext.setNonce(nonce);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final Subject subject = prc.getSubcontext(AuthenticationContext.class, false).getAuthenticationResult().getSubject();
        Assert.assertNotNull(subject);
        Set<UsernamePrincipal> principals = subject.getPrincipals(UsernamePrincipal.class);
        Assert.assertEquals(principals.size(), 1);
        Assert.assertEquals(principals.iterator().next().getName(), userid);
    }
}