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

import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.impl.InitializeStaticWilmaContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * Unit tests for {@link InitializeStaticWilmaContext}.
 */
public class InitializeStaticWilmaContextTest extends BaseInitializeWilmaContextTest {
    
    /** The endpoint where to send authentication request. */
    String wilmaEndpoint;

    /** {@inheritDoc} */
    @BeforeMethod public void setUp() throws Exception {
        super.setUp();
        wilmaEndpoint = "https://wilma.example.org/mpass";
        action = new InitializeStaticWilmaContext(sharedSecret, wilmaEndpoint);        
        action.setHttpServletRequest(initializeServletRequest());
    }
    
    /**
     * Runs action with invalid MAC algorithm.
     */
    @Test public void testInvalidAlgorithm() throws Exception {
        action = new InitializeStaticWilmaContext(sharedSecret, wilmaEndpoint, "InvalidAlgorithm");
        action.setHttpServletRequest(initializeServletRequest());
        action.initialize();
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        authnContext.setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        Assert.assertNull(event);
        Assert.assertNull(action.getRedirect("?mock=mock", authnContext));
    }
}
