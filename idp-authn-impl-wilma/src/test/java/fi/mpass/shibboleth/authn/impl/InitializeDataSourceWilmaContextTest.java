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
import java.security.Principal;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Arrays;

import javax.sql.DataSource;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.impl.testing.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.testing.TestPrincipal;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.shared.testing.DatabaseTestingSupport;
import net.shibboleth.shared.component.ComponentInitializationException;

/**
 * Unit tests for {@link InitializeDataSourceWilmaContext}.
 */
public class InitializeDataSourceWilmaContextTest extends BaseAuthenticationContextTest {

    /** The action to be tested. */
    private InitializeDataSourceWilmaContext action;
    
    /** The datasource used for storing monitoring results. */
    protected DataSource dataSource;
    
    /** The shared secret for calculating the checksum. */
    private String sharedSecret;
    
    private String techId1;
    private String redirectUrl1;
    private String contextClassRef1;
    private String selectedStateKey;

    /** {@inheritDoc} 
     * @throws ComponentInitializationException */
	@BeforeMethod
	public void setUp() throws ComponentInitializationException {
        super.setUp();
        sharedSecret = "mockSharedSecret";
        techId1 = "mockTechId";
        redirectUrl1 = "https://wilma.example.org/mpass";
        contextClassRef1 = "urn:mpass.id:fi:wilma:mock1";
        selectedStateKey = "mockSelectedStateKey";
        dataSource = DatabaseTestingSupport.
                GetMockDataSource("/fi/mpass/shibboleth/storage/AuthSourceStore.sql", 
                        "AuthSourceStore");

		try {
			populateDatabase();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		try {
			action = new InitializeDataSourceWilmaContext(sharedSecret, dataSource);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        action.setSelectedAuthnStateKey(selectedStateKey);
        action.initialize();
    }
    
    /**
     * Empties the database.
     */
    @AfterMethod
    public void tearDown() {
        DatabaseTestingSupport.InitializeDataSource("/fi/mpass/shibboleth/storage/DeleteStore.sql", dataSource);
    }

    @Test
    public void testNoMapping() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        ActionTestingSupport.assertEvent(action.execute(src), AuthnEventIds.RESELECT_FLOW);
    }
    
    @Test
    public void testInvalidState() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).getAuthenticationStateMap().put(selectedStateKey, "invalid");
        ActionTestingSupport.assertEvent(action.execute(src), AuthnEventIds.RESELECT_FLOW);
    }

    @Test
    public void testValidState() throws Exception {
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        authnContext.setAttemptedFlow(authenticationFlows.get(0));
        authnContext.getAuthenticationStateMap().put(selectedStateKey, techId1);
        Assert.assertNull(action.execute(src));
        final WilmaAuthenticationContext wilmaContext = authnContext.getSubcontext(WilmaAuthenticationContext.class);
        Assert.assertEquals(wilmaContext.getRedirectUrl(), redirectUrl1);
    }

    @Test
    public void testInvalidContextRef() throws Exception {
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        authnContext.setAttemptedFlow(authenticationFlows.get(0));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(Arrays.<Principal>asList(new TestPrincipal("invalid")));
        authnContext.addSubcontext(rpc, true);
        ActionTestingSupport.assertEvent(action.execute(src), AuthnEventIds.RESELECT_FLOW);
    }

    @Test
    public void testValidContextRef() throws Exception {
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        authnContext.setAttemptedFlow(authenticationFlows.get(0));
        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(Arrays.<Principal>asList(new TestPrincipal(contextClassRef1)));
        authnContext.addSubcontext(rpc, true);
        Assert.assertNull(action.execute(src));
        final WilmaAuthenticationContext wilmaContext = authnContext.getSubcontext(WilmaAuthenticationContext.class);
        Assert.assertEquals(wilmaContext.getRedirectUrl(), redirectUrl1);
    }
    
    public void populateDatabase() throws Exception {
        final String insertResult = "INSERT INTO " + InitializeDataSourceWilmaContext.TABLE_NAME_AUTH_SOURCES_WILMA + 
                " (techId, description, discoName, discoLogoUrl, discoStyle, mpassUrl, samlContextClassRef, startTime) VALUES (?,?,?,?,?,?,?,?);";
        final PreparedStatement statement = dataSource.getConnection().prepareStatement(insertResult);
        statement.setString(1, techId1);
        statement.setString(2, "Wilma testing");
        statement.setString(3, "Test Wilma");
        statement.setString(4, "mockLogoUrl");
        statement.setString(5, "mockStyle");
        statement.setString(6, redirectUrl1);
        statement.setString(7, contextClassRef1);
        statement.setTimestamp(8, new Timestamp(System.currentTimeMillis()));
        statement.executeUpdate();

    }

}
