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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.sql.DataSource;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.WilmaAuthenticationContext;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.shared.annotation.constraint.NonNegative;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Constructs a new {@link WilmaAuthenticationContext} and attaches it to {@link AuthenticationContext}.
 */
public class InitializeDataSourceWilmaContext extends BaseInitializeWilmaContext {
    
    /** The database table name for Wilma authentication source settings. */
    public static final String TABLE_NAME_AUTH_SOURCES_WILMA = "mpass_authsources_wilma";

    /** The column id for technical identifier. */
    public static final String COLUMN_ID_TECH_ID = "techId";
    
    /** The column id for the Wilma's MPASS endpoint URL. */
    public static final String COLUMN_ID_MPASS_URL = "mpassUrl";
    
    /** The column id for the SAML authentication context class reference. */
    public static final String COLUMN_ID_SAML_CTX = "samlContextClassRef";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(InitializeDataSourceWilmaContext.class);
    
    /** A subordinate RequestedPrincipalContext, if any. */
    @Nullable private RequestedPrincipalContext requestedPrincipalCtx; 

    /** JDBC data source for retrieving connections for Wilma settings. */
    @NonnullAfterInit private DataSource dataSource;
    
    /** Number of times to retry a transaction if it rolls back. */
    @NonNegative private int transactionRetry;
    
    /** Error messages that signal a transaction should be retried. */
    @Nonnull @NonnullElements private Collection<String> retryableErrors;
    
    /** Authentication state map key name for the selected authentication detail. */
    @Nonnull @NotEmpty private String selectedAuthnStateKey;
    
    /**
     * Constructor, using a default MAC algorithm {@link WilmaAuthenticationContext.MAC_ALGORITHM}.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param wilmaDataSource The data source for the Wilma settings.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeDataSourceWilmaContext(final String sharedSecret, final DataSource wilmaDataSource)
            throws UnsupportedEncodingException {
        this(sharedSecret, wilmaDataSource, WilmaAuthenticationContext.MAC_ALGORITHM);
    }
    
    /**
     * Constructor.
     * @param sharedSecret The secret key used for calculating the checksum.
     * @param wilmaDataSource The data source for the Wilma settings.
     * @param macAlgorithm The algorithm used for calculating the checksum.
     * @throws UnsupportedEncodingException If the key cannot be constructed.
     */
    public InitializeDataSourceWilmaContext(final String sharedSecret, final DataSource wilmaDataSource, 
            final String macAlgorithm)
            throws UnsupportedEncodingException {
        super(sharedSecret, macAlgorithm);
        dataSource = Constraint.isNotNull(wilmaDataSource, "wilmaDataSource cannot be null");
    }
    
    /**
     * Set the authentication state map key name for the selected authentication detail.
     * @param keyName What to set.
     */
    public void setSelectedAuthnStateKey(final String keyName) {
        ifInitializedThrowUnmodifiabledComponentException();

        selectedAuthnStateKey = Constraint.isNotEmpty(keyName, "selectedAuthnStataKey cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        
        requestedPrincipalCtx = authenticationContext.getSubcontext(RequestedPrincipalContext.class);
        if (requestedPrincipalCtx != null) {
            if (requestedPrincipalCtx.getOperator() == null
                    || requestedPrincipalCtx.getRequestedPrincipals().isEmpty()) {
                requestedPrincipalCtx = null;
            }
        }
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final String discoveredWilma = 
                (String) authenticationContext.getAuthenticationStateMap().get(selectedAuthnStateKey);
        final String endpointUrl;
        if (StringSupport.trimOrNull(discoveredWilma) == null) {
            log.debug("{}: Could not find mapping from the state map, checking requested context.", getLogPrefix());
            final String contextClassRef = getAuthnContextClassRef();
            if (contextClassRef != null) {
                endpointUrl = getEndpointUrl(authenticationContext, COLUMN_ID_SAML_CTX + "='" + contextClassRef + "'");
            } else {
                endpointUrl = null;
            }
        } else {
            endpointUrl = getEndpointUrl(authenticationContext, COLUMN_ID_TECH_ID + "='" + discoveredWilma + "'");
        }
        if (StringSupport.trimOrNull(endpointUrl) == null) {
            log.warn("{}: Could not find a mapping for the Wilma instance.", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.RESELECT_FLOW);
            return;
        }
        createWilmaContext(authenticationContext, endpointUrl);
    }
    
    /**
     * Get the authentication context class reference, if single one exists.
     * @return The authentication context class reference if single exists, null otherwise. 
     */
    protected String getAuthnContextClassRef() {
        if (requestedPrincipalCtx != null) {
            int amount = requestedPrincipalCtx.getRequestedPrincipals().size();
            if (amount != 1) {
                log.warn("{}: Unsupported amount of requested principals found: {}", getLogPrefix(), amount);
                return null;
            } else {
                final String contextClassRef = requestedPrincipalCtx.getRequestedPrincipals().get(0).getName();
                log.debug("{}: Found authentication context class ref {}", getLogPrefix(), contextClassRef);
                return contextClassRef;
            }
        }
        return null;
    }
    
    /**
     * Initializes the {@link WilmaAuthenticationContext} and attaches it as a subcontext to the given
     * {@link AuthenticationContext}.
     * @param authenticationContext The authentication context.
     * @param endpointUrl The endpoint URL to be put to the Wilma authentication context.
     */
    protected void createWilmaContext(final AuthenticationContext authenticationContext, 
            @Nonnull @NotEmpty final String endpointUrl) {
        final WilmaAuthenticationContext wilmaContext =
                authenticationContext.ensureSubcontext(WilmaAuthenticationContext.class);
        final String nonce = getRandomNonce();
        wilmaContext.setNonce(nonce);
        wilmaContext.setRedirectUrl(endpointUrl);
        log.debug("{}: Added nonce {} and redirectUrl to context", getLogPrefix(), nonce);
    }
    
    /**
     * Get the single endpoint URL corresponding to the given WHERE-clause. The URL is only returned if a single
     * was found. Also its techId will be updated to the authentication state map, with the key configured to
     * this class instance.
     * @param authnContext The authentication context.
     * @param whereClause The WHERE-clause for searching the single instance.
     * @return The endpoint URL if single instance was found, null otherwise.
     */
    protected String getEndpointUrl(@Nonnull final AuthenticationContext authnContext, 
            @Nonnull @NotEmpty final String whereClause) {
        int retries = transactionRetry;
        log.debug("{}: The whereClause to be used: {}", getLogPrefix(), whereClause);
        try (final Connection connection = getConnection(false)) {
            final PreparedStatement getResults = connection.prepareStatement("SELECT " 
                    + COLUMN_ID_MPASS_URL + ", " + COLUMN_ID_TECH_ID + " from " 
                    + InitializeDataSourceWilmaContext.TABLE_NAME_AUTH_SOURCES_WILMA + " where " + whereClause);
            final ResultSet set = getResults.executeQuery();
            if (set.next()) {
                final String techId = set.getString(COLUMN_ID_TECH_ID);
                final String mpassUrl = set.getString(COLUMN_ID_MPASS_URL);
                if (set.next()) {
                    log.warn("{}: The whereClause {} did not give a single response", getLogPrefix(), whereClause);
                    return null;
                }
                authnContext.getAuthenticationStateMap().put(selectedAuthnStateKey, techId);                    
                return mpassUrl;
            }
            return null;
        } catch (final SQLException e) {
            boolean retry = shouldRetry(e, retries);
            if (retry) {
                retries = retries - 1;
                log.info("{} Retrying monitoring result storing operation", getLogPrefix());
            } else {
                log.warn("{} Retry limit exceeded, aborting.", getLogPrefix());
                return null;
            }
        }
        return null;
    }

    /**
     * Checks whether another attempt should be done after failed SQL event.
     * @param e The cause for the failed SQL event.
     * @param retries The amount of retries already run.
     * @return True if another attempt should be done, false otherwise.
     */
    protected boolean shouldRetry(final SQLException e, int retries) {
        boolean retry = false;
        if (retryableErrors != null) {
            for (final String msg : retryableErrors) {
                if (e.getSQLState() != null && e.getSQLState().contains(msg)) {
                    log.warn("{} Caught retryable SQL exception", getLogPrefix(), e);
                    retry = true;
                }
            }
        }
        if (retry) {
            if (retries - 1 < 0) {
                log.warn("{} Error retryable, but retry limit exceeded", getLogPrefix());
                return false;
            }
        } else {
            log.error("{} Caught SQL exception", getLogPrefix(), e);
            return false;
        }
        return true;
    }

    /**
     * Obtain a connection from the data source.
     * 
     * <p>The caller must close the connection.</p>
     * 
     * @param autoCommit auto-commit setting to apply to the connection
     * 
     * @return a fresh connection
     * @throws SQLException if an error occurs
     */
    @Nonnull private Connection getConnection(final boolean autoCommit) throws SQLException {
        final Connection conn = dataSource.getConnection();
        conn.setAutoCommit(autoCommit);
        conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        return conn;
    }
}