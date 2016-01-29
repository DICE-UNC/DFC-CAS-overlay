/**
 * 
 */
package org.irods.de.cas.ldap;


import com.google.common.base.Functions;
import com.google.common.collect.Maps;

import org.jasig.cas.MessageDescriptor;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.support.LdapPasswordPolicyConfiguration;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.AuthenticationResultCode;
import org.ldaptive.auth.Authenticator;

import javax.annotation.PostConstruct;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.validation.constraints.NotNull;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author mconway
 *
 */
public class LabLdapAuthenticationHandler extends
		AbstractUsernamePasswordAuthenticationHandler {
	
	   /** Mapping of LDAP attribute name to principal attribute name. */
    @NotNull
    protected Map<String, String> principalAttributeMap = Collections.emptyMap();

    /** List of additional attributes to be fetched but are not principal attributes. */
    @NotNull
    protected List<String> additionalAttributes = Collections.emptyList();
    
    /**
     * Performs LDAP authentication given username/password.
     **/
    @NotNull
    private final Authenticator authenticator;


  
    /** Component name. */
    @NotNull
    private String name = LabLdapAuthenticationHandler.class.getSimpleName();

    /** Name of attribute to be used for resolved principal. */
    private String principalIdAttribute;

    /** Flag indicating whether multiple values are allowed fo principalIdAttribute. */
    private boolean allowMultiplePrincipalAttributeValues;

    /** Set of LDAP attributes fetch from an entry as part of the authentication process. */
    private String[] authenticatedEntryAttributes = ReturnAttributes.ALL.value();
    
    /**
     * Creates a new authentication handler that delegates to the given authenticator.
     *
     * @param  authenticator  Ldaptive authenticator component.
     */
    public LabLdapAuthenticationHandler(@NotNull final Authenticator authenticator) {
        this.authenticator = authenticator;
    }


	/* (non-Javadoc)
	 * @see org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler#authenticateUsernamePasswordInternal(org.jasig.cas.authentication.UsernamePasswordCredential)
	 */
	@Override
	protected HandlerResult authenticateUsernamePasswordInternal(
			UsernamePasswordCredential upc) throws GeneralSecurityException,
			PreventedException {
		 final AuthenticationResponse response;
	        try {
	            logger.debug("DFCAttempting LDAP authentication for {}", upc);
	            final String password = getPasswordEncoder().encode(upc.getPassword());
	            final AuthenticationRequest request = new AuthenticationRequest(upc.getUsername(),
	                    new org.ldaptive.Credential(password),
	                    this.authenticatedEntryAttributes);
	            logger.debug("DFCcalling authenticatorAuthenticate:{}", request);
	            response = this.authenticator.authenticate(request);
	        } catch (final LdapException e) {
	        	logger.error("unexpectedLDAPError", e);
	            throw new PreventedException("Unexpected LDAP error", e);
	        }
	        logger.debug("LDAP response: {}", response);

	        final List<MessageDescriptor> messageList;
	        logger.info("DFC LOGGING: Before LdapPolicyConfiguration");
	        
	        final LdapPasswordPolicyConfiguration ldapPasswordPolicyConfiguration =
	                (LdapPasswordPolicyConfiguration) super.getPasswordPolicyConfiguration();
	        logger.info("DFC LOGGING: After LdapPolicyConfiguration");
	        logger.debug("ldapPasswordPolicyConfiguration:{}", ldapPasswordPolicyConfiguration);
	        if (ldapPasswordPolicyConfiguration != null) {
	            logger.debug("Applying password policy to {}", response);
	            messageList = ldapPasswordPolicyConfiguration.getAccountStateHandler().handle(
	                    response, ldapPasswordPolicyConfiguration);
	        } else {
	            messageList = Collections.emptyList();
	        }
	        logger.info("DFC LOGGING: Before response.getResult");
	        if (response.getResult()) {
	        	logger.info("DFC LOGGING: Before returning createHandlerResult");
	        	logger.debug("upc:{}", upc);
	        	logger.debug("principal from user name:{}", upc.getUsername());
	        	logger.debug("response ldap entry:{}", response.getLdapEntry());
	        	HandlerResult handlerResult = createHandlerResult(upc, createPrincipal(upc.getUsername(), response.getLdapEntry()), messageList);
	        	logger.debug("DFC HandlerResult:{}", handlerResult);
	        	return handlerResult;
	        }
	        logger.info("DFC LOGGING: After response.getResult");

	        if (AuthenticationResultCode.DN_RESOLUTION_FAILURE == response.getAuthenticationResultCode()) {
	            throw new AccountNotFoundException(upc.getUsername() + " not found.");
	        }
	        throw new FailedLoginException("Invalid credentials");
	}
	
	 /**
     * Creates a CAS principal with attributes if the LDAP entry contains principal attributes.
     *
     * @param username Username that was successfully authenticated which is used for principal ID when
     *                 {@link #setPrincipalIdAttribute(String)} is not specified.
     * @param ldapEntry LDAP entry that may contain principal attributes.
     *
     * @return Principal if the LDAP entry contains at least a principal ID attribute value, null otherwise.
     *
     * @throws LoginException On security policy errors related to principal creation.
     */
    protected Principal createPrincipal(final String username, final LdapEntry ldapEntry) throws LoginException {
        final String id;
        if (this.principalIdAttribute != null) {
            final LdapAttribute principalAttr = ldapEntry.getAttribute(this.principalIdAttribute);
            if (principalAttr == null || principalAttr.size() == 0) {
                throw new LoginException(this.principalIdAttribute + " attribute not found for " + username);
            }
            if (principalAttr.size() > 1) {
                if (this.allowMultiplePrincipalAttributeValues) {
                    logger.warn(
                            "Found multiple values for principal ID attribute: {}. Using first value={}.",
                            principalAttr,
                            principalAttr.getStringValue());
                } else {
                    throw new LoginException("Multiple principal values not allowed: " + principalAttr);
                }
            }
            id = principalAttr.getStringValue();
        } else {
            id = username;
        }
        final Map<String, Object> attributeMap = new LinkedHashMap<>(this.principalAttributeMap.size());
        for (final Map.Entry<String, String> ldapAttr : this.principalAttributeMap.entrySet()) {
            final LdapAttribute attr = ldapEntry.getAttribute(ldapAttr.getKey());
            if (attr != null) {
                logger.debug("Found principal attribute: {}", attr);
                final String principalAttrName = ldapAttr.getValue();
                if (attr.size() > 1) {
                    attributeMap.put(principalAttrName, attr.getStringValues());
                } else {
                    attributeMap.put(principalAttrName, attr.getStringValue());
                }
            }
        }
        return this.principalFactory.createPrincipal(id, attributeMap);
    }


}
