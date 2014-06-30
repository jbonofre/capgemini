package com.capgemini.cxf.syncope.authentication;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.syncope.common.to.UserTO;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.codehaus.jackson.jaxrs.JacksonJsonProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 * Validator which use Syncope IdM
 */
public class SyncopeValidator implements Validator {

    private final static Logger LOGGER = LoggerFactory.getLogger(SyncopeValidator.class);

    private String address;

    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getUsernametoken() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }

        // Validate the UsernameToken
        UsernameToken usernameToken = credential.getUsernametoken();
        String pwType = usernameToken.getPasswordType();
        LOGGER.debug("UsernameToken user {}", usernameToken.getName());
        LOGGER.debug("UsernameToken password type {]", pwType);
        if (!WSConstants.PASSWORD_TEXT.equals(pwType)) {
            LOGGER.error("Authentication failed - digest passwords are not accepted");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        if (usernameToken.getPassword() == null) {
            LOGGER.error("Authentication failed - no password was provided");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        // Send it off to Syncope for validation
        WebClient client = WebClient.create(address, Collections.singletonList(new JacksonJsonProvider()));

        String authorizationHeader = "Basic " + Base64Utility.encode((usernameToken.getName() + ":" + usernameToken.getPassword()).getBytes());

        client.header("Authorization", authorizationHeader);
        LOGGER.debug("Authenticating user {} to Syncope server");

        client = client.path("users/self");
        try {
            UserTO user = client.accept("application/json").get(UserTO.class);
            if (user == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
        } catch (RuntimeException ex) {
            LOGGER.debug(ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        return credential;
    }

    public void setAddress(String newAddress) {
        address = newAddress;
    }

    public String getAddress() {
        return address;
    }


}
