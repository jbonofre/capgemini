package com.capgemini.cxf.syncope.authorization;

import com.capgemini.cxf.syncope.InterceptorsUtil;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.message.Message;
import org.apache.syncope.common.to.MembershipTO;
import org.apache.syncope.common.to.UserTO;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.codehaus.jackson.jaxrs.JacksonJsonProvider;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Dictionary;
import java.util.LinkedList;
import java.util.List;

/**
 * Validator which use Syncope IdM
 */
public class SyncopeValidator implements Validator {

    private final static Logger LOGGER = LoggerFactory.getLogger(SyncopeValidator.class);

    private ConfigurationAdmin configurationAdmin;

    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getUsernametoken() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }

        // Validate the UsernameToken
        UsernameToken usernameToken = credential.getUsernametoken();
        String pwType = usernameToken.getPasswordType();
        LOGGER.debug("UsernameToken user {}", usernameToken.getName());
        LOGGER.debug("UsernameToken password type {}", pwType);
        if (!WSConstants.PASSWORD_TEXT.equals(pwType)) {
            LOGGER.error("Authentication failed - digest passwords are not accepted");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        if (usernameToken.getPassword() == null) {
            LOGGER.error("Authentication failed - no password was provided");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        // create the util and retrieve Syncope address
        InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        String address;
        try {
            address = util.getSyncopeAddress();
        } catch (Exception e) {
            LOGGER.error("Can't get Syncope address", e);
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }

        // Send it off to Syncope for validation
        LOGGER.debug("Use Syncope REST API from {}", address);
        WebClient client = WebClient.create(address, Collections.singletonList(new JacksonJsonProvider()));

        String authorizationHeader = "Basic " + Base64Utility.encode((usernameToken.getName() + ":" + usernameToken.getPassword()).getBytes());

        client.header("Authorization", authorizationHeader);
        LOGGER.debug("Authenticating user {} to Syncope server", usernameToken.getName());

        client = client.path("users/self");
        UserTO user;
        try {
            user = client.accept("application/json").get(UserTO.class);
            if (user == null) {
                LOGGER.error("User {} not authenticated on Syncope", usernameToken.getName());
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
        } catch (RuntimeException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        // get the bus ID
        Message message = (Message) data.getMsgContext();
        String busId = message.getExchange().getBus().getId();
        LOGGER.debug("Processing bus ID {}", busId);

        try {
            // get the roles
            List<MembershipTO> membershipList = user.getMemberships();
            LinkedList<String> userRoles = new LinkedList<String>();
            for (MembershipTO membership : membershipList) {
                String roleName = membership.getRoleName();
                userRoles.add(roleName);
            }

            // validate the roles
            if (!util.authorize(busId, userRoles)) {
                LOGGER.error("User {} has no role expected for CXF bus {}", user.getUsername(), busId);
                throw new Exception("User " + user.getUsername() + " has no role expected for CXF bus " + busId);
            } else {
                LOGGER.debug("User {} is authorized", user.getUsername());
            }
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        return credential;
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return this.configurationAdmin;
    }

}
