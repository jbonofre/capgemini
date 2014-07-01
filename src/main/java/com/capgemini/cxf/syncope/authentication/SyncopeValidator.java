package com.capgemini.cxf.syncope.authentication;

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

import javax.security.auth.Subject;
import java.util.Collections;
import java.util.Dictionary;
import java.util.LinkedList;
import java.util.List;

/**
 * Validator which use Syncope IdM
 */
public class SyncopeValidator implements Validator {

    private final static Logger LOGGER = LoggerFactory.getLogger(SyncopeValidator.class);

    private String address;
    private ConfigurationAdmin configurationAdmin;

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
        UserTO user;
        try {
            user = client.accept("application/json").get(UserTO.class);
            if (user == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
        } catch (RuntimeException ex) {
            LOGGER.debug(ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }

        // get the bus ID
        Message message = (Message) data.getMsgContext();
        String busId = message.getExchange().getBus().getId();

        try {
            // get the roles
            // Now get the roles
            List<MembershipTO> membershipList = user.getMemberships();
            LinkedList<String> userRoles = new LinkedList<String>();
            for (MembershipTO membership : membershipList) {
                String roleName = membership.getRoleName();
                userRoles.add(roleName);
            }

            // validate the roles on the configuration
            Configuration configuration = configurationAdmin.getConfiguration("com.capgemini.cxf.syncope.authorization");
            if (configuration == null) {
                LOGGER.warn("Configuration etc/com.capgemini.cxf.syncope.authorization.cfg is not found");
            } else {
                Dictionary dictionary = configuration.getProperties();
                String rolesString = (String) dictionary.get(busId);
                if (rolesString == null) {
                    throw new Exception("Roles configuration not found for bus " + busId);
                }
                // split the roles by ,
                String[] roles = rolesString.split(",");
                if (roles.length < 1) {
                    throw new Exception("No role authorization defined for bus " + busId);
                }
                // check if at least one role match
                boolean match = false;
                for (String role : roles) {
                    for (String userRole : userRoles) {
                        if (userRole.equals(role)) {
                            match = true;
                            break;
                        }
                    }
                }
                if (!match) {
                    throw new Exception("User " + user.getUsername() + " has not role expected for CXF bus " + busId);
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
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

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return this.configurationAdmin;
    }

}
