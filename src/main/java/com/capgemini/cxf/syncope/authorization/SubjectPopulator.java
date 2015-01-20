package com.capgemini.cxf.syncope.authorization;

import com.capgemini.cxf.syncope.InterceptorsUtil;
import org.apache.cxf.common.security.SecurityToken;
import org.apache.cxf.common.security.SimpleGroup;
import org.apache.cxf.common.security.UsernameToken;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.security.DefaultSecurityContext;
import org.apache.cxf.interceptor.security.SimpleAuthorizingInterceptor;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.SecurityContext;
import org.apache.syncope.common.to.MembershipTO;
import org.apache.syncope.common.to.UserTO;
import org.codehaus.jackson.jaxrs.JacksonJsonProvider;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Take the received usernametoken prepared by the BasicAuthInterceptor and authenticate the username/password credential
 * using Syncope REST API. Then read the user from Syncope and get the roles. Store these in a new Subject that can be
 * authorized by a downstream authorizing interceptor.
 */
public class SubjectPopulator extends AbstractPhaseInterceptor<Message> {

    private final static Logger LOGGER = LoggerFactory.getLogger(SubjectPopulator.class);

    private ConfigurationAdmin configurationAdmin;

    public SubjectPopulator() {
        super(Phase.PRE_INVOKE);
        super.addBefore(SimpleAuthorizingInterceptor.class.getName());
    }

    public void handleMessage(Message message) throws Fault {
        SecurityContext context = message.get(SecurityContext.class);
        if (context == null) {
            return;
        }
        Principal principal = context.getUserPrincipal();
        UsernameToken usernameToken = (UsernameToken)message.get(SecurityToken.class);
        if (principal == null || usernameToken == null
                || !principal.getName().equals(usernameToken.getName())) {
            return;
        }

        // create the util and retrieve Syncope address
        InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        String address;
        try {
            address = util.getSyncopeAddress();
        } catch (Exception e) {
            LOGGER.error("Can't get Syncope address", e);
            throw new Fault(e);
        }

        // Read the user from Syncope and get the roles
        WebClient client = WebClient.create(address, Collections.singletonList(new JacksonJsonProvider()));

        String authorizationHeader = "Basic " + Base64Utility.encode((usernameToken.getName() + ":" + usernameToken.getPassword()).getBytes());

        client.header("Authorization", authorizationHeader);

        client = client.path("users/self");
        UserTO user = null;
        try {
            user = client.accept("application/json").get(UserTO.class);
            if (user == null) {
                Exception exception = new Exception("Authentication failed");
                throw new Fault(exception);
            }
        } catch (RuntimeException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new Fault(ex);
        }

        // Now get the roles
        List<MembershipTO> membershipList = user.getMemberships();
        LinkedList<String> userRoles = new LinkedList<String>();
        Subject subject = new Subject();
        subject.getPrincipals().add(principal);
        for (MembershipTO membership : membershipList) {
            String roleName = membership.getRoleName();
            userRoles.add(roleName);
            subject.getPrincipals().add(new SimpleGroup(roleName, usernameToken.getName()));
        }
        subject.setReadOnly();

        // put principal and subject (with the roles) in message DefaultSecurityContext
        message.put(DefaultSecurityContext.class, new DefaultSecurityContext(principal, subject));
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return this.configurationAdmin;
    }

}
