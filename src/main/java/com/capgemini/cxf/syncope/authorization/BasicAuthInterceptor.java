package com.capgemini.cxf.syncope.authorization;

import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.SecurityContext;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import java.security.Principal;

/**
 * This interceptor just get a base authorization, and create a UsernameToken delegated to the Syncope interceptor
 */
public class BasicAuthInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Logger LOGGER = LoggerFactory.getLogger(BasicAuthInterceptor.class);

    private Validator validator;

    public BasicAuthInterceptor() {
        this(Phase.UNMARSHAL);
    }

    public BasicAuthInterceptor(String phase) {
        super(phase);
    }

    public void handleMessage(Message message) throws Fault {
        AuthorizationPolicy policy = message.get(AuthorizationPolicy.class);
        if (policy == null || policy.getUserName() == null || policy.getPassword() == null) {
            String name = null;
            if (policy != null) {
                name = policy.getUserName();
            }
            String error = "No user credentials are available";
            LOGGER.warn("{} for name {}", error, name);
            throw new SecurityException(error);
        }

        try {
            UsernameToken token = convertPolicyToToken(policy);
            Credential credential = new Credential();
            credential.setUsernametoken(token);

            RequestData data = new RequestData();
            data.setMsgContext(message);
            credential = validator.validate(credential, data);

            // Create a Principal/SecurityContext
            Principal p = null;
            if (credential != null && credential.getPrincipal() != null) {
                p = credential.getPrincipal();
            } else {
                p = new WSUsernameTokenPrincipal(policy.getUserName(), false);
                ((WSUsernameTokenPrincipal)p).setPassword(policy.getPassword());
            }
            message.put(SecurityContext.class, createSecurityContext(p));

        } catch (Exception ex) {
            throw new Fault(ex);
        }
    }

    protected UsernameToken convertPolicyToToken(AuthorizationPolicy policy)
            throws Exception {

        Document doc = DOMUtils.createDocument();
        UsernameToken token = new UsernameToken(false, doc, WSConstants.PASSWORD_TEXT);
        token.setName(policy.getUserName());
        token.setPassword(policy.getPassword());
        return token;
    }

    protected SecurityContext createSecurityContext(final Principal p) {
        return new SecurityContext() {

            public Principal getUserPrincipal() {
                return p;
            }

            public boolean isUserInRole(String arg0) {
                return false;
            }
        };
    }

    public void setValidator(Validator validator) {
        this.validator = validator;
    }

}
