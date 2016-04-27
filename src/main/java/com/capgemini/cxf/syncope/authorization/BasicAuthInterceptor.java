package com.capgemini.cxf.syncope.authorization;

import com.capgemini.cxf.syncope.InterceptorsUtil;
import org.apache.cxf.common.security.SimpleGroup;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.helpers.CastUtils;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.security.DefaultSecurityContext;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.Headers;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.apache.syncope.common.to.MembershipTO;
import org.apache.syncope.common.to.UserTO;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.codehaus.jackson.jaxrs.JacksonJsonProvider;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.security.auth.Subject;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.security.Principal;
import java.util.*;

/**
 * This interceptor just get a base authorization, and create a UsernameToken delegated to the Syncope interceptor
 */
public class BasicAuthInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Logger LOGGER = LoggerFactory.getLogger(BasicAuthInterceptor.class);

    private ConfigurationAdmin configurationAdmin;

    private Validator validator;

    public BasicAuthInterceptor() {
        this(Phase.UNMARSHAL);
    }

    public BasicAuthInterceptor(String phase) {
        super(phase);
    }

    public void sendErrorResponse(Message message, int errorCode) {
        LOGGER.warn("Authorization policy is not present, creating {} response", errorCode);

        // no authentication provided, send error response
        Exchange exchange = message.getExchange();
        Message outMessage = exchange.getOutMessage();
        if (outMessage == null) {
            Endpoint endpoint = exchange.get(Endpoint.class);
            outMessage = new MessageImpl();
            outMessage.putAll(message);
            outMessage.remove(Message.PROTOCOL_HEADERS);
            outMessage.setExchange(exchange);
            outMessage = endpoint.getBinding().createMessage(outMessage);
            exchange.setOutMessage(outMessage);
        }
        outMessage.put(Message.RESPONSE_CODE, errorCode);
        Map<String, List<String>> responseHeaders = Headers.getSetProtocolHeaders(outMessage);
        responseHeaders.put("WWW-Authenticate", Arrays.asList(new String[] {"Basic realm=realm"}));
        message.getInterceptorChain().abort();

        try {
            EndpointReferenceType target = exchange.get(EndpointReferenceType.class);
            Conduit conduit = exchange.getDestination().getBackChannel(message, null, target);
            exchange.setConduit(conduit);
            conduit.prepare(outMessage);
            OutputStream os = outMessage.getContent(OutputStream.class);
            os.flush();
            //os.close();
        } catch (Exception e) {
            LOGGER.error("Can't prepare response", e);
        }
    }

    public void handleMessage(Message message) throws Fault {
        AuthorizationPolicy policy = message.get(AuthorizationPolicy.class);

	LOGGER.debug("Authorization policy: {}", policy);

        if (policy == null || policy.getUserName() == null || policy.getPassword() == null) {
            LOGGER.warn("Authorization policy is not present, creating 401 response");
            // no authentication provided, send error response
            sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
            return;
        }

        try {
            LOGGER.info("Get authorization policy, converting to username token");

            LOGGER.debug("Converting policy to token");
            UsernameToken token = convertPolicyToToken(policy);
            Credential credential = new Credential();
            LOGGER.debug("Token: {}", token);
            credential.setUsernametoken(token);

            RequestData data = new RequestData();
            data.setMsgContext(message);

            LOGGER.info("Call the Syncope validator");
            try {
                LOGGER.debug("Validate credential {} on data {}", credential, data);
                credential = validator.validate(credential, data);
            } catch (Exception e) {
                LOGGER.warn("Syncope authentication failed");
                sendErrorResponse(message, HttpURLConnection.HTTP_FORBIDDEN);
            }

            // Create a Principal/SecurityContext
            Principal p = null;
            if (credential != null && credential.getPrincipal() != null) {
                p = credential.getPrincipal();
            } else {
                p = new WSUsernameTokenPrincipal(policy.getUserName(), false);
                ((WSUsernameTokenPrincipal)p).setPassword(policy.getPassword());
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

            String authorizationHeader = "Basic " + Base64Utility.encode((token.getName() + ":" + token.getPassword()).getBytes());

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
            subject.getPrincipals().add(p);
            for (MembershipTO membership : membershipList) {
                String roleName = membership.getRoleName();
                userRoles.add(roleName);
                subject.getPrincipals().add(new SimpleGroup(roleName, token.getName()));
            }
            subject.setReadOnly();

            // put principal and subject (with the roles) in message DefaultSecurityContext
            // new style: protocol headers
            Map<String, List<String>> headers = CastUtils.cast((Map<?, ?>)message.get(Message.PROTOCOL_HEADERS));
            LinkedList<String> temp = new LinkedList<String>();
            temp.add(p.getName());
            headers.put("User", temp);
            headers.put("Roles", userRoles);
            // old style
            message.put(DefaultSecurityContext.class, new DefaultSecurityContext(p, subject));

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

    public ConfigurationAdmin getConfigurationAdmin() {
        return configurationAdmin;
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

}
