package com.capgemini.cxf.syncope;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Interceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CXF bus listener to inject the interceptor on new registered buses.
 */
public class BusListener {

    private final static Logger LOGGER = LoggerFactory.getLogger(BusListener.class);

    private Interceptor authenticationInterceptor;
    private Interceptor authorizationInterceptor;

    public void busRegistered(Bus bus) {
        LOGGER.info("Adding CapGemini interceptors on bus " + bus.getId());
        if (!bus.getInInterceptors().contains(authenticationInterceptor)) {
            bus.getInInterceptors().add(authenticationInterceptor);
        }
        if (!bus.getInInterceptors().contains(authorizationInterceptor)) {
            bus.getInInterceptors().add(authorizationInterceptor);
        }
    }

    public void setAuthenticationInterceptor(Interceptor authenticationInterceptor) {
        this.authenticationInterceptor = authenticationInterceptor;
    }

    public Interceptor getAuthenticationInterceptor() {
        return this.authenticationInterceptor;
    }

    public void setAuthorizationInterceptor(Interceptor authorizationInterceptor) {
        this.authorizationInterceptor = authorizationInterceptor;
    }

    public Interceptor getAuthorizationInterceptor() {
        return this.authorizationInterceptor;
    }

}
