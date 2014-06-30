package com.capgemini.cxf.syncope;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Interceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Inject interceptor in the CXF buses
 */
public class InterceptorsInjector {

    private final static Logger LOGGER = LoggerFactory.getLogger(InterceptorsInjector.class);

    private List<Bus> buses;

    private Interceptor authenticationInterceptor;
    private Interceptor authorizationInterceptor;

    public void inject() {
        for (Bus bus : buses) {
            //if (!bus.getInInterceptors().contains(authenticationInterceptor)) {
                bus.getInInterceptors().add(authenticationInterceptor);
            //}
            //if (!bus.getInInterceptors().contains(authorizationInterceptor)) {
                bus.getInInterceptors().add(authorizationInterceptor);
            //}
        }
    }

    public void setBuses(List<Bus> busses) {
        this.buses = busses;
    }

    public List<Bus> getBuses() {
        return this.buses;
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
