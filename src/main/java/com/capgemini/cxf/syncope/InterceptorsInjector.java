package com.capgemini.cxf.syncope;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Interceptor;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Inject interceptor in the CXF buses
 */
public class InterceptorsInjector {

    private final static Logger LOGGER = LoggerFactory.getLogger(InterceptorsInjector.class);

    private List<Bus> buses;
    private ConfigurationAdmin configurationAdmin;

    private Interceptor authenticator;
    private Interceptor populator;

    public void inject() {
        InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        try {
            for (Bus bus : buses) {
                LOGGER.debug("Checking if CXF bus {} is defined in the configuration", bus.getId());
                if (util.busDefined(bus.getId())) {
                    LOGGER.debug("Injecting interceptors on CXF bus {}", bus.getId());
                    bus.getInInterceptors().add(authenticator);
                    bus.getInInterceptors().add(populator);
                }
            }
        } catch (Exception e) {
            LOGGER.error("Injection failed", e);
        }
    }

    public void setBuses(List<Bus> busses) {
        this.buses = busses;
    }

    public List<Bus> getBuses() {
        return this.buses;
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return this.configurationAdmin;
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public void setAuthenticator(Interceptor authenticator) {
        this.authenticator = authenticator;
    }

    public Interceptor getAuthenticator() {
        return this.authenticator;
    }

    public void setPopulator(Interceptor populator) {
        this.populator = populator;
    }

    public Interceptor getPopulator() {
        return this.populator;
    }

}
