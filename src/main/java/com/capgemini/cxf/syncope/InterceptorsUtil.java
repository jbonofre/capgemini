package com.capgemini.cxf.syncope;

import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.List;

/**
 * Utils to get the CXF buses defined in the configuration
 */
public class InterceptorsUtil {

    private final static String CONFIG_PID = "com.capgemini.cxf.syncope.authorization";

    private final static Logger LOGGER = LoggerFactory.getLogger(InterceptorsUtil.class);

    private ConfigurationAdmin configurationAdmin;

    public InterceptorsUtil(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    /**
     * Get the buses defined in the configuration.
     *
     * @return the list of bus ID defined
     */
    public List<String> getBuses() throws Exception {
        Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
        if (configuration == null) {
            LOGGER.error("Configuration {} not found", CONFIG_PID);
            throw new IllegalStateException("Configuration " + CONFIG_PID + " not found");
        }
        ArrayList<String> buses = new ArrayList<String>();
        Dictionary properties = configuration.getProperties();
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                LOGGER.debug("Adding CXF bus {}", key);
                buses.add(key);
            }
        }
        return buses;
    }

    /**
     * Get the roles defined for a given bus.
     *
     * @param busId the CXF bus ID (or prefix string) as defined in the configuration.
     * @return the list of roles defined for the bus.
     */
    private String[] getBusRoles(String busId) throws Exception {
        Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
        if (configuration == null) {
            LOGGER.error("Configuration {} not found", CONFIG_PID);
            throw new IllegalStateException("Configuration " + CONFIG_PID + " not found");
        }
        Dictionary properties = configuration.getProperties();
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                LOGGER.debug("Checking if bus {} starts with {} ...", busId, key);
                if (busId.startsWith(key)) {
                    String roles = (String) properties.get(key);
                    LOGGER.debug("Roles found for CXF bus {}: {}", busId, roles);
                    return roles.split(",");
                }
            }
        }
        return null;
    }

    /**
     * Get the REST API address of Syncope.
     *
     * @return the REST API address of Syncope.
     */
    public String getSyncopeAddress() throws Exception {
        Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
        if (configuration == null) {
            LOGGER.error("Configuration {} not found", CONFIG_PID);
            throw new IllegalStateException("Configuration " + CONFIG_PID + " not found");
        }
        Dictionary properties = configuration.getProperties();
        if (properties != null) {
            Object address = properties.get("syncope.address");
            if (address != null) {
                LOGGER.debug("Found syncope.address property: {}", address);
                return ((String) address);
            }
        }
        LOGGER.error("syncope.address property not found in the configuration");
        throw new IllegalStateException("syncope.address property not found in the configuration");
    }

    /**
     * Check if a bus ID is defined in the configuration
     *
     * @param id the CXF bus ID to check.
     * @return true if the bus is defined in the configuration, false else.
     */
    public boolean busDefined(String id) throws Exception {
        List<String> buses = this.getBuses();
        for (String bus : buses) {
            if (id.startsWith(bus)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if one of the roles match the bus roles definition.
     *
     * @param busId the bus ID.
     * @param roles the roles to check.
     * @return true if at least one of the role match, false else.
     */
    public boolean authorize(String busId, List<String> roles) throws Exception {
        LOGGER.debug("Authorizing on bus ID {}", busId);
        String[] configuredRoles = this.getBusRoles(busId);
        if (configuredRoles != null) {
            for (String role : roles) {
                LOGGER.debug("Checking authorization for role {}", role);
                for (String configuredRole : configuredRoles) {
                    LOGGER.debug(" ... on {}", configuredRole);
                    if (role.equalsIgnoreCase(configuredRole)) {
                        LOGGER.debug("Role ({}/{}) authorized", role, configuredRole);
                        return true;
                    }
                }
            }
        }
        return false;
    }

}
