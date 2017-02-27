/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.appmgt.impl.idp.sso;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeObject;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.SSOProvider;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.idp.sso.configurator.SSOConfigurator;
import org.wso2.carbon.appmgt.impl.idp.sso.model.SSOEnvironment;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.util.List;

public class SSOConfiguratorUtil {

    private static Log log = LogFactory.getLog(SSOConfiguratorUtil.class);

    public static final String SP_ADMIN_SERVICE_COOKIE_PROPERTY_KEY = "adminServiceCookie";

    public static String[] getAllClaims(String ssoProvider, String version) {

        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();

        SSOEnvironment ssoEnvironment = findProviderEnvironment(ssoProvider, version, config);

        if(ssoEnvironment == null) {
            log.error("Could not find SSO Configurator details for " + ssoProvider.toString());
            return null;
        }

        try {
            SSOConfigurator configurator = (SSOConfigurator) Class.forName(ssoEnvironment.getProviderClass()).newInstance();
            configurator.init(ssoEnvironment.getParameters());

            return configurator.getAllClaims();

        } catch (ClassNotFoundException e) {
            log.error("SSO Configurator class not found " + ssoEnvironment.getProviderClass());
        } catch (InstantiationException e) {
            log.error("Error instantiating " + ssoEnvironment.getProviderClass());
        } catch (IllegalAccessException e) {
            log.error("Illegal access to " + ssoEnvironment.getProviderClass());
        }

        log.error("Error retrieving claims.");
        return null;
    }

    /**
     * Returns IDPs in the given service provider.
     * @param ssoProviderName SSO provider name of the app
     * @param ssoProviderVersion SSO provider version of the app
     * @param serviceProviderId Service provider id.
     * @return A list of IDPs of the service provider.
     */
    public static String[] getIdentityProvidersInServiceProvider(String ssoProviderName, String ssoProviderVersion, String serviceProviderId){

        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();

        SSOEnvironment ssoEnvironment = findProviderEnvironment(ssoProviderName, ssoProviderVersion, config);

        if(ssoEnvironment == null) {
            log.error("Could not find SSO Configurator details for " + ssoProviderName.toString());
            return null;
        }

        try {
            SSOConfigurator configurator = (SSOConfigurator) Class.forName(ssoEnvironment.getProviderClass()).newInstance();
            configurator.init(ssoEnvironment.getParameters());

            return configurator.getIdentityProvidersInServiceProvider(serviceProviderId);

        } catch (ClassNotFoundException e) {
            log.error("SSO Configurator class not found " + ssoEnvironment.getProviderClass());
        } catch (InstantiationException e) {
            log.error("Error instantiating " + ssoEnvironment.getProviderClass());
        } catch (IllegalAccessException e) {
            log.error("Illegal access to " + ssoEnvironment.getProviderClass());
        }

        log.error(String.format("Error retrieving identity providers for %s ", serviceProviderId));
        return null;
    }

    public static NativeArray getAvailableProviders() {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();

        List<SSOEnvironment> ssoEnvironments = config.getSsoEnvironments();
        NativeArray availableProviders = new NativeArray(0);
        int i = 0;
//        boolean isAvailable = false;
        for(SSOEnvironment env: ssoEnvironments) {
            try {
                SSOConfigurator configurator = (SSOConfigurator) Class.forName(env.getProviderClass()).newInstance();
                configurator.init(env.getParameters());
//                if(configurator.isAvailable()) {
//                    isAvailable = true;
//                }
            } catch (Exception e) {
                log.warn("Unable to check availability of SSO Provider " + env.toString() + " - SSO configurator will be disabled.");
            }

//            if(isAvailable) {
                availableProviders.put(i++, availableProviders, env.getName() + "-" + env.getVersion());
//            }
        }
        return availableProviders;
    }

    public static NativeObject getSSOProvider(String providerName, String providerVersion, String appName) {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();

        List<SSOEnvironment> ssoEnvironments = config.getSsoEnvironments();
        NativeObject ssoProviderObj = new NativeObject();
        for(SSOEnvironment env: ssoEnvironments) {
            try {
                if(env.getName().equals(providerName) && env.getVersion().equals(providerVersion)) {
                    SSOConfigurator configurator = (SSOConfigurator) Class.forName(env.getProviderClass()).newInstance();
                    configurator.init(env.getParameters());
                    SSOProvider ssoProvider = configurator.getProvider(appName);
                    ssoProviderObj.put("provider_name", ssoProviderObj, env.getName());
                    ssoProviderObj.put("provider_version", ssoProviderObj, env.getVersion());
                    ssoProviderObj.put("claims", ssoProviderObj, ssoProvider.getClaims());
                    ssoProviderObj.put("logout_url", ssoProviderObj, ssoProvider.getLogoutUrl());
                    return ssoProviderObj;
                }
            } catch (Exception e) {
                log.error("Unable to retrieve SSO Provider details for " + env.toString());
            }
        }

        return null;
    }

    /**
     * Utility method used to check availability of service on host/port.
     * @param host
     * @param port
     * @return true/false can connect
     */
    public static boolean isUp(String host, int port) {
        try {
            ServerSocketChannel socketChannel = ServerSocketChannel.open();
            socketChannel.configureBlocking(true);
            InetSocketAddress inetSocketAddress = new InetSocketAddress(host, port);
            socketChannel.socket().bind(inetSocketAddress);
            socketChannel.socket().close();
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    private static SSOEnvironment findProviderEnvironment(String provider, String version, AppManagerConfiguration config) {
        for(SSOEnvironment environment : config.getSsoEnvironments()) {
            return environment;
//            if(environment.getName().equals(provider)
//                    && environment.getVersion().equals(version)) {
//                return environment;
//            }
        }

        return null;
    }

    public static boolean isResponseSigningEnabled() {

        String responseSigningEnabled = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                getAPIManagerConfiguration().getFirstProperty(AppMConstants.SSO_CONFIGURATION_ENABLE_RESPONSE_SIGNING);

        /*responseSigningEnabled can be null, when element is not present in the app-manager.xml.
         For backward compatibility reason, we need to handle null scenario.(AppManager-1.2.0 released with
         response signing true without having a config option)
         */
        if (responseSigningEnabled == null) {
            responseSigningEnabled = "true";
        }

        return Boolean.parseBoolean(responseSigningEnabled);
    }

    public static boolean isAssertionSigningEnabled() {

        return Boolean.parseBoolean(ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                getAPIManagerConfiguration().getFirstProperty(AppMConstants.SSO_CONFIGURATION_ENABLE_ASSERTION_SIGNING));
    }

    public static boolean isValidateAssertionValidityPeriod() {
        return Boolean.parseBoolean(ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                getAPIManagerConfiguration().getFirstProperty(AppMConstants.SSO_CONFIGURATION_VALIDATE_ASSERTION_EXPIRY));
    }

    private static void handleException(String msg, Throwable t) throws AppManagementException {
        log.error(msg, t);
        throw new AppManagementException(msg, t);
    }

}
