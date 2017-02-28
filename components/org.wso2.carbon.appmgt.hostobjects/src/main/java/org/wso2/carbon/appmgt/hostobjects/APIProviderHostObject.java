/*
*  Copyright (c) 2005-2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.appmgt.hostobjects;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.woden.WSDLFactory;
import org.apache.woden.WSDLReader;
import org.jaggeryjs.hostobjects.file.FileHostObject;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeJavaObject;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.wso2.carbon.appmgt.api.APIProvider;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APIKey;
import org.wso2.carbon.appmgt.api.model.APIStatus;
import org.wso2.carbon.appmgt.api.model.AppStore;
import org.wso2.carbon.appmgt.api.model.SSOProvider;
import org.wso2.carbon.appmgt.api.model.Tier;
import org.wso2.carbon.appmgt.hostobjects.internal.HostObjectComponent;
import org.wso2.carbon.appmgt.hostobjects.internal.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.APIManagerFactory;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.UserAwareAPIProvider;
import org.wso2.carbon.appmgt.impl.dto.TierPermissionDTO;
import org.wso2.carbon.appmgt.impl.utils.APIVersionStringComparator;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.mgt.stub.UserAdminStub;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.net.ssl.SSLHandshakeException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

@SuppressWarnings("unused")
public class APIProviderHostObject extends ScriptableObject {

    private static final Log log = LogFactory.getLog(APIProviderHostObject.class);

    private String username;

    private APIProvider apiProvider;

    public String getClassName() {
        return "APIProvider";
    }

    // The zero-argument constructor used for create instances for runtime
    public APIProviderHostObject() throws AppManagementException {

    }

    public APIProviderHostObject(String loggedUser) throws AppManagementException {
        username = loggedUser;
        apiProvider = APIManagerFactory.getInstance().getAPIProvider(loggedUser);
    }

    public String getUsername() {
        return username;
    }

    public static Scriptable jsConstructor(Context cx, Object[] args, Function Obj,
                                           boolean inNewExpr)
            throws AppManagementException {
        if (args != null && args.length != 0) {
            String username = (String) args[0];
            return new APIProviderHostObject(username);
        }
        return new APIProviderHostObject();
    }

    public APIProvider getApiProvider() {
        return apiProvider;
    }

    private static APIProvider getAPIProvider(Scriptable thisObj) {
        return ((APIProviderHostObject) thisObj).getApiProvider();
    }

    private static void handleException(String msg) throws AppManagementException {
        log.error(msg);
        throw new AppManagementException(msg);
    }

    private static void handleException(String msg, Throwable t) throws AppManagementException {
        log.error(msg, t);
        throw new AppManagementException(msg, t);
    }

    public static NativeObject jsFunction_login(Context cx, Scriptable thisObj,
                                                Object[] args, Function funObj)
            throws AppManagementException {

        if (args==null || args.length == 0 || !isStringValues(args)) {
            handleException("Invalid input parameters to the login method");
        }

        String username = (String) args[0];
        String password = (String) args[1];

        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
        if (url == null) {
            handleException("WebApp key manager URL unspecified");
        }

        NativeObject row = new NativeObject();
        try {

            UserAdminStub userAdminStub = new UserAdminStub(url + "UserAdmin");
            CarbonUtils.setBasicAccessSecurityHeaders(username, password,
                    true, userAdminStub._getServiceClient());
            //If multiple user stores are in use, and if the user hasn't specified the domain to which
            //he needs to login to
            /* Below condition is commented out as per new multiple users-store implementation,users from
            different user-stores not needed to input domain names when tried to login,APIMANAGER-1392*/
            // if (userAdminStub.hasMultipleUserStores() && !username.contains("/")) {
            //      handleException("Domain not specified. Please provide your username as domain/username");
            // }
        } catch (Exception e) {
            log.error("Error occurred while checking for multiple user stores");
        }

        try {
            AuthenticationAdminStub authAdminStub = new AuthenticationAdminStub(null, url + "AuthenticationAdmin");
            ServiceClient client = authAdminStub._getServiceClient();
            Options options = client.getOptions();
            options.setManageSession(true);

            String host = new URL(url).getHost();
            if (!authAdminStub.login(username, password, host)) {
                handleException("Login failed! Please recheck the username and password and try again..");
            }
            ServiceContext serviceContext = authAdminStub.
                    _getServiceClient().getLastOperationContext().getServiceContext();
            String sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);

            String usernameWithDomain = AppManagerUtil.getLoggedInUserInfo(sessionCookie,url).getUserName();
            usernameWithDomain = AppManagerUtil.setDomainNameToUppercase(usernameWithDomain);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            boolean isSuperTenant = false;

            if (tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                isSuperTenant = true;
            }else {
                usernameWithDomain = usernameWithDomain+"@"+tenantDomain;
            }

            boolean   authorized =
                    AppManagerUtil.checkPermissionQuietly(usernameWithDomain, AppMConstants.Permissions.WEB_APP_CREATE) ||
                            AppManagerUtil.checkPermissionQuietly(usernameWithDomain, AppMConstants.Permissions.WEB_APP_PUBLISH);


            if (authorized) {

                row.put("user", row, usernameWithDomain);
                row.put("sessionId", row, sessionCookie);
                row.put("isSuperTenant", row, isSuperTenant);
                row.put("error", row, false);
            } else {
                handleException("Login failed! Insufficient privileges.");
            }
        } catch (Exception e) {
            row.put("error", row, true);
            row.put("detail", row, e.getMessage());
        }

        return row;
    }

    public static String jsFunction_getAuthServerURL(Context cx, Scriptable thisObj,
                                                     Object[] args, Function funObj)
            throws AppManagementException {

        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
        if (url == null) {
            handleException("WebApp key manager URL unspecified");
        }
        return url;
    }

    public static String jsFunction_getHTTPsURL(Context cx, Scriptable thisObj,
                                                Object[] args, Function funObj)
            throws AppManagementException {
        String hostName = CarbonUtils.getServerConfiguration().getFirstProperty("HostName");
        String backendHttpsPort = HostObjectUtils.getBackendPort("https");
        if (hostName == null) {
            hostName = System.getProperty("carbon.local.ip");
        }
        return "https://" + hostName + ":" + backendHttpsPort;

    }

    /**
     * Check whether the application with a given name, provider and version already exists
     *
     * @param ctx Rhino context
     * @param thisObj Scriptable object
     * @param args passing arguments
     * @param funObj Function object
     * @return true if the webapp already exists
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     * @throws ScriptException
     */
    public static boolean jsFunction_isWebappExists(Context ctx, Scriptable thisObj,Object[] args, Function funObj)
            throws AppManagementException, ScriptException {

        if (args == null || args.length != 3) {
            handleException("Invalid number of input parameters.");
        }

        if (args[0] == null || args[1] == null || args[2] == null) {
            handleException("Error while checking for existence of web app: NULL value in expected parameters ->"
                    + "[webapp name:" + args[0] + ",provider:" + args[1] + ",version:" + args[0] + "]");

        }
        String name = (String) args[0];
        String provider = (String) args[1];
        String version = (String) args[2];

        APIIdentifier apiId = new APIIdentifier(provider, name, version);
        APIProvider apiProvider = getAPIProvider(thisObj);

        return apiProvider.isAPIAvailable(apiId);
    }

    private static String getTransports(NativeObject apiData) {
        String transportStr = String.valueOf(apiData.get("overview_transports", apiData));
        String transport  = transportStr;
        if (transportStr != null) {
            if ((transportStr.indexOf(",") == 0) || (transportStr.indexOf(",") == (transportStr.length()-1))) {
                transport =transportStr.replace(",","");
            }
        }
        return transport;
    }

    private static void checkFileSize(FileHostObject fileHostObject)
            throws ScriptException, AppManagementException {
        if (fileHostObject != null) {
            long length = fileHostObject.getJavaScriptFile().getLength();
            if (length / 1024.0 > 1024) {
                handleException("Image file exceeds the maximum limit of 1MB");
            }
        }
    }

    public static boolean jsFunction_updateTierPermissions(Context cx, Scriptable thisObj,
                                                           Object[] args,
                                                           Function funObj)
            throws AppManagementException {
        if (args == null ||args.length == 0) {
            handleException("Invalid input parameters.");
        }

        NativeObject tierData = (NativeObject) args[0];
        boolean success = false;
        String tierName = (String) tierData.get("tierName", tierData);
        String permissiontype = (String) tierData.get("permissiontype", tierData);
        String roles = (String) tierData.get("roles", tierData);

        try {
            APIProvider apiProvider = getAPIProvider(thisObj);
            apiProvider.updateTierPermissions(tierName, permissiontype, roles);
            return true;

        } catch (AppManagementException e) {
            handleException("Error while updating subscription status", e);
            return false;
        }

    }

    public static NativeArray jsFunction_getTierPermissions(Context cx, Scriptable thisObj,
                                                            Object[] args,
                                                            Function funObj) {
        NativeArray myn = new NativeArray(0);
        APIProvider apiProvider = getAPIProvider(thisObj);
         /* Create an array with everyone role */
        String everyOneRoleName = ServiceReferenceHolder.getInstance().getRealmService().
                getBootstrapRealmConfiguration().getEveryOneRoleName();
        String defaultRoleArray[] = new String[1];
        defaultRoleArray[0] = everyOneRoleName;
        try {
            Set<Tier> tiers = apiProvider.getTiers();
            Set<TierPermissionDTO> tierPermissions = apiProvider.getTierPermissions();
            int i = 0;
            if (tiers != null) {

                for (Tier tier: tiers) {
                    NativeObject row = new NativeObject();
                    boolean found = false;
                    for (TierPermissionDTO permission : tierPermissions) {
                        if (permission.getTierName().equals(tier.getName())) {
                            row.put("tierName", row, permission.getTierName());
                            row.put("tierDisplayName", row, tier.getDisplayName());
                            row.put("permissionType", row,
                                    permission.getPermissionType());
                            String[] roles = permission.getRoles();
                             /*If no roles defined return default role list*/
                            if (roles == null ||  roles.length == 0) {
                                row.put("roles", row, defaultRoleArray);
                            } else {
                                row.put("roles", row,
                                        permission.getRoles());
                            }
                            found = true;
                            break;
                        }
                    }
            		 /* If no permissions has defined for this tier*/
                    if (!found) {
                        row.put("tierName", row, tier.getName());
                        row.put("tierDisplayName", row, tier.getDisplayName());
                        row.put("permissionType", row,
                                AppMConstants.TIER_PERMISSION_ALLOW);
                        row.put("roles", row, defaultRoleArray);
                    }
                    myn.put(i, myn, row);
                    i++;
                }
            }
        } catch (Exception e) {
            log.error("Error while getting available tiers", e);
        }
        return myn;
    }

    public static NativeArray jsFunction_getTiers(Context cx, Scriptable thisObj,
                                                  Object[] args,
                                                  Function funObj) {
        NativeArray myn = new NativeArray(1);
        APIProvider apiProvider = getAPIProvider(thisObj);
        try {
            Set<Tier> tiers = apiProvider.getTiers();
            int i = 0;
            if (tiers != null) {
                for (Tier tier : tiers) {
                    NativeObject row = new NativeObject();
                    row.put("tierName", row, tier.getName());
                    row.put("tierDisplayName", row, tier.getDisplayName());
                    row.put("tierDescription", row,
                            tier.getDescription() != null ? tier.getDescription() : "");
                    row.put("tierSortKey", row, tier.getRequestPerMinute());
                    myn.put(i, myn, row);
                    i++;
                }
            }
        } catch (Exception e) {
            log.error("Error while getting available tiers", e);
        }
        return myn;
    }

    private static String checkTransport(String compare, String transport)
            throws AppManagementException {
        if(transport!=null){
            List<String> transportList = new ArrayList<String>();
            transportList.addAll(Arrays.asList(transport.split(",")));
            if(transportList.contains(compare)){
                return "checked";
            }else{
                return "";
            }

        }else{
            return "";
        }
    }

    /**
     * Get the identity provider URL from app-manager.xml file
     *
     * @param context Rhino context
     * @param thisObj Scriptable object
     * @param args    Passing arguments
     * @param funObj  Function object
     * @return identity provider URL
     * @throws org.wso2.carbon.appmgt.api.AppManagementException Wrapped exception by org.wso2.carbon.apimgt.api.AppManagementException
     */
    public static String jsFunction_getIdentityProviderUrl(Context context, Scriptable thisObj,
                                                           Object[] args,
                                                           Function funObj) throws AppManagementException {
        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(AppMConstants.SSO_CONFIGURATION_IDENTITY_PROVIDER_URL);
        if (url == null) {
            handleException("Identity provider URL unspecified");
        }
        return url;
    }

    public static String jsFunction_isContextExist(Context cx, Scriptable thisObj,
                                                   Object[] args, Function funObj)
            throws AppManagementException {
        Boolean contextExist = false;
        if (args != null && isStringValues(args)) {
            String context = (String) args[0];
            String oldContext = (String) args[1];

            if (context.equals(oldContext)) {
                return contextExist.toString();
            }
            APIProvider apiProvider = getAPIProvider(thisObj);
            try {
                contextExist = apiProvider.isContextExist(context);
            } catch (AppManagementException e) {
                handleException("Error from registry while checking the input context is already exist", e);
            }
        } else {
            handleException("Input context value is null");
        }
        return contextExist.toString();
    }

    private static boolean isStringValues(Object[] args) {
        int i = 0;
        for (Object arg : args) {

            if (!(arg instanceof String)) {
                return false;

            }
            i++;
        }
        return true;
    }

    private static String checkValue(String input) {
        return input != null ? input : "";
    }


    private static APIStatus getApiStatus(String status) {
        APIStatus apiStatus = null;
        for (APIStatus aStatus : APIStatus.values()) {
            if (aStatus.getStatus().equalsIgnoreCase(status)) {
                apiStatus = aStatus;
            }

        }
        return apiStatus;
    }

    public static boolean jsFunction_hasManageTierPermission(Context cx, Scriptable thisObj,
                                                             Object[] args,
                                                             Function funObj) {
        APIProvider provider = getAPIProvider(thisObj);
        if (provider instanceof UserAwareAPIProvider) {
            try {
                ((UserAwareAPIProvider) provider).checkManageTiersPermission();
                return true;
            } catch (AppManagementException e) {
                return false;
            }
        }
        return false;
    }

    public static boolean jsFunction_hasUserPermissions(Context cx, Scriptable thisObj,
                                                        Object[] args,
                                                        Function funObj)
            throws AppManagementException {
        if (args == null || !isStringValues(args)) {
            handleException("Invalid input parameters.");
        }
        String username = (String) args[0];
        return AppManagerUtil.checkPermissionQuietly(username, AppMConstants.Permissions.WEB_APP_CREATE) ||
                AppManagerUtil.checkPermissionQuietly(username, AppMConstants.Permissions.WEB_APP_PUBLISH);
    }

    public static boolean jsFunction_hasPublishPermission(Context cx, Scriptable thisObj,
                                                          Object[] args,
                                                          Function funObj) {
        APIProvider provider = getAPIProvider(thisObj);
        if (provider instanceof UserAwareAPIProvider) {
            try {
                ((UserAwareAPIProvider) provider).checkPublishPermission();
                return true;
            } catch (AppManagementException e) {
                return false;
            }
        }
        return false;
    }

    public static void jsFunction_loadRegistryOfTenant(Context cx, Scriptable thisObj,
            Object[] args, Function funObj) {
        String tenantDomain = args[0].toString();
        if (tenantDomain != null
                && !org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME
                .equals(tenantDomain)) {
            try {
                int tenantId = ServiceReferenceHolder.getInstance().getRealmService().
                        getTenantManager().getTenantId(tenantDomain);
                AppManagerUtil.loadTenantRegistry(tenantId);
            } catch (org.wso2.carbon.user.api.UserStoreException | AppManagementException e) {
                log.error(
                        "Could not load tenant registry. Error while getting tenant id from tenant domain "
                                + tenantDomain);
            }
        }

    }

    private static class APISubscription {
        private String name;
        private long count;
        private String version;
        private String uuid;
    }

    /**
     * Remove a given application
     *
     * @param context Rhino context
     * @param thisObj Scriptable object
     * @param args    Passing arguments
     * @param funObj  Function object
     * @return true if success else false
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    public static boolean jsFunction_deleteApp(Context context, Scriptable thisObj,
                                               Object[] args,
                                               Function funObj) throws AppManagementException {
        if (args == null || args.length != 4) {
            handleException("Invalid number of input parameters.");
        }
        if (args[0] == null || args[2] == null) {
            handleException("Error while deleting application. The required parameters are null.");
        }
        boolean isAppDeleted = false;

        NativeJavaObject appIdentifierNativeJavaObject = (NativeJavaObject) args[0];
        APIIdentifier apiIdentifier = (APIIdentifier) appIdentifierNativeJavaObject.unwrap();
        String username = (String) args[1];
        username = AppManagerUtil.replaceEmailDomain(username);
        NativeJavaObject ssoProviderNativeJavaObject = (NativeJavaObject) args[2];
        SSOProvider ssoProvider = (SSOProvider) ssoProviderNativeJavaObject.unwrap();

        boolean isTenantFlowStarted = false;
        String authorizedAdminCookie = (String) args[3];
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(AppManagerUtil.replaceEmailDomainBack(username));
            if (tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                isTenantFlowStarted = true;
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            }
            APIProvider appProvider = getAPIProvider(thisObj);
           // isAppDeleted = appProvider.deleteApp(apiIdentifier, ssoProvider, authorizedAdminCookie);
        } finally {
            if (isTenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
        return isAppDeleted;
    }

    public static boolean jsFunction_isAPIOlderVersionExist(Context cx, Scriptable thisObj,
                                                            Object[] args, Function funObj)
            throws AppManagementException {
        boolean apiOlderVersionExist = false;
        if (args==null ||args.length == 0) {
            handleException("Invalid number of input parameters.");
        }

        NativeObject apiData = (NativeObject) args[0];
        String provider = (String) apiData.get("provider", apiData);
        provider= AppManagerUtil.replaceEmailDomain(provider);
        String name = (String) apiData.get("name", apiData);
        String currentVersion = (String) apiData.get("version", apiData);
        boolean isTenantFlowStarted = false;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(AppManagerUtil.replaceEmailDomainBack(provider));
            if(tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                isTenantFlowStarted = true;
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            }

            APIProvider apiProvider = getAPIProvider(thisObj);
            Set<String> versions = apiProvider.getAPIVersions(provider, name);
            APIVersionStringComparator comparator = new APIVersionStringComparator();
            for (String version : versions) {
                if (comparator.compare(version, currentVersion) < 0) {
                    apiOlderVersionExist = true;
                    break;
                }
            }
        } finally {
            if (isTenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
        return apiOlderVersionExist;
    }

    public static String jsFunction_isURLValid(Context cx, Scriptable thisObj,
                                               Object[] args, Function funObj)
            throws AppManagementException {
        String response = "";
        if (args == null || !isStringValues(args)) {
            handleException("Invalid input parameters.");
        }
        String urlVal = (String) args[1];
        String type = (String) args[0];
        if (urlVal != null && !urlVal.equals("")) {
            try {
                if (type != null && type.equals("wsdl")) {
                    validateWsdl(urlVal);
                } else {
                    URL url = new URL(urlVal);
                    URLConnection conn = url.openConnection();
                    conn.connect();
                }
                response = "success";
            } catch (MalformedURLException e) {
                response = "malformed";
            } catch (UnknownHostException e) {
                response = "unknown";
            } catch (ConnectException e) {
                response = "Cannot establish connection to the provided address";
            } catch (SSLHandshakeException e) {
                response = "ssl_error";
            } catch (Exception e) {
                response = e.getMessage();
            }
        }
        return response;

    }

    private boolean resourceMethodMatches(String[] resourceMethod1,
                                          String[] resourceMethod2) {
        for (String m1 : resourceMethod1) {
            for (String m2 : resourceMethod2) {
                if (m1.equals(m2)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void validateWsdl(String url) throws AppManagementException {
        try {
            URL wsdl = new URL(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(wsdl.openStream()));
            String inputLine;
            boolean isWsdl2 = false;
            boolean isWsdl10 = false;
            StringBuilder urlContent = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                String wsdl2NameSpace = "http://www.w3.org/ns/wsdl";
                String wsdl10NameSpace = "http://schemas.xmlsoap.org/wsdl/";
                urlContent.append(inputLine);
                isWsdl2 = urlContent.indexOf(wsdl2NameSpace) > 0;
                isWsdl10 = urlContent.indexOf(wsdl10NameSpace) > 0;
            }
            in.close();
            if (isWsdl10) {
                javax.wsdl.xml.WSDLReader wsdlReader11 = javax.wsdl.factory.WSDLFactory.newInstance().newWSDLReader();
                wsdlReader11.readWSDL(url);
            } else if (isWsdl2) {
                WSDLReader wsdlReader20 = WSDLFactory.newInstance().newWSDLReader();
                wsdlReader20.readWSDL(url);
            } else {
                handleException("URL is not in format of wsdl1/wsdl2");
            }
        } catch (Exception e) {
            handleException("Error occurred while validating the Wsdl", e);
        }
    }

    private static String getWebContextRoot(String postfixUrl) {
        String webContext = CarbonUtils.getServerConfiguration().getFirstProperty("WebContextRoot");
        if (postfixUrl != null && webContext != null && !webContext.equals("/")) {
            postfixUrl = webContext + postfixUrl;
        }
        return postfixUrl;
    }


    public static NativeArray jsFunction_searchAccessTokens(Context cx, Scriptable thisObj,
                                                            Object[] args,
                                                            Function funObj) throws AppManagementException {
        NativeObject tokenInfo;
        NativeArray tokenInfoArr = new NativeArray(0);
        if (args == null || !isStringValues(args)) {
            handleException("Invalid input parameters.");
        }
        String searchValue = (String) args[0];
        String searchTerm;
        String searchType;
        APIProvider apiProvider = getAPIProvider(thisObj);
        Map<Integer, APIKey> tokenData = null;
        String loggedInUser = ((APIProviderHostObject) thisObj).getUsername();

        if (searchValue.contains(":")) {
            searchTerm = searchValue.split(":")[1];
            searchType = searchValue.split(":")[0];
            if ("*".equals(searchTerm) || searchTerm.startsWith("*")) {
                searchTerm = searchTerm.replaceFirst("\\*", ".*");
            }
            tokenData = apiProvider.searchAccessToken(searchType, searchTerm, loggedInUser);
        } else {
            //Check whether old access token is already available
            if (apiProvider.isApplicationTokenExists(searchValue)) {
                APIKey tokenDetails = apiProvider.getAccessTokenData(searchValue);
                if (tokenDetails.getAccessToken() == null) {
                    throw new AppManagementException("The requested access token is already revoked or No access token available as per requested.");
                }
                tokenData = new HashMap<Integer, APIKey>();
                tokenData.put(0, tokenDetails);
            } else {
                if ("*".equals(searchValue) || searchValue.startsWith("*")) {
                    searchValue = searchValue.replaceFirst("\\*", ".*");
                }
                tokenData = apiProvider.searchAccessToken(null, searchValue, loggedInUser);
            }
        }
        if (tokenData != null && tokenData.size() != 0) {
            for (int i = 0; i < tokenData.size(); i++) {
                tokenInfo = new NativeObject();
                tokenInfo.put("token", tokenInfo, tokenData.get(i).getAccessToken());
                tokenInfo.put("user", tokenInfo, tokenData.get(i).getAuthUser());
                tokenInfo.put("scope", tokenInfo, tokenData.get(i).getTokenScope());
                tokenInfo.put("createTime", tokenInfo, tokenData.get(i).getCreatedDate());
                if (tokenData.get(i).getValidityPeriod() == Long.MAX_VALUE) {
                    tokenInfo.put("validTime", tokenInfo, "Won't Expire");
                } else {
                    tokenInfo.put("validTime", tokenInfo, tokenData.get(i).getValidityPeriod());
                }
                tokenInfo.put("consumerKey", tokenInfo, tokenData.get(i).getConsumerKey());
                tokenInfoArr.put(i, tokenInfoArr, tokenInfo);
            }
        } else {
            throw new AppManagementException("The requested access token is already revoked or No access token available as per requested.");
        }

        return tokenInfoArr;
    }

    public static boolean jsFunction_validateRoles(Context cx,
                                                   Scriptable thisObj, Object[] args,
                                                   Function funObj) {
        if (args == null || args.length==0) {
            return false;
        }

        boolean valid=false;
        String inputRolesSet = (String)args[0];
        String username=  (String) args[1];
        String[] inputRoles=null;
        if (inputRolesSet != null) {
            inputRoles = inputRolesSet.split(",");
        }

        try {
            String[] roles= AppManagerUtil.getRoleNames(username);

            if (roles != null && inputRoles != null) {
                for (String inputRole : inputRoles) {
                    for (String role : roles) {
                        valid= (inputRole.equals(role));
                        if(valid){ //If we found a match for the input role,then no need to process the for loop further
                            break;
                        }
                    }
                    //If the input role doesn't match with any of the role existing in the system
                    if(!valid){
                        return valid;
                    }

                }
                return valid;
            }
        }catch (Exception e) {
            log.error("Error while validating the input roles.",e);
        }

        return valid;
    }

    public static NativeArray jsFunction_getExternalAPIStores(Context cx,
                                                              Scriptable thisObj, Object[] args,
                                                              Function funObj)
            throws AppManagementException {
        Set<AppStore> apistoresList = AppManagerUtil.getExternalAPIStores();
        NativeArray myn = new NativeArray(0);
        if (apistoresList == null) {
            return null;
        } else {
            Iterator it = apistoresList.iterator();
            int i = 0;
            while (it.hasNext()) {
                NativeObject row = new NativeObject();
                Object apistoreObject = it.next();
                AppStore apiStore = (AppStore) apistoreObject;
                row.put("displayName", row, apiStore.getDisplayName());
                row.put("name", row, apiStore.getName());
                row.put("endpoint", row, apiStore.getEndpoint());

                myn.put(i, myn, row);
                i++;

            }
            return myn;
        }

    }

    /**
     * Returns the current subscription configuration defined in app-manager.xml.
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return Subscription Configuration
     * @throws AppManagementException
     */
    public static NativeObject jsFunction_getSubscriptionConfiguration(Context cx, Scriptable thisObj, Object[] args,
                                                                       Function funObj) throws AppManagementException {
        Map<String, Boolean> subscriptionConfigurationData = HostObjectUtils.getSubscriptionConfiguration();
        NativeObject subscriptionConfiguration = new NativeObject();
        for (Map.Entry<String, Boolean> entry : subscriptionConfigurationData.entrySet()) {
            subscriptionConfiguration.put(entry.getKey(), subscriptionConfiguration, entry.getValue().booleanValue());
        }
        return subscriptionConfiguration;
    }

    public static NativeObject jsFunction_getDefaultThumbnail(Context cx, Scriptable thisObj, Object[] args,
                                                              Function funObj) throws AppManagementException {
        if (args == null || args.length != 1) {
            throw new AppManagementException("Invalid number of arguments. Arguments length should be one.");
        }
        if (!(args[0] instanceof String)) {
            throw new AppManagementException("Invalid argument type. App name should be a String.");
        }
        String appName = (String) args[0];

        Map<String, String> defaultThumbnailData;
        try {
            defaultThumbnailData = HostObjectUtils.getDefaultThumbnail(appName);
        } catch (IllegalArgumentException e) {
            throw new AppManagementException("App name cannot be null or empty string.", e);
        }

        NativeObject defaultThumbnail = new NativeObject();
        for (Map.Entry<String, String> entry : defaultThumbnailData.entrySet()) {
            defaultThumbnail.put(entry.getKey(), defaultThumbnail, entry.getValue());
        }
        return defaultThumbnail;
    }

	/**
     * Returns the enabled asset type list in app-manager.xml
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static NativeArray jsFunction_getEnabledAssetTypeList(Context cx, Scriptable thisObj,
                                                                 Object[] args, Function funObj)
            throws AppManagementException {
        NativeArray availableAssetTypes = new NativeArray(0);
        List<String> typeList = HostObjectUtils.getEnabledAssetTypes();
        for (int i = 0; i < typeList.size(); i++) {
            availableAssetTypes.put(i, availableAssetTypes, typeList.get(i));
        }
        return availableAssetTypes;
    }

    /**
     * Returns asset type enabled or not in app-manager.xml
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static boolean jsFunction_isAssetTypeEnabled(Context cx, Scriptable thisObj,
                                                        Object[] args, Function funObj)
            throws AppManagementException {
        if (args == null || args.length != 1) {
            throw new AppManagementException(
                    "Invalid number of arguments. Arguments length should be one.");
        }
        if (!(args[0] instanceof String)) {
            throw new AppManagementException("Invalid argument type. App name should be a String.");
        }
        String assetType = (String) args[0];
        List<String> typeList = HostObjectUtils.getEnabledAssetTypes();

        for (String type : typeList) {
            if (assetType.equals(type)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns binary file storage location configured in app-manager.xml
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return file storage location
     * @throws AppManagementException
     */
    public static String jsFunction_getBinaryFileStorage(Context cx, Scriptable thisObj, Object[] args,
                                                         Function funObj) throws AppManagementException {
        return HostObjectUtils.getBinaryStorageConfiguration();
    }

    /**
     * Is Service Provider Create is enabled for skip gateway apps
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static boolean jsFunction_isSPCreateEnabledForSkipGatewayApps(Context cx, Scriptable thisObj, Object[] args,
                                                                         Function funObj) throws AppManagementException{
        return HostObjectUtils.isServiceProviderCreateEnabledForSkipGatewayApp();
    }

    /**
     * Remove mobile application binary files
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @throws AppManagementException
     */
    public static void jsFunction_removeBinaryFilesFromStorage(Context cx, Scriptable thisObj, Object[] args,
                                                         Function funObj) throws AppManagementException {
        if (args == null || args.length != 1) {
            throw new AppManagementException(
                    "Invalid number of arguments. Arguments length should be one.");
        }
        if (!(args[0] instanceof NativeArray)) {
            throw new AppManagementException("Invalid argument type. App name should be a String.");
        }
        APIProvider apiProvider = getAPIProvider(thisObj);
        NativeArray fileNames = (NativeArray) args[0];
        for (int i = 0; i < fileNames.getLength(); i++) {
            apiProvider.removeBinaryFromStorage(AppManagerUtil.resolvePath(HostObjectUtils.getBinaryStorageConfiguration(),
                    fileNames.get(i).toString()));
        }
    }

    /**
     * Returns the generated Issuer name
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static String jsFunction_populateIssuerName(Context cx, Scriptable thisObj, Object[] args,
                                                       Function funObj) throws AppManagementException {
        if (args == null || args.length != 2) {
            throw new AppManagementException(
                    "Invalid number of arguments. Arguments length should be one.");
        }

        String appName = (String) args[0];
        String version = (String) args[1];
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain(true);

        String saml2SsoIssuer;
        if (!"carbon.super".equalsIgnoreCase(tenantDomain)) {
            saml2SsoIssuer = appName + "-" + tenantDomain + "-" + version;
        } else {
            saml2SsoIssuer = appName + "-" + version;
        }
        return saml2SsoIssuer;
    }
}





