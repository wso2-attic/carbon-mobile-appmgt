/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.json.simple.JSONArray;
import org.json.simple.JSONValue;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.wso2.carbon.appmgt.api.APIConsumer;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.dto.AppVersionUserUsageDTO;
import org.wso2.carbon.appmgt.api.exception.AppUsageQueryServiceClientException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APIKey;
import org.wso2.carbon.appmgt.api.model.Application;
import org.wso2.carbon.appmgt.api.model.SubscribedAPI;
import org.wso2.carbon.appmgt.api.model.Subscriber;
import org.wso2.carbon.appmgt.api.model.Subscription;
import org.wso2.carbon.appmgt.api.model.Tier;
import org.wso2.carbon.appmgt.hostobjects.internal.HostObjectComponent;
import org.wso2.carbon.appmgt.hostobjects.internal.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.APIManagerFactory;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.UserAwareAPIConsumer;
import org.wso2.carbon.appmgt.impl.dao.AppMDAO;
import org.wso2.carbon.appmgt.impl.dto.UserRegistrationConfigDTO;
import org.wso2.carbon.appmgt.impl.dto.WorkflowDTO;
import org.wso2.carbon.appmgt.impl.idp.TrustedIdP;
import org.wso2.carbon.appmgt.impl.idp.WebAppIdPFactory;
import org.wso2.carbon.appmgt.impl.service.AppUsageStatisticsService;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.impl.utils.SelfSignUpUtil;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowConstants;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowException;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowExecutor;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowExecutorFactory;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowStatus;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.user.registration.stub.UserRegistrationAdminServiceException;
import org.wso2.carbon.identity.user.registration.stub.UserRegistrationAdminServiceStub;
import org.wso2.carbon.identity.user.registration.stub.dto.UserDTO;
import org.wso2.carbon.identity.user.registration.stub.dto.UserFieldDTO;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.stub.UserAdminStub;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.carbon.user.mgt.stub.types.carbon.FlaggedName;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;


public class APIStoreHostObject extends ScriptableObject {

    private static final long serialVersionUID = -3169012616750937045L;
    private static final Log log = LogFactory.getLog(APIStoreHostObject.class);
    private static final String hostObjectName = "AppStore";
    private static final String httpPort = "mgt.transport.http.port";
    private static final String httpsPort = "mgt.transport.https.port";
    private static final String hostName = "carbon.local.ip";

    private APIConsumer apiConsumer;

    private String username;

    public String getUsername() {
        return username;
    }

    @Override
    public String getClassName() {
        return hostObjectName;
    }

    // The zero-argument constructor used for create instances for runtime
    public APIStoreHostObject() throws AppManagementException {
        //apiConsumer = APIManagerFactory.getInstance().getAPIConsumer();
    }

    public APIStoreHostObject(String loggedUser) throws AppManagementException {
    	if (loggedUser != null) {
    		this.username = loggedUser;
    		apiConsumer = APIManagerFactory.getInstance().getAPIConsumer(username);
    	} else {
    		apiConsumer = APIManagerFactory.getInstance().getAPIConsumer();
    	}
    }

    public static void jsFunction_loadRegistryOfTenant(Context cx, Scriptable thisObj,
            Object[] args, Function funObj) {
        if (!isStringArray(args)) {
            return;
        }

        String tenantDomain = args[0].toString();
        if (tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME
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

    public static Scriptable jsConstructor(Context cx, Object[] args, Function Obj,
                                           boolean inNewExpr)
            throws ScriptException, AppManagementException {

        if (args!=null && args.length != 0) {
            String username = (String) args[0];
            return new APIStoreHostObject(username);
        }
        return new APIStoreHostObject(null);
    }

    private static String getUsernameFromObject(Scriptable obj) {
        return ((APIStoreHostObject) obj).getUsername();
    }

    public APIConsumer getApiConsumer() {
        return apiConsumer;
    }

    private static APIConsumer getAPIConsumer(Scriptable thisObj) {
        return ((APIStoreHostObject) thisObj).getApiConsumer();
    }

    private static void handleException(String msg) throws AppManagementException {
        log.error(msg);
        throw new AppManagementException(msg);
    }

    private static void handleException(String msg, Throwable t) throws AppManagementException {
        log.error(msg, t);
        throw new AppManagementException(msg, t);
    }

    public static String jsFunction_getAuthServerURL(Context cx, Scriptable thisObj,
                                                     Object[] args, Function funObj) throws
                                                                                     AppManagementException {

        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
        if (url == null) {
            handleException("WebApp key manager URL unspecified");
        }
        return url;
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
            handleException("Identity provider URL unspecified in <IdentityProviderUrl> element in appmanager.xml");
        }
        return url;
    }
    
    public static String jsFunction_getHTTPsURL(Context cx, Scriptable thisObj,
                                                Object[] args, Function funObj)
            throws AppManagementException {
    	
    	String hostName = null;
    	if (args != null && isStringArray(args)) {
    		hostName = (String)args[0];
    		URI uri;
			try {
				uri = new URI(hostName);
				hostName = uri.getHost();
			} catch (URISyntaxException e) {
				//ignore
			}
    	} 
                
        if (hostName == null) {
        	hostName = CarbonUtils.getServerConfiguration().getFirstProperty("HostName");
        }
        if (hostName == null) {
        	hostName = System.getProperty("carbon.local.ip");
        }
        String backendHttpsPort = HostObjectUtils.getBackendPort("https");
        return "https://" + hostName + ":" + backendHttpsPort;

    }


    public static String jsFunction_getHTTPURL(Context cx, Scriptable thisObj,
                                               Object[] args, Function funObj)
            throws AppManagementException {
        return "http://" + System.getProperty(hostName) + ":" + System.getProperty(httpPort);
    }

    public static NativeObject jsFunction_login(Context cx, Scriptable thisObj,
                                                Object[] args, Function funObj) throws ScriptException,
                                                                                       AppManagementException {
        if (args==null || args.length == 0||!isStringArray(args)) {
            handleException("Invalid input parameters for the login method");
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
            AuthenticationAdminStub authAdminStub = new AuthenticationAdminStub(null, url + "AuthenticationAdmin");
            ServiceClient client = authAdminStub._getServiceClient();
            Options options = client.getOptions();
            options.setManageSession(true);

            String host = new URL(url).getHost();
            if (!authAdminStub.login(username, password, host)) {
                handleException("Login failed! Please recheck the username and password and try again.");
            }
            ServiceContext serviceContext = authAdminStub.
                    _getServiceClient().getLastOperationContext().getServiceContext();
            String sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);

            String usernameWithDomain = AppManagerUtil.getLoggedInUserInfo(sessionCookie,url).getUserName();
            usernameWithDomain = AppManagerUtil.setDomainNameToUppercase(usernameWithDomain);

            boolean isSuperTenant = false;
            
            if (tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
            	isSuperTenant = true;
            }else {
                usernameWithDomain = usernameWithDomain + "@"+tenantDomain;
            }

            boolean authorized =
                    AppManagerUtil.checkPermissionQuietly(usernameWithDomain, AppMConstants.Permissions.WEB_APP_SUBSCRIBE);


            if (authorized) {
                row.put("user", row, usernameWithDomain);
                row.put("sessionId", row, sessionCookie);
                row.put("isSuperTenant", row, isSuperTenant);
                row.put("error", row, false);
            } else {
                handleException("Login failed! Insufficient Privileges.");
            }
        } catch (Exception e) {
            row.put("error", row, true);
            row.put("detail", row, e.getMessage());
        }

        return row;
    }

    /**
     * Given a base 64 encoded username:password string,
     * this method checks if said user has enough privileges to advance a workflow.
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws ScriptException
     * @throws WorkflowException
     */
    public static NativeObject jsFunction_validateWFPermission(Context cx, Scriptable thisObj,
                                                Object[] args, Function funObj) throws ScriptException,
                                                                                       AppManagementException {
        if (args==null || args.length == 0||!isStringArray(args)) {
            throw new AppManagementException("Invalid input parameters for authorizing workflow progression.");
        }

        NativeObject row = new NativeObject();

        String reqString = (String) args[0];
        String authType = reqString.split("\\s+")[0];
        String encodedString = reqString.split("\\s+")[1];
        if(!HttpTransportProperties.Authenticator.BASIC.equals(authType)){
            //throw new AppManagementException("Invalid Authorization Header Type");
            row.put("error", row, true);
            row.put("statusCode", row, 401);
            row.put("message", row, "Invalid Authorization Header Type");
            return row;
        }

        byte[] decoded = Base64.decodeBase64(encodedString.getBytes());

        String decodedString = new String(decoded);

        if(decodedString.isEmpty() || !decodedString.contains(":")){
            //throw new AppManagementException("Invalid number of arguments. Please provide a valid username and password.");
            row.put("error", row, true);
            row.put("statusCode", row, 401);
            row.put("message", row, "Invalid Authorization Header Value");
            return row;
        }

        String username = decodedString.split(":")[0];
        String password = decodedString.split(":")[1];

        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        //String url = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
        //if (url == null) {
        //    throw new AppManagementException("WebApp key manager URL unspecified");
        //}

        try {
            RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();

            int tenantId=ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(username));

            org.wso2.carbon.user.api.UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            Boolean authStatus = userStoreManager.authenticate(username, password);

            if(!authStatus){
                //throw new WorkflowException("Please recheck the username and password and try again.");
                row.put("error", row, true);
                row.put("statusCode", row, 401);
                row.put("message", row, "Authentication Failure. Please recheck username and password");
                return row;
            }

            String tenantDomain = MultitenantUtils.getTenantDomain(username);

            String usernameWithDomain = AppManagerUtil.setDomainNameToUppercase(username);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                usernameWithDomain = usernameWithDomain + "@"+tenantDomain;
            }

            boolean authorized = AppManagerUtil.checkPermissionQuietly(usernameWithDomain, AppMConstants.Permissions.APP_WORKFLOWADMIN);

            if (authorized) {
                row.put("error", row, false);
                row.put("statusCode", row, 200);
                row.put("message", row, "Authorization Successful");
                return row;
            } else {
                //handleException("Login failed! Insufficient Privileges.");
                row.put("error", row, true);
                row.put("statusCode", row, 403);
                row.put("message", row, "Forbidden. User not authorized to perform action");
                return row;
            }
        } catch (Exception e) {
            row.put("error", row, true);
            row.put("statusCode", row, 500);
            row.put("message", row, e.getMessage());
            return row;
        }
    }

    public static boolean jsFunction_isSelfSignupEnabled(){
        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        return Boolean.parseBoolean(config.getFirstProperty(AppMConstants.SELF_SIGN_UP_ENABLED));
    }

    private static String filterUrls(String apiData, String transports) {
        if(apiData != null && transports !=null){
            List<String> urls = new ArrayList<String>();
            List<String> transportList = new ArrayList<String>();
            urls.addAll(Arrays.asList(apiData.split(",")));
            transportList.addAll(Arrays.asList(transports.split(",")));
            urls = filterUrlsByTransport(urls, transportList, "https");
            urls = filterUrlsByTransport(urls, transportList, "http");
            String urlString = urls.toString();
            return urlString.substring(1, urlString.length() - 1);
        }
        return apiData;
    }

    private static List<String> filterUrlsByTransport(List<String> urlsList, List<String> transportList, String transportName) {
        if(!transportList.contains(transportName)){
            ListIterator<String> it = urlsList.listIterator();
            while(it.hasNext()){
                String url = it.next();
                if(url.startsWith(transportName+":")){
                    it.remove();
                }
            }
            return urlsList;
        }
        return urlsList;
    }

    public static boolean jsFunction_isSubscribed(Context cx, Scriptable thisObj,
                                                  Object[] args, Function funObj)
            throws ScriptException,
                   AppManagementException {

        String username = null;
        if (args != null && args.length != 0) {
            String providerName = (String) args[0];
            String apiName = (String) args[1];
            String version = (String) args[2];
            if (args[3] != null) {
                username = (String) args[3];
            }
            APIIdentifier apiIdentifier = new APIIdentifier(providerName, apiName, version);
            APIConsumer apiConsumer = getAPIConsumer(thisObj);
            return username != null && apiConsumer.isSubscribed(apiIdentifier, username);
        } else {
            throw new AppManagementException("No input username value.");
        }
    }

    /**
     * Returns the subscription for the given criteria based on the subscription type. e.g. Individual, Enterprise
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    public static NativeObject jsFunction_getSubscription(Context cx,
                                         Scriptable thisObj, Object[] args, Function funObj)throws
                                                                                            AppManagementException {

        APIConsumer apiConsumer = getAPIConsumer(thisObj);

        String providerName = (String)args[0];
        providerName= AppManagerUtil.replaceEmailDomain(providerName);
        String apiName = (String)args[1];
        String version = (String)args[2];
        String applicationName = (String)args[3];
        String subscriptionType = (String)args[4];
        String userId = (String)args[5];

        int applicationId = AppManagerUtil.getApplicationId(applicationName,userId);

        APIIdentifier apiIdentifier = new APIIdentifier(providerName, apiName, version);

        NativeObject subscriptionToReturn = null;

        try {
            Subscription subscription = apiConsumer.getSubscription(apiIdentifier, applicationId, subscriptionType);

            if(subscription != null){
                subscriptionToReturn = new NativeObject();

                subscriptionToReturn.put("subscriptionId", subscriptionToReturn, subscription.getSubscriptionId());
                subscriptionToReturn.put("webAppId", subscriptionToReturn, subscription.getWebAppId());
                subscriptionToReturn.put("applicationId", subscriptionToReturn, subscription.getApplicationId());
                subscriptionToReturn.put("subscriptionType", subscriptionToReturn, subscription.getSubscriptionType());
                subscriptionToReturn.put("subscriptionStatus",subscriptionToReturn,subscription.getSubscriptionStatus());
                subscriptionToReturn.put("subscriptionTime",subscriptionToReturn,subscription.getSubscriptionTime());
                subscriptionToReturn.put("subscribedUser",subscriptionToReturn,subscription.getUserId());

                Set<String> trustedIdps = subscription.getTrustedIdps();

                String trustedIdpsJsonString = "[]";
                if(trustedIdps != null) {
                    JSONArray jsonArray = new JSONArray();

                    for (String idp : trustedIdps) {
                        jsonArray.add(idp);
                    }

                    trustedIdpsJsonString = JSONValue.toJSONString(jsonArray);
                }

                subscriptionToReturn.put("trustedIdps", subscriptionToReturn, trustedIdpsJsonString);

            }

            return subscriptionToReturn;

        } catch (AppManagementException e) {
            handleException("Error while getting subscription", e);
            return null;
        }

    }

    /**
     * This method takes care of updating the visibiltiy of an app to given user role.
     * It will be invoked when subscribing / un-subscribing to an app in the store.
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     */
    public static boolean jsFunction_updateAPPVisibility(Context cx,
                                                        Scriptable thisObj, Object[] args, Function funObj) {
        if(!isStringArray(args)) {
            return false;
        }

        String providerName = args[0].toString();
        String apiName = args[1].toString();
        String version = args[2].toString();
        String userName = args[3].toString();
        String optype = args[4].toString();
        String userRole = "Internal/private_"+userName;

        APIIdentifier apiIdentifier = new APIIdentifier(providerName, apiName, version);
        String apiPath = "/_system/governance"+AppManagerUtil.getAPIPath(apiIdentifier);
        try {
            if(optype.equalsIgnoreCase("ALLOW")) {
                org.wso2.carbon.user.api.UserRealm realm = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
                realm.getAuthorizationManager().authorizeRole(userRole, apiPath, ActionConstants.GET);
                return true;
            }else if(optype.equalsIgnoreCase("DENY")){
                org.wso2.carbon.user.api.UserRealm realm = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
                realm.getAuthorizationManager().denyRole(userRole, apiPath, ActionConstants.GET);
                return true;
            }
            return false;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error while updating visibility of Web App : " + apiName +" at "+apiPath, e);
            return false;
        }
    }

    public static boolean jsFunction_removeSubscriber(Context cx,
                                                      Scriptable thisObj, Object[] args, Function funObj)
            throws AppManagementException {
        String providerName = "";
        String apiName = "";
        String version = "";
        String application = "";
        String userId = "";
        if (args!=null && args.length!=0 ) {
            providerName = (String)args[0];
            apiName = (String)args[1];
            version = (String)args[2];
            application = (String) args[3];
            userId = (String)args[4];
        }
        APIIdentifier apiIdentifier = new APIIdentifier(providerName, apiName, version);
        apiIdentifier.setApplicationId(application);
        APIConsumer apiConsumer = getAPIConsumer(thisObj);
        try {
            apiConsumer.removeSubscriber(apiIdentifier, userId);
            return true;
        } catch (AppManagementException e) {
            handleException("Error while removing subscriber: " + userId, e);
            return false;
        }

    }

    public static NativeArray jsFunction_getSubscriptions(Context cx,
                                                          Scriptable thisObj, Object[] args, Function funObj)
            throws ScriptException, AppManagementException {

        NativeArray myn = new NativeArray(0);
        if (args!=null && args.length!=0 ) {
            String providerName = (String)args[0];
            String apiName = (String)args[1];
            String version = (String)args[2];
            String user = (String)args[3];

            APIIdentifier apiIdentifier = new APIIdentifier(AppManagerUtil.replaceEmailDomain(providerName), apiName, version);
            Subscriber subscriber = new Subscriber(user);
            APIConsumer apiConsumer = getAPIConsumer(thisObj);
            Set<SubscribedAPI> apis = apiConsumer.getSubscribedIdentifiers(subscriber, apiIdentifier);
            int i = 0;
            if(apis!=null){
                for (SubscribedAPI api : apis) {
                    NativeObject row = new NativeObject();
                    row.put("application", row, api.getApplication().getName());
                    row.put("applicationId", row, api.getApplication().getId());
                    row.put("prodKey", row, getKey(api, AppMConstants.API_KEY_TYPE_PRODUCTION));
                    row.put("sandboxKey", row, getKey(api, AppMConstants.API_KEY_TYPE_SANDBOX));
                    myn.put(i++, myn, row);

                }
            }
        }
        return myn;
    }

    public static String jsFunction_getSwaggerDiscoveryUrl(Context cx,
                                                           Scriptable thisObj, Object[] args,
                                                           Function funObj)
            throws AppManagementException {
        String apiName;
        String version;
        String providerName;
        
        if (args != null && args.length != 0 ) {

            apiName = (String) args[0];
            version = (String) args[1];
            providerName = (String) args[2];
            
            String apiDefinitionFilePath = AppManagerUtil.getAPIDefinitionFilePath(apiName, version);
            apiDefinitionFilePath = RegistryConstants.PATH_SEPARATOR + "registry"
            		+ RegistryConstants.PATH_SEPARATOR + "resource"
            		+ RegistryConstants.PATH_SEPARATOR + "_system"
            		+ RegistryConstants.PATH_SEPARATOR + "governance"
            		+ apiDefinitionFilePath;
            
            apiDefinitionFilePath = AppManagerUtil.prependTenantPrefix(apiDefinitionFilePath, providerName);
            
            return AppManagerUtil.prependWebContextRoot(apiDefinitionFilePath);
            
        } else {
            handleException("Invalid input parameters.");
            return null;
        }
    }

    private static APIKey getKey(SubscribedAPI api, String keyType) {
        List<APIKey> apiKeys = api.getKeys();
        return getKeyOfType(apiKeys, keyType);
    }

    private static APIKey getAppKey(Application app, String keyType) {
        List<APIKey> apiKeys = app.getKeys();
        return getKeyOfType(apiKeys, keyType);
    }

    private static APIKey getKeyOfType(List<APIKey> apiKeys, String keyType) {
        for (APIKey key : apiKeys) {
            if (keyType.equals(key.getType())) {
                return key;
            }
        }
        return null;
    }

    public static NativeObject jsFunction_getSubscriber(Context cx,
                                                        Scriptable thisObj, Object[] args, Function funObj)
            throws ScriptException, AppManagementException {

        if (args != null && isStringArray(args)) {
            NativeObject user = new NativeObject();
            String userName = args[0].toString();
            Subscriber subscriber = null;
            APIConsumer apiConsumer = getAPIConsumer(thisObj);
            try {
                subscriber = apiConsumer.getSubscriber(userName);
            } catch (AppManagementException e) {
                handleException("Error while getting Subscriber", e);
            } catch (Exception e) {
                handleException("Error while getting Subscriber", e);
            }

            if (subscriber != null) {
                user.put("name", user, subscriber.getName());
                user.put("id", user, subscriber.getId());
                user.put("email", user, subscriber.getEmail());
                user.put("subscribedDate", user, subscriber.getSubscribedDate());
                return user;
            }
        }
        return null;
    }

    private static boolean addSubscriber(String userId, Scriptable thisObj)
            throws ScriptException, AppManagementException, UserStoreException {

        APIConsumer apiConsumer = getAPIConsumer(thisObj);
        Subscriber subscriber = apiConsumer.getSubscriber(userId);
        if (subscriber == null) {
            subscriber = new Subscriber(userId);
            subscriber.setSubscribedDate(new Date());
            //TODO : need to set the proper email
            subscriber.setEmail("");
            try {
                int tenantId =
                        ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                                              .getTenantId(
                                                      MultitenantUtils.getTenantDomain(userId));
                subscriber.setTenantId(tenantId);
                apiConsumer.addSubscriber(subscriber);
            } catch (AppManagementException e) {
                handleException("Error while adding the subscriber" + subscriber.getName(), e);
                return false;
            } catch (Exception e) {
                handleException("Error while adding the subscriber" + subscriber.getName(), e);
                return false;
            }
            return true;
        }
        return false;
    }


    public static boolean jsFunction_sleep(Context cx,
                                           Scriptable thisObj, Object[] args, Function funObj){
        if (isStringArray(args)) {
            String millis = (String) args[0];
            try {
                Thread.sleep( Long.valueOf(millis));
            } catch (InterruptedException e) {
                log.error("Sleep Thread Interrupted");
                return false;
            }
        }
        return true;
    }

    public static NativeObject jsFunction_resumeWorkflow(Context cx,
                                                       Scriptable thisObj, Object[] args, Function funObj)
            throws ScriptException, WorkflowException {

        NativeObject row = new NativeObject();

        if (args!=null && isStringArray(args)) {

            String workflowReference = (String) args[0];
            String status = (String) args[1];
            String description = null;
            if(args.length > 2){
                description = (String) args[2];
            }

            AppMDAO appMDAO = new AppMDAO();

            try {
                if(workflowReference!=null){
                    WorkflowDTO workflowDTO = appMDAO.retrieveWorkflow(workflowReference);

                    if(workflowDTO == null){
                        log.error("Could not find workflow for reference " + workflowReference);
                        row.put("error", row, true);
                        row.put("statusCode", row, 500);
                        row.put("message", row, "Could not find workflow for reference " + workflowReference);
                        return row;
                    }

                    workflowDTO.setWorkflowDescription(description);
                    workflowDTO.setStatus(WorkflowStatus.valueOf(status));

                    String workflowType = workflowDTO.getWorkflowType();
                    WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.getInstance()
                            .getWorkflowExecutor(workflowType);

                    workflowExecutor.complete(workflowDTO);
                    row.put("error", row, false);
                    row.put("statusCode", row, 200);
                    row.put("message", row, "Invoked workflow completion successfully.");
                }
            } catch (IllegalArgumentException e){
                row.put("error", row, true);
                row.put("statusCode", row, 500);
                row.put("message", row, "Illegal argument provided. Valid values for status are APPROVED and REJECTED.");
            } catch (AppManagementException e) {
                row.put("error", row, true);
                row.put("statusCode", row, 500);
                row.put("message", row, "Error while resuming workflow. " + e.getMessage());
            }
        }
        return row;
    }

    /*
      * here return boolean with checking all objects in array is string
      */
    public static boolean isStringArray(Object[] args) {
        int argsCount = args.length;
        for (int i = 0; i < argsCount; i++) {
            if (!(args[i] instanceof String)) {
                return false;
            }
        }
        return true;

    }

    public static boolean jsFunction_hasSubscribePermission(Context cx, Scriptable thisObj,
                                                            Object[] args,
                                                            Function funObj)
            throws ScriptException {
        APIConsumer consumer = getAPIConsumer(thisObj);
        if (consumer instanceof UserAwareAPIConsumer) {
            try {
                ((UserAwareAPIConsumer) consumer).checkSubscribePermission();
                return true;
            } catch (AppManagementException e) {
                return false;
            }
        }
        return false;
    }

    public static void jsFunction_addUser(Context cx, Scriptable thisObj, Object[] args, Function funObj)
            throws AppManagementException {
        String customErrorMsg = null;

        if (args != null && isStringArray(args)) {
            String username = args[0].toString();
            String password = args[1].toString();


            AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
            /*
             * boolean workFlowEnabled =
             * Boolean.parseBoolean(config.getFirstProperty
             * (APIConstants.SELF_SIGN_UP_ENABLED));
             * if (!workFlowEnabled) {
             * handleException("Self sign up has been disabled on this server");
             * }
             */
            String serverURL = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
            String tenantDomain = MultitenantUtils.getTenantDomain(AppManagerUtil.replaceEmailDomainBack(username));


            boolean isTenantFlowStarted = false;

            try {

                if (tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    isTenantFlowStarted = true;
                    PrivilegedCarbonContext.startTenantFlow();
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                }
                int tenantId =
                        ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                                .getTenantId(tenantDomain);

                // get the signup configuration
                UserRegistrationConfigDTO signupConfig = SelfSignUpUtil.getSignupConfiguration(tenantId);
                // set tenant specific sign up user storage
                if (signupConfig != null && !("".equals(signupConfig.getSignUpDomain()))) {
                    if (!signupConfig.isSignUpEnabled()) {
                        handleException("Self sign up has been disabled for this tenant domain");
                    }
                    int index = username.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
                    /*
                     * if there is a different domain provided by the user other than one given in the configuration,
                     * add the correct signup domain. Here signup domain refers to the user storage
                     */

                    if (index > 0) {
                        username =
                                signupConfig.getSignUpDomain().toUpperCase() + UserCoreConstants.DOMAIN_SEPARATOR +
                                        username.substring(index + 1);
                    } else {
                        username =
                                signupConfig.getSignUpDomain().toUpperCase() + UserCoreConstants.DOMAIN_SEPARATOR +
                                        username;
                    }
                }

                // check whether admin credentials are correct.
                boolean validCredentials = checkCredentialsForAuthServer(
                        signupConfig.getAdminUserName(), signupConfig.getAdminPassword(), serverURL);

                if (validCredentials) {
                    UserDTO userDTO = new UserDTO();
                    userDTO.setUserName(username);
                    userDTO.setPassword(password);

                    UserRegistrationAdminServiceStub stub = new UserRegistrationAdminServiceStub(null, serverURL +
                            "UserRegistrationAdminService");
                    CarbonUtils.setBasicAccessSecurityHeaders(signupConfig.getAdminUserName(),
                            signupConfig.getAdminPassword(), true, stub._getServiceClient());
                    stub.addUser(userDTO);

                    WorkflowExecutor userSignUpWFExecutor = WorkflowExecutorFactory.getInstance()
                            .getWorkflowExecutor(WorkflowConstants.WF_TYPE_AM_USER_SIGNUP);

                    WorkflowDTO signUpWFDto = new WorkflowDTO();
                    signUpWFDto.setWorkflowReference(username);
                    signUpWFDto.setStatus(WorkflowStatus.CREATED);
                    signUpWFDto.setCreatedTime(System.currentTimeMillis());
                    signUpWFDto.setTenantDomain(tenantDomain);
                    signUpWFDto.setTenantId(tenantId);
                    signUpWFDto.setExternalWorkflowReference(userSignUpWFExecutor.generateUUID());
                    signUpWFDto.setWorkflowType(WorkflowConstants.WF_TYPE_AM_USER_SIGNUP);
                    signUpWFDto.setCallbackUrl(userSignUpWFExecutor.getCallbackURL());

                    try {
                        userSignUpWFExecutor.execute(signUpWFDto);
                    } catch (WorkflowException e) {
                        log.error("Unable to execute User SignUp Workflow", e);
                        // removeUser(username, config, serverURL);
                        removeTenantUser(username, signupConfig, serverURL);

                        handleException("Unable to execute User SignUp Workflow", e);
                    }
                } else {
                    customErrorMsg =
                            "Unable to add a user. Please check credentials in "
                                    + "the signup-config.xml in the registry";
                    handleException(customErrorMsg);
                }

            } catch (RemoteException e) {
                handleException(e.getMessage(), e);
            } catch (UserRegistrationAdminServiceException e) {
                handleException("Error while adding the user: " + username + ". " + e.getMessage(), e);
            } catch (WorkflowException e) {
                handleException("Error while adding the user: " + username + ". " + e.getMessage(), e);
            } catch (UserAdminUserAdminException e) {
                handleException("Error while adding the user: " + username + ". " + e.getMessage(), e);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                handleException("Error while retrieving tenant id for tenant domain : " + tenantDomain, e);
            } finally {
                if (isTenantFlowStarted) {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            }
        } else {
            handleException("Invalid input parameters.");
        }
    }

    /**
     * check whether UserAdmin service can be accessed using the admin credentials in the
     *
     * @param userName
     * @param password
     * @param serverURL
     * @return
     */
    private static boolean checkCredentialsForAuthServer(String userName, String password, String serverURL) {

        boolean status = false;
        try {
            UserAdminStub userAdminStub = new UserAdminStub(null, serverURL + "UserAdmin");
            CarbonUtils.setBasicAccessSecurityHeaders(userName, password, true,
                    userAdminStub._getServiceClient());
            //send a request. if exception occurs, then the credentials are not correct.
            FlaggedName[] roles = userAdminStub.getRolesOfCurrentUser();
            status = true;
        } catch (RemoteException e) {
            log.error("Error while accessing UserAdminService", e);
            status = false;
        } catch (UserAdminUserAdminException e) {
            log.error("Error in checking admin credentials. Please check credentials in "
                    + "the signup-config.xml in the registry. ");
            status = false;
        }
        return status;
    }

    /**
     * remove tenant user
     *
     * @param username
     * @param signupConfig tenant based configuration
     * @param serverURL
     * @throws RemoteException
     * @throws UserAdminUserAdminException
     */
    private static void removeTenantUser(String username, UserRegistrationConfigDTO signupConfig,
                                         String serverURL) throws RemoteException,
            UserAdminUserAdminException {
        UserAdminStub userAdminStub = new UserAdminStub(null, serverURL + "UserAdmin");
        String adminUsername = signupConfig.getAdminUserName();
        String adminPassword = signupConfig.getAdminPassword();

        CarbonUtils.setBasicAccessSecurityHeaders(adminUsername, adminPassword, true,
                userAdminStub._getServiceClient());
        String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
        int index = tenantAwareUserName.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
        //remove the 'PRIMARY' part from the user name
        if (index > 0) {
            if (tenantAwareUserName.substring(0, index)
                    .equalsIgnoreCase(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME)) {
                tenantAwareUserName = tenantAwareUserName.substring(index + 1);
            }
        }
        userAdminStub.deleteUser(tenantAwareUserName);
    }

    private static void removeUser(String username, AppManagerConfiguration config, String serverURL) throws RemoteException, UserAdminUserAdminException {
        UserAdminStub userAdminStub = new UserAdminStub(null, serverURL
                + "UserAdmin");
        String adminUsername = config.getFirstProperty(AppMConstants.AUTH_MANAGER_USERNAME);
        String adminPassword = config.getFirstProperty(AppMConstants.AUTH_MANAGER_PASSWORD);

        CarbonUtils.setBasicAccessSecurityHeaders(adminUsername, adminPassword,
                true, userAdminStub._getServiceClient());
        userAdminStub.deleteUser(username);
    }

    /**
     * Check for user existance for given user name
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws ScriptException
     * @throws AppManagementException
     * @throws org.wso2.carbon.user.api.UserStoreException
     */
    public static boolean jsFunction_isUserExists(Context cx, Scriptable thisObj, Object[] args, Function funObj)
            throws ScriptException, AppManagementException, org.wso2.carbon.user.api.UserStoreException {

        if (args == null || args.length == 0) {
            handleException("Invalid input parameters to the isUserExists method");
        }

        String username = (String) args[0];
        boolean exists = false;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(AppManagerUtil.replaceEmailDomainBack(username));
            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRegistrationConfigDTO signupConfig = SelfSignUpUtil.getSignupConfiguration(tenantId);
            //add user storage info
            username = SelfSignUpUtil.getDomainSpecificUserName(username, signupConfig);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);

            RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
            //UserRealm realm = realmService.getBootstrapRealm();
            UserRealm realm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            UserStoreManager manager = realm.getUserStoreManager();
            if (manager.isExistingUser(tenantAwareUserName)) {
                exists = true;
            }
        } catch (UserStoreException e) {
            handleException("Error while checking user existence for " + username);
        }
        return exists;
    }

    /**
     * Check whether the self sign-up is enable for the given tenant domain
     *
     * @param cx      context
     * @param thisObj
     * @param args
     * @param funObj
     * @return 'true' if self sign-up is enabled, else 'false'
     * @throws AppManagementException
     */
    public static boolean jsFunction_isSelfSignupEnabledForTenant(
            Context cx, Scriptable thisObj, Object[] args, Function funObj) throws AppManagementException {
        boolean status = false;
        if (!isStringArray(args)) {
            return status;
        }
        if (args == null || args.length != 1) {
            handleException("Invalid number of parameters.");
        }

        String tenantDomain = args[0].toString();
        try {
            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRegistrationConfigDTO signupConfig = SelfSignUpUtil.getSignupConfiguration(tenantId);
            if (signupConfig != null) {
                status = signupConfig.isSignUpEnabled();
            }
        } catch (AppManagementException e) {
            log.error("Error occurred while reading self sign-up configuration from registry for tenant domain : " +
                    tenantDomain, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error occurred while retrieving tenant id for tenant domain : " +
                    tenantDomain + " during self sign-up configuration read time.");
        }
        return status;

    }

    public static boolean jsFunction_removeSubscription(Context cx, Scriptable thisObj,
                                                        Object[] args,
                                                        Function funObj)
            throws AppManagementException {
        if (args==null|| args.length == 0) {
            handleException("Invalid number of input parameters.");
        }
        String username = (String)args[0];
        int applicationId = ((Number) args[1]).intValue();
        NativeObject apiData = (NativeObject) args[2];
        String provider = AppManagerUtil.replaceEmailDomain((String) apiData.get("provider", apiData));
        String name = (String) apiData.get("apiName", apiData);
        String version = (String) apiData.get("version", apiData);
        APIIdentifier apiId = new APIIdentifier(provider, name, version);

        APIConsumer apiConsumer = getAPIConsumer(thisObj);
        try {
            apiConsumer.removeSubscription(apiId, username, applicationId);
            return true;
        } catch (AppManagementException e) {
            handleException("Error while removing the subscription of" + name + "-" + version, e);
            return false;
      }
    }

    public static boolean jsFunction_removeAPISubscription(Context cx, Scriptable thisObj,
                                                        Object[] args,
                                                        Function funObj)
            throws AppManagementException {
        if (args==null|| args.length == 0) {
            handleException("Invalid number of input parameters.");
        }
        String username = (String)args[3];
        String applicationName = (String)args[2];
        NativeObject apiData = (NativeObject) args[0];

        String provider = AppManagerUtil.replaceEmailDomain((String) apiData.get("provider", apiData));
        String name = (String) apiData.get("name", apiData);
        String version = (String) apiData.get("version", apiData);
        APIIdentifier apiId = new APIIdentifier(provider, name, version);

        APIConsumer apiConsumer = getAPIConsumer(thisObj);
        try {
            apiConsumer.removeAPISubscription(apiId, username, applicationName);
            return true;
        } catch (AppManagementException e) {
            handleException("Error while removing the subscription of" + name + "-" + version, e);
            return false;
        }
    }

    /**
     * Given a name of a user the function checks whether the subscriber role is present
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     * @throws AxisFault
     */
    public static NativeObject jsFunction_checkIfSubscriberRoleAttached (Context cx, Scriptable thisObj,
                                                           Object[] args,
                                                           Function funObj) throws
                                                                            AppManagementException, AxisFault {
        String userName = (String) args[0];
        Boolean valid;

        NativeObject row = new NativeObject();

        if(userName!=null){
            AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
            String serverURL = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);

            UserAdminStub userAdminStub = new UserAdminStub(null, serverURL + "UserAdmin");
            String adminUsername = config.getFirstProperty(AppMConstants.AUTH_MANAGER_USERNAME);
            String adminPassword = config.getFirstProperty(AppMConstants.AUTH_MANAGER_PASSWORD);

            CarbonUtils.setBasicAccessSecurityHeaders(adminUsername, adminPassword,
                    true, userAdminStub._getServiceClient());
            try {
                    valid = AppManagerUtil.checkPermissionQuietly(userName, AppMConstants.Permissions.WEB_APP_SUBSCRIBE);
                    if(valid){
                        row.put("error", row, false);
                        return row;
                    }
            } catch (Exception e) {
                handleException(e.getMessage(), e);
                row.put("error", row, true);
                row.put("message", row, "Error while checking if " + userName + " has subscriber role.");
                return row;
            }
            row.put("error", row, true);
            row.put("message", row, "User does not have subscriber role.");
            return row;
        }else{
            row.put("error", row, true);
            row.put("message", row, "Please provide a valid username");
            return row;
        }
    }



    public static NativeArray jsFunction_getAPIUsageforSubscriber(Context cx, Scriptable thisObj,
                                                                  Object[] args, Function funObj)
            throws AppManagementException {
        List<AppVersionUserUsageDTO> list = null;
        if (args==null || args.length == 0) {
            handleException("Invalid number of parameters.");
        }
        NativeArray myn = new NativeArray(0);
//        if (!HostObjectUtils.checkDataPublishingEnabled()) {
//            return myn;
//        }
        String subscriberName = (String) args[0];
        String period = (String) args[1];

        try {
            AppUsageStatisticsService appUsageStatisticsService = new
                    AppUsageStatisticsService(((APIProviderHostObject) thisObj).getUsername());
            list = appUsageStatisticsService.
                    getUsageBySubscriber(subscriberName, period);
        } catch (AppUsageQueryServiceClientException e) {
            handleException("Error while invoking AbstractAppUsageStatisticsClient for ProviderAPIUsage", e);
        } catch (Exception e) {
            handleException("Error while invoking AbstractAppUsageStatisticsClient for ProviderAPIUsage", e);
        }

        Iterator it = null;

        if (list != null) {
            it = list.iterator();
        }
        int i = 0;
        if (it != null) {
            while (it.hasNext()) {
                NativeObject row = new NativeObject();
                Object usageObject = it.next();
                AppVersionUserUsageDTO usage = (AppVersionUserUsageDTO) usageObject;
                row.put("api", row, usage.getApiname());
                row.put("version", row, usage.getVersion());
                row.put("count", row, usage.getCount());
                row.put("costPerAPI", row, usage.getCostPerAPI());
                row.put("cost", row, usage.getCost());
                myn.put(i, myn, row);
                i++;

            }
        }
        return myn;
    }


    public static boolean jsFunction_isCommentActivated() throws AppManagementException {

        boolean commentActivated = false;
        AppManagerConfiguration config =
                ServiceReferenceHolder.getInstance()
                        .getAPIManagerConfigurationService()
                        .getAPIManagerConfiguration();

        commentActivated = Boolean.valueOf(config.getFirstProperty(AppMConstants.API_STORE_DISPLAY_COMMENTS));

        if (commentActivated) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean jsFunction_isRatingActivated() throws AppManagementException {

        boolean ratingActivated = false;
        AppManagerConfiguration config =
                ServiceReferenceHolder.getInstance()
                        .getAPIManagerConfigurationService()
                        .getAPIManagerConfiguration();

        ratingActivated = Boolean.valueOf(config.getFirstProperty(AppMConstants.API_STORE_DISPLAY_RATINGS));

        if (ratingActivated) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return true if billing enabled else false
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    public static boolean jsFunction_isBillingEnabled()
            throws AppManagementException {
        AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String billingConfig = config.getFirstProperty(AppMConstants.BILLING_AND_USAGE_CONFIGURATION);
        return Boolean.parseBoolean(billingConfig);
    }

    public static NativeArray jsFunction_getTiers(Context cx, Scriptable thisObj,
                                                  Object[] args,
                                                  Function funObj) {
        NativeArray myn = new NativeArray(0);
        APIConsumer apiConsumer = getAPIConsumer(thisObj);
        Set<Tier> tiers;
        try {
            //If tenant domain is present in url we will use it to get available tiers
            if(args.length>0 && args[0]!=null){
                tiers = apiConsumer.getTiers((String)args[0]);
            }
            else {
            	tiers = apiConsumer.getTiers();
            }
            int i = 0;
            for (Tier tier : tiers) {
                NativeObject row = new NativeObject();
                row.put("tierName", row, tier.getName());
                row.put("tierDisplayName", row, tier.getDisplayName());
                row.put("tierDescription", row,
                        tier.getDescription() != null ? tier.getDescription() : "");
                myn.put(i, myn, row);
                i++;
            }
        } catch (Exception e) {
            log.error("Error while getting available tiers", e);
        }
        return myn;
    }
    
    public static NativeArray jsFunction_getDeniedTiers(Context cx, Scriptable thisObj,
			Object[] args,
			Function funObj) throws AppManagementException {

    	NativeArray myn = new NativeArray(0);
    	APIConsumer apiConsumer = getAPIConsumer(thisObj);
    	
    	try {
    		Set<String> tiers = apiConsumer.getDeniedTiers();
    		int i = 0;
    		for (String tier : tiers) {
    			NativeObject row = new NativeObject();
    			row.put("tierName", row, tier);
    			myn.put(i, myn, row);
    			i++;
    		}
    	} catch (Exception e) {
    		log.error("Error while getting available tiers", e);
    	}
    	return myn;
	}
    public static NativeArray jsFunction_getUserFields(Context cx,
                                                       Scriptable thisObj, Object[] args, Function funObj)
            throws ScriptException {
        UserFieldDTO[] userFields = getOrderedUserFieldDTO();
        NativeArray myn = new NativeArray(0);
        int limit = userFields.length;
        for (int i = 0; i < limit; i++) {
            NativeObject row = new NativeObject();
            row.put("fieldName", row, userFields[i].getFieldName());
            row.put("claimUri", row, userFields[i].getClaimUri());
            row.put("required", row, userFields[i].getRequired());
            myn.put(i, myn, row);
        }
        return myn;
    }

    public static boolean jsFunction_hasUserPermissions(Context cx,
                                                        Scriptable thisObj, Object[] args,
                                                        Function funObj)
            throws ScriptException, AppManagementException {
        if (args!=null && isStringArray(args)) {
            String username = args[0].toString();
            return AppManagerUtil.checkPermissionQuietly(username, AppMConstants.Permissions.WEB_APP_SUBSCRIBE);
        } else {
            handleException("Invalid types of input parameters.");
        }
        return false;
    }

    private static UserFieldDTO[] getOrderedUserFieldDTO() {
        UserRegistrationAdminServiceStub stub;
        UserFieldDTO[] userFields = null;
        try {
            AppManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
            String url = config.getFirstProperty(AppMConstants.AUTH_MANAGER_URL);
            if (url == null) {
                handleException("WebApp key manager URL unspecified");
            }
            stub = new UserRegistrationAdminServiceStub(null, url + "UserRegistrationAdminService");
            ServiceClient client = stub._getServiceClient();
            Options option = client.getOptions();
            option.setManageSession(true);
            userFields = stub.readUserFieldsForUserRegistration(IdentityConstants.INFOCARD_DIALECT);
            Arrays.sort(userFields, new HostObjectUtils.RequiredUserFieldComparator());
            Arrays.sort(userFields, new HostObjectUtils.UserFieldComparator());
        } catch (Exception e) {
            log.error("Error while retrieving User registration Fields", e);
        }
        return userFields;
    }

    private static void updateRolesOfUser(String serverURL, String adminUsername,
                                          String adminPassword, String userName, String role) throws Exception {
        String url = serverURL + "UserAdmin";

        UserAdminStub userAdminStub = new UserAdminStub(url);
        CarbonUtils.setBasicAccessSecurityHeaders(adminUsername, adminPassword,
                true, userAdminStub._getServiceClient());
        FlaggedName[] flaggedNames = userAdminStub.getRolesOfUser(userName, "*", -1);
        List<String> roles = new ArrayList<String>();
        if (flaggedNames != null) {
            for (int i = 0; i < flaggedNames.length; i++) {
                if (flaggedNames[i].getSelected()) {
                    roles.add(flaggedNames[i].getItemName());
                }
            }
        }
        roles.add(role);
        userAdminStub.updateRolesOfUser(userName, roles.toArray(new String[roles.size()]));
    }

    private static long getApplicationAccessTokenValidityPeriodInSeconds(){
        return OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds();
    }

    public static NativeArray jsFunction_getActiveTenantDomains(Context cx, Scriptable thisObj,
                                                                Object[] args, Function funObj)
            throws AppManagementException {

        try {
            Set<String> tenantDomains = AppManagerUtil.getActiveTenantDomains();
            NativeArray domains = null;
            int i = 0;
            if (tenantDomains == null || tenantDomains.size() == 0) {
                return domains;
            } else {
                domains = new NativeArray(tenantDomains.size());
                for (String tenantDomain : tenantDomains) {
                    domains.put(i, domains, tenantDomain);
                    i++;
                }
            }
            return domains;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AppManagementException("Error while checking the AppStore is running in tenant mode or not.", e);
        }


    }

    private static boolean isApplicationAccessTokenNeverExpire(long validityPeriod) {
        return validityPeriod == Long.MAX_VALUE;
    }

    public static boolean jsFunction_isEnableEmailUsername(Context cx,
                                                   Scriptable thisObj, Object[] args,
                                                   Function funObj) {
    return Boolean.parseBoolean(CarbonUtils.getServerConfiguration().getFirstProperty("EnableEmailUserName"));
    }

	/**
	 * Returns trusted IdPs for the web application. If the configuration was
	 * set to show only the already trusted IdPs those will be returned, if else
	 * all the trusted IdPs trusted by the app manager will be provided
	 * 
	 * @param cx
	 * @param thisObj
	 * @param args
	 * @param funObj
	 * @return
	 * @throws org.wso2.carbon.appmgt.api.AppManagementException
	 */
	public static NativeArray jsFunction_getTrustedIdPs(Context cx, Scriptable thisObj,
	                                                    Object[] args, Function funObj)
	                                                                                   throws
                                                                                       AppManagementException {
		NativeArray idps = null;
		if (args != null && isStringArray(args)) {
			String webAppName = args[0].toString();
			List<TrustedIdP> idpList =
			                           WebAppIdPFactory.getInstance().getIdpManager()
			                                           .getIdPList(webAppName);
			if (idpList != null && !idpList.isEmpty()) {
				idps = new NativeArray(idpList.size());
				int i = 0;
				for (TrustedIdP idp : idpList) {
					idps.put(i, idps, idp);
					i++;
				}
			}
		} else {
			handleException("Invalid types of input parameters.");
		}

		return idps;

	}

    public static NativeArray jsFunction_getApplications(Context cx,
                                                         Scriptable thisObj, Object[] args,
                                                         Function funObj)
            throws ScriptException, AppManagementException {

        NativeArray myn = new NativeArray(0);
        if (args != null && isStringArray(args)) {
            String username = args[0].toString();
            APIConsumer apiConsumer = getAPIConsumer(thisObj);
            Application[] applications = apiConsumer.getApplications(new Subscriber(username));
            if (applications != null) {
                int i = 0;
                for (Application application : applications) {
                    NativeObject row = new NativeObject();
                    row.put("name", row, application.getName());
                    row.put("tier", row, application.getTier());
                    row.put("id", row, application.getId());
                    row.put("callbackUrl", row, application.getCallbackUrl());
                    row.put("status", row, application.getStatus());
                    row.put("description", row, application.getDescription());
                    myn.put(i++, myn, row);
                }
            }
        }
        return myn;
    }

    /**
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static boolean jsFunction_isTenantActive(Context cx, Scriptable thisObj,
                                                    Object[] args, Function funObj)
            throws AppManagementException {
        if (args == null || args.length != 1) {
            throw new AppManagementException("Invalid number of arguments.Argument length should be one");
        }

        if (!(args[0] instanceof String)) {
            throw new AppManagementException("Invalid type of input.Tenant domain should be String");
        }
        String tenantDomain = (String) args[0];
        try {
            boolean isActive = AppManagerUtil.isTenantActive(tenantDomain);
            return isActive;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AppManagementException("Error while checking whether tenant with tenant domain :" + tenantDomain +
                    "is active or not", e);
        }

    }

    /**
     * Check if the multiple version display in store is enabled.
     *
     * @param cx
     * @param thisObj
     * @param args
     * @param funObj
     * @return
     * @throws AppManagementException
     */
    public static boolean jsFunction_isDisplayMultipleVersionsEnabled(Context cx, Scriptable thisObj, Object[] args,
                                                                      Function funObj) throws AppManagementException {
        return HostObjectComponent.isDisplayMultipleVersionsEnabled();
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
     * Returns the current subscription configuration defined in app-manager.xml.
     *
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

}
