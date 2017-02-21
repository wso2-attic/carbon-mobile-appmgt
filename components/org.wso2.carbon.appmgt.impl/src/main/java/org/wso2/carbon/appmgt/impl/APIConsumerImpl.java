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

package org.wso2.carbon.appmgt.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.appmgt.api.APIConsumer;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APIStatus;
import org.wso2.carbon.appmgt.api.model.Application;
import org.wso2.carbon.appmgt.api.model.SubscribedAPI;
import org.wso2.carbon.appmgt.api.model.Subscriber;
import org.wso2.carbon.appmgt.api.model.Subscription;
import org.wso2.carbon.appmgt.api.model.WebAppSearchOption;
import org.wso2.carbon.appmgt.api.model.WebAppSortOption;
import org.wso2.carbon.appmgt.impl.dto.SubscriptionWorkflowDTO;
import org.wso2.carbon.appmgt.impl.dto.TierPermissionDTO;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.APINameComparator;
import org.wso2.carbon.appmgt.impl.utils.APIVersionComparator;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowConstants;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowException;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowExecutor;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowExecutorFactory;
import org.wso2.carbon.appmgt.impl.workflow.WorkflowStatus;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.governance.api.exception.GovernanceException;
import org.wso2.carbon.governance.api.generic.GenericArtifactManager;
import org.wso2.carbon.governance.api.generic.dataobjects.GenericArtifact;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.Association;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.pagination.PaginationContext;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.registry.core.utils.RegistryUtils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class provides the core WebApp store functionality. It is implemented in a very
 * self-contained and 'pure' manner, without taking requirements like security into account,
 * which are subject to frequent change. Due to this 'pure' nature and the significance of
 * the class to the overall WebApp management functionality, the visibility of the class has
 * been reduced to package level. This means we can still use it for internal purposes and
 * possibly even extend it, but it's totally off the limits of the users. Users wishing to
 * programmatically access this functionality should use one of the extensions of this
 * class which is visible to them. These extensions may add additional features like
 * security to this class.
 */
class APIConsumerImpl extends AbstractAPIManager implements APIConsumer {

    private static final Log log = LogFactory.getLog(APIConsumerImpl.class);

    private boolean isTenantModeStoreView;
    private String requestedTenant;
    private boolean isTagCacheEnabled;
    private long tagCacheValidityTime;
    private long lastUpdatedTime;
    private Object tagCacheMutex = new Object();

    public APIConsumerImpl() throws AppManagementException {
        super();
        readTagCacheConfigs();
    }

    public APIConsumerImpl(String username) throws AppManagementException {
        super(username);
        readTagCacheConfigs();
    }

    private void readTagCacheConfigs() {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                getAPIManagerConfiguration();
        String enableTagCache = config.getFirstProperty(AppMConstants.API_STORE_TAG_CACHE_DURATION);
        if (enableTagCache == null) {
            isTagCacheEnabled = false;
            tagCacheValidityTime = 0;
        } else {
            isTagCacheEnabled = true;
            tagCacheValidityTime = Long.parseLong(enableTagCache);
        }
    }

    public Subscriber getSubscriber(String subscriberId) throws AppManagementException {
        Subscriber subscriber = null;
        try {
            subscriber = appMDAO.getSubscriber(subscriberId);
        } catch (AppManagementException e) {
            handleException("Failed to get Subscriber", e);
        }
        return subscriber;
    }

    private <T> T[] concatArrays(T[] first, T[] second) {
        T[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public float getAverageRating(String uuid, String assetType) throws AppManagementException {
        float rating = 0;
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, assetType);
            GenericArtifact genericArtifact = artifactManager.getGenericArtifact(uuid);
            rating = registry.getAverageRating(genericArtifact.getPath());
        } catch (RegistryException e) {
            handleException("Failed to retrieve rating", e);
        }
        return rating;
    }

    public Map<String,Object> searchPaginatedAPIs(String searchTerm, String searchType, String requestedTenantDomain,int start,int end)
            throws AppManagementException {
        Map<String,Object> result = new HashMap<String,Object>();
        try {
            Registry userRegistry;
            boolean isTenantMode=(requestedTenantDomain != null);
            if ((isTenantMode && this.tenantDomain==null) || (isTenantMode && isTenantDomainNotMatching(requestedTenantDomain))) {//Tenant store anonymous mode
                int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                        .getTenantId(requestedTenantDomain);
                userRegistry = ServiceReferenceHolder.getInstance().
                        getRegistryService().getGovernanceUserRegistry(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME, tenantId);
            } else {
                userRegistry = this.registry;
            }
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(this.username);
            result=searchPaginatedAPIs(userRegistry, searchTerm, searchType,start,end);

        } catch (Exception e) {
            handleException("Failed to Search APIs", e);
        }
        return result;
    }

    public Set<SubscribedAPI> getSubscribedAPIs(Subscriber subscriber) throws
                                                                       AppManagementException {
        Set<SubscribedAPI> originalSubscribedAPIs = null;
        Set<SubscribedAPI> subscribedAPIs = new HashSet<SubscribedAPI>();
        try {
            originalSubscribedAPIs= appMDAO.getSubscribedAPIs(subscriber);
            for(SubscribedAPI subscribedApi:originalSubscribedAPIs) {
                subscribedApi.getTier().setDisplayName(AppManagerUtil.getTierDisplayName(tenantId,subscribedApi.getTier().getName()));
                subscribedAPIs.add(subscribedApi);
            }

        } catch (AppManagementException e) {
            handleException("Failed to get APIs of " + subscriber.getName(), e);
        }
        return subscribedAPIs;
    }

    public Set<SubscribedAPI> getSubscribedAPIs(Subscriber subscriber, String applicationName) throws
                                                                                               AppManagementException {
        Set<SubscribedAPI> subscribedAPIs = null;
        try {
            subscribedAPIs = appMDAO.getSubscribedAPIs(subscriber, applicationName);
        } catch (AppManagementException e) {
            handleException("Failed to get APIs of " + subscriber.getName() + " under application " + applicationName, e);
        }
        return subscribedAPIs;
    }

    public boolean isSubscribed(APIIdentifier apiIdentifier, String userId)
            throws AppManagementException {
        boolean isSubscribed;
        try {
            isSubscribed = appMDAO.isSubscribed(apiIdentifier, userId);
        } catch (AppManagementException e) {
            String msg = "Failed to check if user(" + userId + ") has subscribed to " + apiIdentifier;
            log.error(msg, e);
            throw new AppManagementException(msg, e);
        }
        return isSubscribed;
    }

    @Override
    public Subscription getSubscription(APIIdentifier apiIdentifier, int applicationId, String subscriptionType)throws
                                                                                                                AppManagementException {
        return appMDAO.getSubscription(apiIdentifier, applicationId, subscriptionType);
    }

    public void removeSubscription(APIIdentifier identifier, String userId, int applicationId)
            throws AppManagementException {
        appMDAO.removeSubscription(identifier, applicationId);
    }

    public void removeAPISubscription(APIIdentifier identifier, String userId, String applicationName)
            throws AppManagementException {
        appMDAO.removeAPISubscription(identifier, userId, applicationName);
        /*if (AppManagerUtil.isAPIGatewayKeyCacheEnabled()) {
            invalidateCachedKeys(applicationId, identifier);
        }*/
    }

    public void removeSubscriber(APIIdentifier identifier, String userId)
            throws AppManagementException {
        throw new UnsupportedOperationException("Unsubscribe operation is not yet implemented");
    }

    /**
     * Add a new Application from the store.
     * @param application - {@link Application}
     * @param userId - {@link String} 
     * @return {@link String}
     */
    //ToDo: Refactor addApplication method return type to void
    public String addApplication(Application application, String userId)
            throws AppManagementException {
    	
    	appMDAO.addApplication(application, userId);
        return appMDAO.getApplicationStatus(application.getName(),userId);
    }

    public void updateApplication(Application application) throws AppManagementException {
        appMDAO.updateApplication(application);
    }

    public boolean isApplicationTokenExists(String accessToken) throws AppManagementException {
        return appMDAO.isAccessTokenExists(accessToken);
    }

    public Set<SubscribedAPI> getSubscribedIdentifiers(Subscriber subscriber, APIIdentifier identifier)
            throws AppManagementException {
        Set<SubscribedAPI> subscribedAPISet = new HashSet<SubscribedAPI>();
        Set<SubscribedAPI> subscribedAPIs = getSubscribedAPIs(subscriber);
        for (SubscribedAPI api : subscribedAPIs) {
            if (api.getApiId().equals(identifier)) {
                subscribedAPISet.add(api);
            }
        }
        return subscribedAPISet;
    }

    private boolean isAllowDisplayAPIsWithMultipleStatus() {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();
        String displayAllAPIs = config.getFirstProperty(AppMConstants.API_STORE_DISPLAY_ALL_APIS);
        if (displayAllAPIs == null) {
            log.warn("The configurations related to show deprecated Apps in AppStore " +
                    "are missing in app-manager.xml.");
            return false;
        }
        return Boolean.parseBoolean(displayAllAPIs);
    }

    private boolean isAllowDisplayMultipleVersions() {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();

        String displayMultiVersions = config.getFirstProperty(AppMConstants.API_STORE_DISPLAY_MULTIPLE_VERSIONS);
        if (displayMultiVersions == null) {
            log.warn("The configurations related to show multiple versions of WebApp in AppStore " +
                    "are missing in app-manager.xml.");
            return false;
        }
        return Boolean.parseBoolean(displayMultiVersions);
    }

    /**
     * Returns a list of tiers denied
     *
     * @return Set<Tier>
     */
    public Set<String> getDeniedTiers() throws AppManagementException {
        Set<String> deniedTiers = new HashSet<String>();
        String[] currentUserRoles = new String[0];
        try {
            if (tenantId != 0) {
                /* Get the roles of the Current User */
                currentUserRoles = ((UserRegistry) ((UserAwareAPIConsumer) this).registry).
                        getUserRealm().getUserStoreManager().getRoleListOfUser(((UserRegistry) this.registry).getUserName());

                Set<TierPermissionDTO> tierPermissions = appMDAO.getTierPermissions(tenantId);
                for (TierPermissionDTO tierPermission : tierPermissions) {
                    String type = tierPermission.getPermissionType();

                    List<String> currentRolesList = new ArrayList<String>(Arrays.asList(currentUserRoles));
                    List<String> roles = new ArrayList<String>(Arrays.asList(tierPermission.getRoles()));
                    currentRolesList.retainAll(roles);

                    if (AppMConstants.TIER_PERMISSION_ALLOW.equals(type)) {
                        /* Current User is not allowed for this Tier*/
                        if (currentRolesList.size() == 0) {
                            deniedTiers.add(tierPermission.getTierName());
                        }
                    } else {
                        /* Current User is denied for this Tier*/
                        if (currentRolesList.size() > 0) {
                            deniedTiers.add(tierPermission.getTierName());
                        }
                    }
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("cannot retrieve user role list for tenant" + tenantDomain);
        }
        return deniedTiers;
    }

    /**
     * Check whether given Tier is denied for the user
     *
     * @param tierName
     * @return
     * @throws org.wso2.carbon.appmgt.api.AppManagementException if failed to get the tiers
     */
    public boolean isTierDeneid(String tierName) throws AppManagementException {
        String[] currentUserRoles = new String[0];
        try {
            if (tenantId != 0) {
                /* Get the roles of the Current User */
                currentUserRoles = ((UserRegistry) ((UserAwareAPIConsumer) this).registry).
                        getUserRealm().getUserStoreManager().getRoleListOfUser(((UserRegistry) this.registry).getUserName());
                TierPermissionDTO tierPermission = appMDAO.getTierPermission(tierName, tenantId);
                if (tierPermission == null) {
                    return false;
                } else {
                    List<String> currentRolesList = new ArrayList<String>(Arrays.asList(currentUserRoles));
                    List<String> roles = new ArrayList<String>(Arrays.asList(tierPermission.getRoles()));
                    currentRolesList.retainAll(roles);
                    if (AppMConstants.TIER_PERMISSION_ALLOW.equals(tierPermission.getPermissionType())) {
                        if (currentRolesList.size() == 0) {
                            return true;
                        }
                    } else {
                        if (currentRolesList.size() > 0) {
                            return true;
                        }
                    }
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("cannot retrieve user role list for tenant" + tenantDomain);
        }
        return false;
    }

    private boolean isAllowDisplayAllAPIs() {
        AppManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();
        String displayAllAPIs = config.getFirstProperty(AppMConstants.API_STORE_DISPLAY_ALL_APIS);
        if (displayAllAPIs == null) {
            log.warn("The configurations related to show deprecated Apps in AppStore " +
                    "are missing in app-manager.xml.");
            return false;
        }
        return Boolean.parseBoolean(displayAllAPIs);
    }
    
    private boolean isTenantDomainNotMatching(String tenantDomain) {
    	if (this.tenantDomain != null) {
    		return !(this.tenantDomain.equals(tenantDomain));
    	}
    	return true;
    }

    public Application[] getApplications(Subscriber subscriber) throws AppManagementException {
        return appMDAO.getApplications(subscriber);
    }

    @Override
    public List<APIIdentifier> getUserAccessibleApps(String username, int tenantIdOfUser, int tenantIdOfStore,
                                                     WebAppSortOption sortOption, boolean treatAsSite)
            throws AppManagementException {
        return appMDAO.getUserAccessibleApps(username, tenantIdOfUser, tenantIdOfStore, sortOption, treatAsSite);
    }

    @Override
    public List<APIIdentifier> searchUserAccessibleApps(String username, int tenantIdOfUser, int tenantIdOfStore,
                                                        boolean treatAsSite, WebAppSearchOption searchOption,
                                                        String searchValue) throws AppManagementException {
        Registry anonnymousUserRegistry = null;
        try {
            if (tenantIdOfStore != tenantIdOfUser) {
                // Get registry for anonnymous users when searching is going in tenant.
                anonnymousUserRegistry = ServiceReferenceHolder.getInstance().getRegistryService()
                        .getGovernanceUserRegistry(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME, tenantIdOfStore);
            } else {
                anonnymousUserRegistry = registry;
            }
        } catch (RegistryException e) {
            handleException("Error while obtaining registry.", e);
        }

        return appMDAO.searchUserAccessibleApps(username, tenantIdOfUser, tenantIdOfStore, treatAsSite, searchOption,
                                                searchValue, anonnymousUserRegistry);
    }

    @Override
    public boolean isSubscribedToMobileApp(String userId, String appId) throws AppManagementException {
        String path = "users/" + userId + "/subscriptions/mobileapp/" + appId;
        boolean isSubscribed = false;
        try {
            if (registry.resourceExists(path)) {
                isSubscribed = true;
            }
        } catch (org.wso2.carbon.registry.api.RegistryException e) {
            handleException("Error while checking subscription in registry for mobileapp with id : " + appId, e);
        }
        return isSubscribed;
    }

}
