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
import org.wso2.carbon.appmgt.api.APIConsumer;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.impl.dto.TierPermissionDTO;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
