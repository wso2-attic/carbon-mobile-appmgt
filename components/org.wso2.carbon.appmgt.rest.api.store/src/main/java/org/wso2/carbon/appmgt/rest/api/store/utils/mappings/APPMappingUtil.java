/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.appmgt.rest.api.store.utils.mappings;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APIStatus;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.CustomProperty;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.rest.api.store.dto.AppAppmetaDTO;
import org.wso2.carbon.appmgt.rest.api.store.dto.AppDTO;
import org.wso2.carbon.appmgt.rest.api.store.dto.AppListDTO;
import org.wso2.carbon.appmgt.rest.api.store.dto.AppRatingListDTO;
import org.wso2.carbon.appmgt.rest.api.store.dto.AppSummaryDTO;
import org.wso2.carbon.appmgt.rest.api.store.dto.CustomPropertyDTO;
import org.wso2.carbon.appmgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.appmgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class APPMappingUtil {

    private static final Log log = LogFactory.getLog(APPMappingUtil.class);
    private final static String treatAsSiteTrue = "TREATASASITE:TRUE";
    private final static String treatAsSiteFalse = "TREATASASITE:FALSE";

    /**
     * Converts a List object of Apps into a DTO
     *
     * @param appList List of Apps
     * @param limit   maximum number of APIs returns
     * @param offset  starting index
     * @return APIListDTO object containing APIDTOs
     */
    public static AppListDTO fromAPIListToDTO(List<App> appList, int offset, int limit) {
        AppListDTO appListDTO = new AppListDTO();
        List<AppSummaryDTO> appSummaryDTOs = appListDTO.getAppSummaryList();
        if (appSummaryDTOs == null) {
            appSummaryDTOs = new ArrayList<>();
            appListDTO.setAppSummaryList(appSummaryDTOs);
        }

        //add the required range of objects to be returned
        int start = offset < appList.size() && offset >= 0 ? offset : Integer.MAX_VALUE;
        int end = offset + limit - 1 <= appList.size() - 1 ? offset + limit - 1 : appList.size() - 1;
        for (int i = start; i <= end; i++) {
            AppSummaryDTO appSummaryDTO = fromAppToInfoDTO(appList.get(i));
            if (appSummaryDTO != null) {
                appSummaryDTOs.add(appSummaryDTO);
            }
        }
        appListDTO.setCount(appSummaryDTOs.size());
        return appListDTO;
    }

    /**
     * Create and returns an AppListDTO with basic fields in the given apps.
     *
     * @param appList List of Apps
     * @param limit   maximum number of APIs returns
     * @param offset  starting index
     * @return APIListDTO
     */
    public static AppListDTO getAppListDTOWithBasicFields(List<App> appList, int offset, int limit) {
        AppListDTO appListDTO = new AppListDTO();
        List<AppSummaryDTO> appSummaryDTOs = appListDTO.getAppSummaryList();
        if (appSummaryDTOs == null) {
            appSummaryDTOs = new ArrayList<>();
            appListDTO.setAppSummaryList(appSummaryDTOs);
        }

        //add the required range of objects to be returned
        int start = offset < appList.size() && offset >= 0 ? offset : Integer.MAX_VALUE;
        int end = offset + limit - 1 <= appList.size() - 1 ? offset + limit - 1 : appList.size() - 1;
        for (int i = start; i <= end; i++) {
            AppSummaryDTO appSummaryDTO = fromAppToInfoDTO(appList.get(i));
            if (appSummaryDTO != null) {
                appSummaryDTOs.add(appSummaryDTO);
            }
        }
        appListDTO.setCount(appSummaryDTOs.size());
        return appListDTO;
    }

    /**
     * Create and returns an AppListDTO with all fields in the given apps.
     *
     * @param appList List of Apps
     * @param limit   maximum number of APIs returns
     * @param offset  starting index
     * @return AppListDTO
     */
    public static AppListDTO getAppListDTOWithAllFields(List<App> appList, int offset, int limit) {

        AppListDTO appListDTO = new AppListDTO();
        List<AppDTO> appDTOs = appListDTO.getAppList();
        if (appDTOs == null) {
            appDTOs = new ArrayList<>();
            appListDTO.setAppList(appDTOs);
        }

        //add the required range of objects to be returned
        int start = offset < appList.size() && offset >= 0 ? offset : Integer.MAX_VALUE;
        int end = offset + limit - 1 <= appList.size() - 1 ? offset + limit - 1 : appList.size() - 1;
        for (int i = start; i <= end; i++) {
            AppDTO appDTO = fromAppToDTO(appList.get(i));
            if(appDTO != null){
                appDTOs.add(appDTO);
            }
        }
        appListDTO.setCount(appDTOs.size());
        return appListDTO;
    }

    public static AppSummaryDTO fromAppToInfoDTO(App app) {
        //check if app visibility is permitted and the lifecycle status published
        if (isVisibilityAllowed(app) && (APIStatus.PUBLISHED).equals(app.getLifeCycleStatus())) {
            if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
                return fromMobileAppToInfoDTO((MobileApp) app);
            }
        }
        return null;
    }

    private static AppSummaryDTO fromMobileAppToInfoDTO(MobileApp app) {

        AppSummaryDTO appSummaryDTO = new AppSummaryDTO();
        appSummaryDTO.setId(app.getUUID());
        appSummaryDTO.setName(app.getAppName());
        appSummaryDTO.setVersion(app.getVersion());
        appSummaryDTO.setProvider(AppManagerUtil.replaceEmailDomainBack(app.getAppProvider()));
        appSummaryDTO.setDescription(app.getDescription());
        appSummaryDTO.setLifecycleState(app.getLifeCycleStatus().getStatus());
        appSummaryDTO.setRating(BigDecimal.valueOf(app.getRating()));
        return appSummaryDTO;

    }

    /**
     * Sets pagination urls for a APIListDTO object given pagination parameters and url parameters
     *
     * @param appListDTO a AppListDTO object
     * @param query      search condition
     * @param limit      max number of objects returned
     * @param offset     starting index
     * @param size       max offset
     */
    public static void setPaginationParams(AppListDTO appListDTO, String query, int offset, int limit, int size) {

        //acquiring pagination parameters and setting pagination urls
        Map<String, Integer> paginatedParams = RestApiUtil.getPaginationParams(offset, limit, size);
        String paginatedPrevious = "";
        String paginatedNext = "";

        if (paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_OFFSET) != null) {
            paginatedPrevious = RestApiUtil
                    .getAPIPaginatedURL(paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_OFFSET),
                                        paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_LIMIT), query);
        }

        if (paginatedParams.get(RestApiConstants.PAGINATION_NEXT_OFFSET) != null) {
            paginatedNext = RestApiUtil
                    .getAPIPaginatedURL(paginatedParams.get(RestApiConstants.PAGINATION_NEXT_OFFSET),
                                        paginatedParams.get(RestApiConstants.PAGINATION_NEXT_LIMIT), query);
        }

        appListDTO.setNext(paginatedNext);
        appListDTO.setPrevious(paginatedPrevious);
    }


    /**
     * Sets pagination urls for a AppRatingListDTO object given pagination parameters and url parameters
     *
     * @param appRatingListDTO a AppListDTO object
     * @param limit            max number of objects returned
     * @param offset           starting index
     * @param size             max offset
     */
    public static void setAppRatingPaginationParams(AppRatingListDTO appRatingListDTO, int offset, int limit,
                                                    int size) {

        //acquiring pagination parameters and setting pagination urls
        Map<String, Integer> paginatedParams = RestApiUtil.getPaginationParams(offset, limit, size);
        String paginatedPrevious = "";
        String paginatedNext = "";

        if (paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_OFFSET) != null) {
            paginatedPrevious = RestApiUtil
                    .getAppRatingPaginatedURL(paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_OFFSET),
                                              paginatedParams.get(RestApiConstants.PAGINATION_PREVIOUS_LIMIT));
        }

        if (paginatedParams.get(RestApiConstants.PAGINATION_NEXT_OFFSET) != null) {
            paginatedNext = RestApiUtil
                    .getAppRatingPaginatedURL(paginatedParams.get(RestApiConstants.PAGINATION_NEXT_OFFSET),
                                              paginatedParams.get(RestApiConstants.PAGINATION_NEXT_LIMIT));
        }

        appRatingListDTO.setNext(paginatedNext);
        appRatingListDTO.setPrevious(paginatedPrevious);
    }

    public static APIIdentifier getAppIdentifierFromApiId(String appID) {
        //if appID contains -AT-, that need to be replaced before splitting
        appID = AppManagerUtil.replaceEmailDomainBack(appID);
        String[] appIdDetails = appID.split(RestApiConstants.API_ID_DELIMITER);

        if (appIdDetails.length < 3) {
            RestApiUtil.handleBadRequest("Provided API identifier '" + appID + "' is invalid", log);
        }

        // appID format: provider-apiName-version
        String providerName = appIdDetails[0];
        String apiName = appIdDetails[1];
        String version = appIdDetails[2];
        String providerNameEmailReplaced = AppManagerUtil.replaceEmailDomain(providerName);
        return new APIIdentifier(providerNameEmailReplaced, apiName, version);
    }

    public static AppDTO fromAppToDTO(App app) {
        AppDTO appDTO = null;

        //check if app visibility is permitted and the lifecycle status published
        if (isVisibilityAllowed(app) && APIStatus.PUBLISHED.equals(app.getLifeCycleStatus())) {
            if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
                appDTO = fromMobileAppToDTO((MobileApp) app);
            }
        }

        if(appDTO != null && app.getCustomProperties() != null){

            List<CustomPropertyDTO> customPropertyDTOs = new ArrayList<CustomPropertyDTO>();

            CustomPropertyDTO customPropertyDTO = null;
            for(CustomProperty customProperty : app.getCustomProperties()){
                customPropertyDTO = new CustomPropertyDTO();
                customPropertyDTO.setName(customProperty.getName());
                customPropertyDTO.setValue(customProperty.getValue());
                customPropertyDTOs.add(customPropertyDTO);
            }
            appDTO.setCustomProperties(customPropertyDTOs);
        }

        return appDTO;
    }

    private static boolean isVisibilityAllowed(App app) {
        try {
            String[] appVisibilityRoles = app.getAppVisibility();
            if (appVisibilityRoles == null) {
                //no restrictions
                return true;
            } else {
                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                RealmService realmService = (RealmService) carbonContext.getOSGiService(RealmService.class, null);
                String[] roleNames = null;
                String tenantDomainName = RestApiUtil.getLoggedInUserTenantDomain();
                int tenantId = 0;
                tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getTenantId(
                        tenantDomainName);
                UserRealm realm = realmService.getTenantUserRealm(tenantId);
                UserStoreManager manager = realm.getUserStoreManager();
                roleNames = manager.getRoleListOfUser(RestApiUtil.getLoggedInUsername());

                for (String roleName : roleNames) {
                    for (String appVisibilityRole : appVisibilityRoles) {
                        if (appVisibilityRole.equals(roleName)) {
                            return true;
                        }
                    }
                }

            }
            return false;
        } catch (UserStoreException e) {
            log.error("Error while initializing User store");
            return false;
        }
    }

    private static AppDTO fromMobileAppToDTO(MobileApp mobileApp) {

        AppDTO dto = new AppDTO();

        dto.setId(mobileApp.getUUID());
        dto.setName(mobileApp.getAppName());
        dto.setVersion(mobileApp.getVersion());
        dto.setDescription(mobileApp.getDescription());
        dto.setRating(BigDecimal.valueOf(mobileApp.getRating()));

        Set<String> apiTags = mobileApp.getTags();
        List<String> tagsToReturn = new ArrayList<>();
        tagsToReturn.addAll(apiTags);
        dto.setTags(tagsToReturn);

        dto.setType(mobileApp.getType());
        dto.setMarketType(mobileApp.getMarketType());
        dto.setBundleversion(mobileApp.getBundleVersion());
        dto.setCategory(mobileApp.getCategory());
        dto.setDisplayName(mobileApp.getDisplayName());
        if (mobileApp.getScreenShots() != null) {
            dto.setScreenshots(mobileApp.getScreenShots());
        }
        dto.setPlatform(mobileApp.getPlatform());
        dto.setCreatedtime(mobileApp.getDisplayName());
        dto.setBanner(mobileApp.getBanner());
        dto.setRecentChanges(mobileApp.getRecentChanges());

        AppAppmetaDTO appAppmetaDTO = new AppAppmetaDTO();
        appAppmetaDTO.setPackage(mobileApp.getPackageName());
        appAppmetaDTO.setWeburl(mobileApp.getAppUrl());
        dto.setAppmeta(appAppmetaDTO);

        dto.setIcon(mobileApp.getThumbnail());
        dto.setAppType(mobileApp.getAppType());
        dto.setRecentChanges(mobileApp.getRecentChanges());
        dto.setPreviousVersionAppID(mobileApp.getPreviousVersionAppID());

        return dto;
    }

    public static void subscribeApp(Registry registry, String userId, String appId)
            throws org.wso2.carbon.registry.api.RegistryException {
        String path = "users/" + userId + "/subscriptions/mobileapp/" + appId;
        Resource resource = null;
        try {
            resource = registry.get(path);
        } catch (RegistryException e) {
            log.error("RegistryException occurred", e);
        }
        if (resource == null) {
            resource = registry.newResource();
            resource.setContent("");
            registry.put(path, resource);
        }
    }


    public static void unSubscribeApp(Registry registry, String userId, String appId) throws RegistryException {
        String path = "users/" + userId + "/subscriptions/mobileapp/" + appId;
        try {
            registry.delete(path);
        } catch (RegistryException e) {
            log.error("Error while deleting registry path: " + path, e);
            throw e;
        }
    }

    public static boolean showAppVisibilityToUser(String appPath, String username, String opType)
            throws UserStoreException {
        String userRole = "Internal/private_" + username;

        try {
            if ("ALLOW".equalsIgnoreCase(opType)) {
                org.wso2.carbon.user.api.UserRealm realm =
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
                realm.getAuthorizationManager().authorizeRole(userRole, appPath, ActionConstants.GET);
                return true;
            } else if ("DENY".equalsIgnoreCase(opType)) {
                org.wso2.carbon.user.api.UserRealm realm =
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
                realm.getAuthorizationManager().denyRole(userRole, appPath, ActionConstants.GET);
                return true;
            }
            return false;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error while updating visibility of mobile app at " + appPath, e);
            throw e;
        }
    }

    public static String buildQuery(String appType, String query) {
        if (AppMConstants.SITE_ASSET_TYPE.equalsIgnoreCase(appType)) {
            if (StringUtils.isNotEmpty(query)) {
                return query + "," + treatAsSiteTrue;
            } else {
                return treatAsSiteTrue;
            }
        } else if (AppMConstants.WEBAPP_ASSET_TYPE.equalsIgnoreCase(appType)) {
            if (StringUtils.isNotEmpty(query)) {
                return query + "," + treatAsSiteFalse;
            } else {
                return treatAsSiteFalse;
            }
        }
        return "";
    }

    public static String updateAssetType(String appType) {
        if (AppMConstants.SITE_ASSET_TYPE.equalsIgnoreCase(appType) ||
                (AppMConstants.WEBAPP_ASSET_TYPE.equalsIgnoreCase(appType))) {
            return AppMConstants.WEBAPP_ASSET_TYPE;
        }
        return appType;
    }
}
