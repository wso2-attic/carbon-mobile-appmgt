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

package org.wso2.carbon.appmgt.rest.api.publisher.utils.mappings;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.CustomProperty;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppAppmetaDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppSummaryDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.CustomPropertyDTO;
import org.wso2.carbon.appmgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.appmgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class APPMappingUtil {

    private static final Log log = LogFactory.getLog(APPMappingUtil.class);

    /**
     * Converts a List object of APIs into a DTO
     *
     * @param appList List of Apps
     * @param limit   maximum number of APIs returns
     * @param offset  starting index
     * @return APIListDTO object containing AppInfoDTOs
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
            appSummaryDTOs.add(fromAppToInfoDTO(appList.get(i)));
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
        if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
            return fromMobileAppToInfoDTO((MobileApp) app);
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
     * @param appListDTO a APIListDTO object
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

        if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
            appDTO = fromMobileAppToDTO((MobileApp) app);
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
        dto.setCreatedTime(mobileApp.getCreatedTime());

        return dto;

    }


    /**
     * Converts AppDTO into a MobileApp
     *
     * @param appDTO AppDTO
     * @return if appDTO is valid, returns the converted MobileApp, else throws a BadRequestException
     * @throws AppManagementException
     */
    public static MobileApp fromDTOtoMobileApp(AppDTO appDTO) {

        String providerName = RestApiUtil.getLoggedInUsername();

        MobileApp mobileAppModel = new MobileApp();
        AppAppmetaDTO appAppmetaDTO = appDTO.getAppmeta();

        mobileAppModel.setAppProvider(providerName);
        //Validate Mandatory fields

        validateMandatoryField("platform", appDTO.getPlatform());
        mobileAppModel.setPlatform(appDTO.getPlatform());

        validateMandatoryField("markettype", appDTO.getMarketType());
        mobileAppModel.setMarketType(appDTO.getMarketType());

        if (validateMandatoryField("appmeta", appAppmetaDTO)) {
            if (AppMConstants.MOBILE_APPS_PLATFORM_ANDROID.equals(appDTO.getPlatform()) ||
                    AppMConstants.MOBILE_APPS_PLATFORM_IOS.equals(appDTO.getPlatform())) {

                if ("enterprise".equals(appDTO.getMarketType())) {
                    validateMandatoryField("path", appAppmetaDTO.getPath());
                    mobileAppModel.setAppUrl(appAppmetaDTO.getPath());
                    validateMandatoryField("package", appAppmetaDTO.getPackage());
                    mobileAppModel.setPackageName(appAppmetaDTO.getPackage());
                    validateMandatoryField("version", appAppmetaDTO.getVersion());
                    mobileAppModel.setBundleVersion(appAppmetaDTO.getVersion());
                    mobileAppModel.setVersion(appDTO.getVersion());
                } else if ("public".equals(appDTO.getMarketType())) {
                    validateMandatoryField("package", appAppmetaDTO.getPackage());
                    mobileAppModel.setPackageName(appAppmetaDTO.getPackage());
                    validateMandatoryField("version", appAppmetaDTO.getVersion());
                    mobileAppModel.setBundleVersion(appAppmetaDTO.getVersion());
                    mobileAppModel.setVersion(appDTO.getVersion());
                } else {
                    RestApiUtil.handleBadRequest("Unsupported market type '" + appDTO.getMarketType() +
                            "' is provided for platform : " + appDTO.getPlatform(), log);
                }
            } else if (AppMConstants.MOBILE_APPS_PLATFORM_WEBAPP.equals(appDTO.getPlatform())) {
                if ("webapp".equals(appDTO.getMarketType())) {
                    validateMandatoryField("weburl", appAppmetaDTO.getWeburl());
                    mobileAppModel.setAppUrl(appAppmetaDTO.getWeburl());
                    validateMandatoryField("version", appAppmetaDTO.getVersion());
                    mobileAppModel.setVersion(appAppmetaDTO.getVersion());
                } else {
                    RestApiUtil.handleBadRequest("Unsupported market type '" + appDTO.getMarketType() +
                            "' is provided for platform : " + appDTO.getPlatform(), log);
                }
            } else {
                RestApiUtil.handleBadRequest("Unsupported platform '" + appDTO.getPlatform() + "' is provided.", log);
            }
        }
        mobileAppModel.setAppName(appDTO.getName());
        mobileAppModel.setDisplayName(appDTO.getDisplayName());
        validateMandatoryField("description", appDTO.getDescription());
        mobileAppModel.setDescription(appDTO.getDescription());
        validateMandatoryField("category", appDTO.getCategory());
        mobileAppModel.setCategory(appDTO.getCategory());
        validateMandatoryField("banner", appDTO.getBanner());
        mobileAppModel.setBanner(appDTO.getBanner());
        validateMandatoryField("iconFile", appDTO.getIcon());
        mobileAppModel.setThumbnail(appDTO.getIcon());
        List<String> screenShots = appDTO.getScreenshots();
        validateMandatoryField("screenshots", screenShots);
        if (screenShots.size() > 3) {
            RestApiUtil.handleBadRequest("Attached screenshots count exceeds the maximum number of allowed screenshots",
                    log);
        }
        while (screenShots.size() < 3) {
            screenShots.add("");
        }
        mobileAppModel.setScreenShots(appDTO.getScreenshots());
        mobileAppModel.setRecentChanges(appDTO.getRecentChanges());
        //mobileAppModel.setPreviousVersionAppID(appDTO.getPreviousVersionAppID());

        if (appDTO.getTags() != null) {
            Set<String> apiTags = new HashSet<>(appDTO.getTags());
            mobileAppModel.addTags(apiTags);
        }
        List<String> visibleRoleList = new ArrayList<String>();
        visibleRoleList = appDTO.getVisibleRoles();
        if (visibleRoleList != null) {
            String[] visibleRoles = new String[visibleRoleList.size()];
            visibleRoles = visibleRoleList.toArray(visibleRoles);
            mobileAppModel.setAppVisibility(visibleRoles);
        }
        return mobileAppModel;
    }

    private static boolean validateMandatoryField(String fieldName, Object fieldValue) {

        if (fieldValue == null) {
            RestApiUtil.handleBadRequest("Mandatory field  '" + fieldName + "' is not provided.", log);
        }
        return true;
    }

    public static String getSaml2SsoIssuer(String appName, String appVersion) {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String saml2SsoIssuer;
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            saml2SsoIssuer = appName + "-" + appVersion;
        } else {
            saml2SsoIssuer = appName + "-" + tenantDomain + "-" + appVersion;
        }
        return saml2SsoIssuer;
    }
}
