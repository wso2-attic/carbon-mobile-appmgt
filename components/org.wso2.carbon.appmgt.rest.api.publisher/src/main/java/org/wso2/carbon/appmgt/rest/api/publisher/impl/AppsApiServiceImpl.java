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

package org.wso2.carbon.appmgt.rest.api.publisher.impl;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.wso2.carbon.appmgt.api.APIProvider;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.FileContent;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.api.model.Tier;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.AppRepository;
import org.wso2.carbon.appmgt.impl.DefaultAppRepository;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.rest.api.publisher.AppsApiService;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.AppListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.BinaryDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.LifeCycleDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.LifeCycleHistoryDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.LifeCycleHistoryListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.ResponseMessageDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.TierDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.TierListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.UserIdListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.utils.RestApiPublisherUtils;
import org.wso2.carbon.appmgt.rest.api.publisher.utils.mappings.APPMappingUtil;
import org.wso2.carbon.appmgt.rest.api.publisher.utils.validation.AppDTOValidator;
import org.wso2.carbon.appmgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.appmgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.appmgt.rest.api.util.validation.BeanValidator;
import org.wso2.carbon.appmgt.rest.api.util.validation.CommonValidator;
import org.wso2.carbon.governance.api.exception.GovernanceException;
import org.wso2.carbon.governance.api.generic.GenericArtifactManager;
import org.wso2.carbon.governance.api.generic.dataobjects.GenericArtifact;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.mobile.utils.utilities.ZipFileReading;

import javax.activation.MimetypesFileTypeMap;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * This is the service implementation class for Publisher API related operations
 */
public class AppsApiServiceImpl extends AppsApiService {

    private static final Log log = LogFactory.getLog(AppsApiService.class);
    BeanValidator beanValidator;

    /**
     * Upload binary files into storage
     *
     * @param fileInputStream   Uploading fileInputStream
     * @param fileDetail        Attachment details
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return API path of the uploaded binary
     */
    @Override
    public Response appsMobileBinariesPost(InputStream fileInputStream, Attachment fileDetail, String ifMatch,
                                           String ifUnmodifiedSince) {

        BinaryDTO binaryDTO = new BinaryDTO();
        try {
            if (fileInputStream != null) {
                if ("application".equals(fileDetail.getContentType().getType())) {
                    String fileName = fileDetail.getContentDisposition().getParameter("filename");

                    if(!RestApiUtil.isValidFileName(fileName)){
                        RestApiUtil.handleBadRequest("Invalid file '"+fileName +"' has been provided to upload", log);
                    }

                    String fileExtension =
                            FilenameUtils.getExtension(fileName);
                    if (AppMConstants.MOBILE_APPS_ANDROID_EXT.equals(fileExtension) ||
                            AppMConstants.MOBILE_APPS_IOS_EXT.equals(fileExtension)) {

                        //Generate UUID for the uploading file
                        String filename = RestApiPublisherUtils.generateBinaryUUID() + "." + fileExtension;

                        FileContent fileContent = new FileContent();
                        fileContent.setContent(fileInputStream);
                        fileContent.setFileName(filename);
                        String filePath = RestApiPublisherUtils.uploadFileIntoStorage(fileContent);
                        ZipFileReading zipFileReading = new ZipFileReading();

                        String information = null;
                        if (AppMConstants.MOBILE_APPS_ANDROID_EXT.equals(fileExtension)) {
                            information = zipFileReading.readAndroidManifestFile(filePath);
                        } else if (AppMConstants.MOBILE_APPS_IOS_EXT.equals(fileExtension)) {
                            information = zipFileReading.readiOSManifestFile(filePath, filename);
                        }
                        JSONObject binaryObj = new JSONObject(information);
                        binaryDTO.setPackage(binaryObj.getString("package"));
                        binaryDTO.setVersion(binaryObj.getString("version"));

                        binaryDTO.setPath(filename);
                    } else {
                        RestApiUtil.handleBadRequest("Invalid Filetype is provided", log);
                    }
                } else {
                    RestApiUtil.handleBadRequest("Invalid file is provided with unsupported Media type.", log);
                }

            } else {
                RestApiUtil.handleBadRequest("'file' should be specified", log);
            }
        } catch (AppManagementException e) {
            RestApiUtil.handleInternalServerError(
                    "Error occurred while parsing binary file archive and retrieving information", e, log);
        } catch (JSONException e) {
            RestApiUtil.handleInternalServerError(
                    "Error occurred while parsing metadata of binary and retrieving information", e, log);
        }
        return Response.ok().entity(binaryDTO).build();
    }

    /**
     * Retrieve mobile binary from storage
     *
     * @param fileName          binary file name
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return
     */
    @Override
    public Response appsMobileBinariesFileNameGet(String fileName, String ifMatch, String ifUnmodifiedSince) {
        File binaryFile = null;
        String contentType = null;
        try {
            if(!RestApiUtil.isValidFileName(fileName)){
                RestApiUtil.handleBadRequest("Invalid filename '"+fileName +"' is provided", log);
            }

            String fileExtension = FilenameUtils.getExtension(fileName);
            if (AppMConstants.MOBILE_APPS_ANDROID_EXT.equals(fileExtension) ||
                    AppMConstants.MOBILE_APPS_IOS_EXT.equals(fileExtension)) {

                binaryFile = RestApiUtil.readFileFromStorage(fileName);
                contentType = new MimetypesFileTypeMap().getContentType(binaryFile);
                if (!contentType.startsWith("application")) {
                    RestApiUtil.handleBadRequest("Invalid file '" + fileName + "' with unsupported file type requested",
                                                 log);
                }
            } else {
                RestApiUtil.handleBadRequest("Invalid file '" + fileName + "' with unsupported media type is requested",
                                             log);
            }
        } catch (AppManagementException e) {
            if (RestApiUtil.isDueToResourceNotFound(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleResourceNotFoundError("Static Content", fileName, e, log);
            } else {
                RestApiUtil.handleInternalServerError(
                        "Error occurred while retrieving mobile binary : " + fileName + "from storage", e, log);
            }
        }
        Response.ResponseBuilder response = Response.ok((Object) binaryFile);
        response.header(RestApiConstants.HEADER_CONTENT_DISPOSITION, RestApiConstants.CONTENT_DISPOSITION_ATTACHMENT
                + "; " + RestApiConstants.CONTENT_DISPOSITION_FILENAME + "=\"" + fileName + "\"");
        response.header(RestApiConstants.HEADER_CONTENT_TYPE, contentType);
        return response.build();
    }

    @Override
    public Response appsMobileGetplistTenantTenantIdFileFileNameGet(String tenantId, String fileName, String accept,
                                                                    String ifNoneMatch) {
        return null;
    }

    /**
     * Upload static contents like images into storage
     *
     * @param fileInputStream   Upload static content's fileInputStream
     * @param fileDetail        uploading file details
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return API path of the uploaded static content
     */
    @Override
    public Response appsStaticContentsPost(String appType, InputStream fileInputStream, Attachment fileDetail,
                                           String ifMatch, String ifUnmodifiedSince) {

        CommonValidator.isValidAppType(appType);
        Map<String, String> response = new HashMap<>();

        try {
            if (fileInputStream != null) {
                FileContent fileContent = new FileContent();
                if ("image".equals(fileDetail.getContentType().getType()) ||
                        "application".equals(fileDetail.getContentType().getType())) {
                    String fileName = fileDetail.getContentDisposition().getParameter(
                            RestApiConstants.CONTENT_DISPOSITION_FILENAME);
                    if(!RestApiUtil.isValidFileName(fileName)){
                        RestApiUtil.handleBadRequest("Invalid file '"+fileName +"' has been provided to upload", log);
                    }

                    String fileExtension = FilenameUtils.getExtension(fileName);
                    String filename = RestApiPublisherUtils.generateBinaryUUID() + "." + fileExtension;
                    fileContent.setFileName(filename);
                    fileContent.setContent(fileInputStream);
                    fileContent.setContentType(fileDetail.getContentType().toString());
                    if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                        RestApiPublisherUtils.uploadFileIntoStorage(fileContent);
                        response.put("id", filename);
                    } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                        try {
                            DefaultAppRepository defaultAppRepository = new DefaultAppRepository(null);
                            UUID contentUUID = UUID.randomUUID();
                            fileContent.setUuid(contentUUID.toString());
                            fileContent.setContentLength(fileInputStream.available());
                            defaultAppRepository.persistStaticContents(fileContent);
                            response.put("id", contentUUID.toString() + File.separator + filename);
                        } catch (IOException e) {
                            RestApiUtil.handleInternalServerError("Error occurred while uploading static content", e, log);
                        }
                    }
                } else {
                    RestApiUtil.handleBadRequest("Invalid file is provided with unsupported Media type.", log);
                }
            } else {
                RestApiUtil.handleBadRequest("'file' should be specified", log);
            }
        } catch (AppManagementException e) {
            RestApiUtil.handleInternalServerError(
                    "Error occurred while parsing binary file archive and retrieving information", e, log);
        }
        return Response.ok().entity(response).build();
    }

    /**
     * Retrieve a given static content from storage
     *
     * @param fileName          request file name
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return
     */
    @Override
    public Response appsStaticContentsFileNameGet(String appType, String fileName, String ifMatch, String ifUnmodifiedSince) {
        CommonValidator.isValidAppType(appType);
        File staticContentFile = null;
        String contentType = null;

        try {

            if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {

                staticContentFile = RestApiUtil.readFileFromStorage(fileName);
                if (staticContentFile == null) {
                    RestApiUtil.handleResourceNotFoundError("Static Content", fileName, log);
                }
                contentType = RestApiUtil.readFileContentType(staticContentFile.getAbsolutePath());
            } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                OutputStream outputStream = null;
                AppRepository appRepository = new DefaultAppRepository(null);
                try {
                    FileContent fileContent = appRepository.getStaticContent(fileName);
                    if (fileContent == null) {
                        RestApiUtil.handleResourceNotFoundError("Static Content", fileName, log);
                    }
                    staticContentFile = File.createTempFile("temp", ".tmp");
                    outputStream = new FileOutputStream(staticContentFile);
                    IOUtils.copy(fileContent.getContent(), outputStream);
                    contentType = fileContent.getContentType();
                } catch (IOException e) {
                    RestApiUtil.handleBadRequest("Error occurred while retrieving static content '" + fileName + "'", log);
                }
            }

            if (contentType != null && !contentType.startsWith("image")) {
                RestApiUtil.handleBadRequest("Invalid file '" + fileName + "'with unsupported file type requested",
                        log);
            }

            Response.ResponseBuilder response = Response.ok((Object) staticContentFile);
            response.header(RestApiConstants.HEADER_CONTENT_DISPOSITION, RestApiConstants.CONTENT_DISPOSITION_ATTACHMENT
                    + "; " + RestApiConstants.CONTENT_DISPOSITION_FILENAME + "=\"" + fileName + "\"");
            response.header(RestApiConstants.HEADER_CONTENT_TYPE, contentType);
            return response.build();
        } catch (AppManagementException e) {
            if (RestApiUtil.isDueToResourceNotFound(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleResourceNotFoundError("Static Content", fileName, e, log);
            } else {
                RestApiUtil.handleInternalServerError(
                        "Error occurred while retrieving static content : " + fileName + "from storage", e, log);
            }
        }
        return null;
    }

    @Override
    public Response appsAppTypeGet(String appType, String query, String fieldFilter, Integer limit, Integer offset,
                                   String accept, String ifNoneMatch) {
        //setting default limit and offset values if they are not set
        limit = limit != null ? limit : RestApiConstants.PAGINATION_LIMIT_DEFAULT;
        offset = offset != null ? offset : RestApiConstants.PAGINATION_OFFSET_DEFAULT;
        query = query == null ? "" : query;

        try {
            //check if a valid asset type is provided
            if (!(AppMConstants.WEBAPP_ASSET_TYPE.equalsIgnoreCase(appType) || AppMConstants.MOBILE_ASSET_TYPE.equalsIgnoreCase(appType))) {
                String errorMessage = "Invalid Asset Type : " + appType;
                RestApiUtil.handleBadRequest(errorMessage, log);
            }

            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();

            List<App> result = apiProvider.searchApps(appType, RestApiUtil.getSearchTerms(query));

            AppListDTO appListDTO = null;
            if(fieldFilter == null || "BASIC".equalsIgnoreCase(fieldFilter)){
                appListDTO = APPMappingUtil.getAppListDTOWithBasicFields(result, offset, limit);

            }else {
                appListDTO = APPMappingUtil.getAppListDTOWithAllFields(result, offset, limit);
            }

            APPMappingUtil.setPaginationParams(appListDTO, query, offset, limit, result.size());
            return Response.ok().entity(appListDTO).build();
        } catch (AppManagementException e) {
            String errorMessage = "Error while retrieving Apps";
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return null;
    }


    /**
     * Create an application
     *
     * @param appType         application type ie: webapp, mobileapp
     * @param body            Application DTO
     * @param contentType
     * @param ifModifiedSince
     * @return created application id
     */
    @Override
    public Response appsAppTypePost(String appType, AppDTO body, String contentType, String ifModifiedSince) {
        CommonValidator.isValidAppType(appType);
        beanValidator = new BeanValidator();
        //Validate common mandatory fields for mobile and webapp
        beanValidator.validate(body);
        Map<String, String> response = new HashMap<>();
        AppDTOValidator.validateAppDTO(appType, body);
        String applicationId = null;
        try {
            APIProvider appProvider = RestApiUtil.getLoggedInUserProvider();
            if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {

                MobileApp mobileApp = APPMappingUtil.fromDTOtoMobileApp(body);
                applicationId = appProvider.createMobileApp(mobileApp);
            }
            response.put("AppId", applicationId);
        } catch (AppManagementException e) {
            if (RestApiUtil.isDueToResourceAlreadyExisting(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleConflictException("A duplicate " + appType + " already exists with the name : "
                                                            + body.getName(), log);
            } else {
                RestApiUtil.handleInternalServerError(
                        "Error occurred while creating mobile application : " + body.getName(), e, log);
            }
        }

        return Response.ok().entity(response).build();
    }

    /**
     * Change lifecycle state of an application
     *
     * @param appType           application type ie: webapp, mobileapp
     * @param action            lifecycle action
     * @param appId             application uuid
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return status message
     */
    @Override
    public Response appsAppTypeChangeLifecyclePost(String appType, String action, String appId, String ifMatch,
                                                   String ifUnmodifiedSince) {
        CommonValidator.isValidAppType(appType);
        ResponseMessageDTO responseMessageDTO = new ResponseMessageDTO();
        try {

            APIProvider appProvider = RestApiUtil.getLoggedInUserProvider();
            String[] allowedLifecycleActions = appProvider.getAllowedLifecycleActions(appId, appType);
            if (!ArrayUtils.contains(allowedLifecycleActions, action)) {
                RestApiUtil.handleBadRequest(
                        "Action '" + action + "' is not allowed to perform on " + appType + " with id: " + appId +
                                ". Allowed actions are " + Arrays.toString(allowedLifecycleActions), log);
            }
            appProvider.changeLifeCycleStatus(appType, appId, action);

            responseMessageDTO.setMessage("Lifecycle action : " + action + " has been accepted for processing ");
        } catch (AppManagementException e) {
            //Auth failure occurs when cross tenant accessing APIs. Sends 404, since we don't need to expose the
            // existence of the resource
            if (RestApiUtil.isDueToResourceNotFound(e)) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, e, log);
            } else if (RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleAuthorizationFailedError("The user is not permitted to perform lifecycle action '" +
                                                                   action + "' on " + appType + " with uuid " + appId,
                                                           e, log);
            } else {
                String errorMessage = "Error while changing lifecycle state of app with id : " + appId;
                RestApiUtil.handleInternalServerError(errorMessage, e, log);
            }
        }
        return Response.accepted().entity(responseMessageDTO).build();
    }

    @Override
    public Response appsAppTypeIdAppIdGet(String appType, String appId, String accept, String ifNoneMatch,
                                          String ifModifiedSince) {
        AppDTO appDTO;
        try {

            Map<String, String> searchTerms = new HashMap<String, String>();
            searchTerms.put("id", appId);

            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
            List<App> result = apiProvider.searchApps(appType, searchTerms);

            if (result.isEmpty()) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, log);
            }

            App app = result.get(0);
            appDTO = APPMappingUtil.fromAppToDTO(app);

            return Response.ok().entity(appDTO).build();
        } catch (AppManagementException e) {
            //Auth failure occurs when cross tenant accessing APIs. Sends 404, since we don't need to expose the
            // existence of the resource
            if (RestApiUtil.isDueToResourceNotFound(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, e, log);
            } else {
                String errorMessage = "Error while retrieving App : " + appId;
                RestApiUtil.handleInternalServerError(errorMessage, e, log);
            }
        }
        return null;
    }

    /**
     * Update an application
     *
     * @param appType           appType application type ie: webapp, mobileapp
     * @param appId             application id
     * @param body              Application DTO
     * @param contentType
     * @param ifMatch
     * @param ifUnmodifiedSince
     * @return
     */
    @Override
    public Response appsAppTypeIdAppIdPut(String appType, String appId, AppDTO body, String contentType, String ifMatch,
                                          String ifUnmodifiedSince) {

        if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
            try {
                APIProvider appProvider = RestApiUtil.getLoggedInUserProvider();
                //TODO:APP Validations
                //TODO:Get provider name from context (Token owner)
                //TODO:Permission check
                MobileApp updatingMobileApp = APPMappingUtil.fromDTOtoMobileApp(body);
                updatingMobileApp.setAppId(appId);
                appProvider.updateMobileApp(updatingMobileApp);

            } catch (AppManagementException e) {
                RestApiUtil.handleInternalServerError("Error occurred while ", e, log);
            }
        } else{
            RestApiUtil.handleBadRequest("Invalid application type :" + appType, log);
        }
        return Response.ok().build();
    }

    @Override
    public Response appsAppTypeIdAppIdDelete(String appType, String appId, String ifMatch, String ifUnmodifiedSince) {
        try {
            CommonValidator.isValidAppType(appType);

            Map<String, String> searchTerms = new HashMap<String, String>();
            searchTerms.put("id", appId);

            String username = RestApiUtil.getLoggedInUsername();
            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();

            List<App> result = apiProvider.searchApps(appType, searchTerms);
            if (result.isEmpty()) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, log);
            }

            App app = result.get(0);
            if (appType.equals(AppMConstants.MOBILE_ASSET_TYPE)) {
                removeRegistryArtifact(app, username);
            }
            return Response.ok().build();
        } catch (AppManagementException e) {
            //Auth failure occurs when cross tenant accessing APIs. Sends 404, since we don't need to expose the
            // existence of the resource
            if (RestApiUtil.isDueToResourceNotFound(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, e, log);
            } else {
                String errorMessage = "Error while deleting App : " + appId;
                RestApiUtil.handleInternalServerError(errorMessage, e, log);
            }
        } catch (RegistryException e) {
            RestApiUtil.handleInternalServerError("Error while initializing registry", e, log);
        } catch (UserStoreException e) {
            RestApiUtil.handleInternalServerError("Error while initializing UserStore", e, log);
        }
        return null;
    }

    @Override
    public Response appsAppTypeIdAppIdCreateNewVersionPost(String appType, String appId, AppDTO body,String contentType,
                                                           String ifModifiedSince){
        APIProvider apiProvider = null;
        try {
            apiProvider = RestApiUtil.getLoggedInUserProvider();

            App app = null;
            if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                MobileApp mobileAppModel = new MobileApp();
                mobileAppModel.setVersion(body.getVersion());
                mobileAppModel.setDisplayName(body.getDisplayName());
                mobileAppModel.setType(AppMConstants.MOBILE_ASSET_TYPE);
                app = mobileAppModel;
            } else {
                RestApiUtil.handleBadRequest("Invalid application type :" + appType, log);
            }

            app.setUUID(appId);
            String newUUID = apiProvider.createNewVersion(app);

            Map<String, String> response = new HashMap<>();
            response.put("AppId", newUUID);

            return Response.ok(response).build();
        } catch (AppManagementException e) {
            RestApiUtil.handleInternalServerError(String.format("Error while creating new version for the app '%s':'%s'", appType, appId), e, log);
        }

        return null;
    }

    @Override
    public Response appsAppTypeIdAppIdDiscoverPost(String appType, String appId, String contentType,
                                                   String ifModifiedSince) {
        return null;
    }

    @Override
    public Response appsAppTypeIdAppIdLifecycleGet(String appType, String appId, String accept, String ifNoneMatch) {
        LifeCycleDTO lifeCycleDTO = new LifeCycleDTO();
        try {
            //Validate App Type
            CommonValidator.isValidAppType(appType);
            String username = RestApiUtil.getLoggedInUsername();
            String tenantDomainName = MultitenantUtils.getTenantDomain(username);
            String tenantUserName = MultitenantUtils.getTenantAwareUsername(username);
            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getTenantId(
                    tenantDomainName);
            Registry registry = ServiceReferenceHolder.getInstance().
                    getRegistryService().getGovernanceUserRegistry(tenantUserName, tenantId);
            boolean isAsynchronousFlow = true;
            GenericArtifactManager artifactManager = new GenericArtifactManager(registry, appType);
            GenericArtifact artifact = artifactManager.getGenericArtifact(appId);
            //Validate App Id
            if (artifact == null) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, log);
            }

            String state = artifact.getLifecycleState().toUpperCase();
            String[] actions;
            if (AppMConstants.MOBILE_ASSET_TYPE.equalsIgnoreCase(appType)) {
                actions = artifact.getAllLifecycleActions(AppMConstants.MOBILE_LIFE_CYCLE);
            } else {
                actions = artifact.getAllLifecycleActions(AppMConstants.WEBAPP_LIFE_CYCLE);
            }

            lifeCycleDTO.setActions(Arrays.asList(actions));
            lifeCycleDTO.setAsync(isAsynchronousFlow);
            lifeCycleDTO.setState(state);
        } catch (Exception e) {
            String errorMessage = "Error while retrieving lifecycle state of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return Response.ok().entity(lifeCycleDTO).build();
    }

    @Override
    public Response appsAppTypeIdAppIdLifecycleHistoryGet(String appType, String appId, String accept,
                                                          String ifNoneMatch) {
        LifeCycleHistoryListDTO lifeCycleHistoryListDTO = new LifeCycleHistoryListDTO();
        try {
            //Validate App Type
            CommonValidator.isValidAppType(appType);
            String username = RestApiUtil.getLoggedInUsername();
            String tenantDomainName = MultitenantUtils.getTenantDomain(username);
            String tenantUserName = MultitenantUtils.getTenantAwareUsername(username);
            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getTenantId(
                    tenantDomainName);
            Registry registry = ServiceReferenceHolder.getInstance().
                    getRegistryService().getGovernanceUserRegistry(tenantUserName, tenantId);
            GenericArtifactManager artifactManager = new GenericArtifactManager(registry, appType);
            GenericArtifact artifact = artifactManager.getGenericArtifact(appId);
            //Validate App Id
            if (artifact == null) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, log);
            }

            String historyRegPath = getHistoryPath(artifact);
            String historyResourceXMLStr = IOUtils.toString(registry.get(historyRegPath).getContentStream());
            JSONObject historyResourceObj = XML.toJSONObject(historyResourceXMLStr);

            JSONArray historyResourceJsonArray = (historyResourceObj.getJSONObject("lifecycleHistory")).getJSONArray(
                    "item");
            List<LifeCycleHistoryDTO> lifeCycleHistoryDTOList = new ArrayList<>();
            //iterate life cycle history json
            for (int i = 0; i < historyResourceJsonArray.length() - 1; i++) {
                JSONObject lifecycleHistoryStateObj = (JSONObject) historyResourceJsonArray.get(i);
                LifeCycleHistoryDTO lifeCycleHistoryDTO = new LifeCycleHistoryDTO();
                lifeCycleHistoryDTO.setOrder(Integer.parseInt(lifecycleHistoryStateObj.get("order").toString()));
                lifeCycleHistoryDTO.setState((String) lifecycleHistoryStateObj.get("state"));
                lifeCycleHistoryDTO.setTargetState((String) lifecycleHistoryStateObj.get("targetState"));
                lifeCycleHistoryDTO.setTimestamp((String) lifecycleHistoryStateObj.get("timestamp"));
                lifeCycleHistoryDTO.setUser((String) lifecycleHistoryStateObj.get("user"));
                lifeCycleHistoryDTOList.add(lifeCycleHistoryDTO);
            }
            lifeCycleHistoryListDTO.setLifeCycleHistoryList(lifeCycleHistoryDTOList);
        } catch (GovernanceException e) {
            String errorMessage = "GovernanceException while retrieving lifecycle History of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        } catch (IOException e) {
            String errorMessage = "IOException while retrieving lifecycle History of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        } catch (UserStoreException e) {
            String errorMessage = "UserStoreException while retrieving lifecycle History of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        } catch (RegistryException e) {
            String errorMessage = "RegistryException while retrieving lifecycle History of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        } catch (JSONException e) {
            String errorMessage = "JSONException while retrieving lifecycle History of app with id : " + appId;
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return Response.ok().entity(lifeCycleHistoryListDTO).build();
    }

    @Override
    public Response appsAppTypeIdAppIdSubscriptionsGet(String appType, String appId, String accept, String ifNoneMatch,
                                                       String ifModifiedSince) {
        UserIdListDTO userIdListDTO = new UserIdListDTO();
        try {
            APIProvider appProvider = RestApiUtil.getLoggedInUserProvider();
            if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {

                AppManagerConfiguration appManagerConfiguration = ServiceReferenceHolder.getInstance().
                        getAPIManagerConfigurationService().getAPIManagerConfiguration();
                Boolean isSelfSubscriptionEnabled = Boolean.valueOf(appManagerConfiguration.getFirstProperty(
                        AppMConstants.ENABLE_SELF_SUBSCRIPTION));
                Boolean isEnterpriseSubscriptionEnabled = Boolean.valueOf(appManagerConfiguration.getFirstProperty(
                        AppMConstants.ENABLE_ENTERPRISE_SUBSCRIPTION));
                if (isSelfSubscriptionEnabled || isEnterpriseSubscriptionEnabled) {
                    //TODO: Check the usage of this function.
                } else {
                    RestApiUtil.handleBadRequest("Subscription is disabled", log);
                }
            } else {
                RestApiUtil.handleBadRequest("Unsupported application type '" + appType + "' provided", log);
            }
        } catch (AppManagementException e) {
            if (RestApiUtil.isDueToResourceNotFound(e) || RestApiUtil.isDueToAuthorizationFailure(e)) {
                RestApiUtil.handleResourceNotFoundError(appType, appId, e, log);
            } else {
                String errorMessage = "Error while changing lifecycle state of app with id : " + appId;
                RestApiUtil.handleInternalServerError(errorMessage, e, log);
            }

        }
        return Response.ok().entity(userIdListDTO).build();
    }

    @Override
    public Response appsAppTypeThrottlingtiersGet(String appType, String accept,
                                                  String ifNoneMatch) {
        TierListDTO tierListDTO = new TierListDTO();
        try {
            //check appType validity (currently support only webApps)
            if (!AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                RestApiUtil.handleBadRequest("Unsupported application type '" + appType + "' provided", log);
            }

            List<TierDTO> tierDTOList = new ArrayList<>();
            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
            Set<Tier> tiers = apiProvider.getTiers();
            if (tiers.isEmpty()) {
                return RestApiUtil.buildNotFoundException("Tiers", null).getResponse();
            }

            for (Tier tier : tiers) {
                TierDTO tierDTO = new TierDTO();
                tierDTO.setTierName(tier.getName());
                tierDTO.setTierDisplayName(tier.getDisplayName());
                tierDTO.setTierDescription(tier.getDescription() != null ? tier.getDescription() : "");
                tierDTO.setTierSortKey(tier.getRequestPerMinute());
                tierDTOList.add(tierDTO);
            }
            tierListDTO.setTierList(tierDTOList);
        } catch (AppManagementException e) {
            String errorMessage = "Error while retrieving Throttling Tier details";
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return Response.ok().entity(tierListDTO).build();
    }

    private boolean isTimeStampValid(String timeStamp)
    {
        SimpleDateFormat format = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        try{
            format.parse(timeStamp);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    /**
     * Validate webapp context
     *
     * @param appType         application type
     * @param appContext      context of the webapp
     * @param contentType
     * @param ifModifiedSince
     * @return whether context is valid or not
     */
    @Override
    public Response appsAppTypeValidateContextPost(String appType, String appContext, String contentType,
                                                   String ifModifiedSince) {
        boolean isContextExists = false;
        Map<String, Boolean> responseMap = new HashMap<>();
        try {
            if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                if (StringUtils.isEmpty(appContext)) {
                    RestApiUtil.handleBadRequest("Webapp context is not provided", log);
                }

                if (appContext.indexOf("/") != 0) {
                    appContext = "/" + appContext;
                }
                APIProvider appProvider = RestApiUtil.getLoggedInUserProvider();
                isContextExists = appProvider.isContextExist(appContext);
                responseMap.put("IsContextExists", isContextExists);
            } else {
                RestApiUtil.handleBadRequest("Unsupported application type '" + appType + "' provided", log);
            }
        } catch (AppManagementException e) {
            String errorMessage = "Error retrieving tags for " + appType + "s.";
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return Response.ok().entity(responseMap).build();
    }

    //remove artifact from registry
    private void removeRegistryArtifact(App webApp, String username)
            throws RegistryException, AppManagementException, UserStoreException {
        String tenantDomainName = MultitenantUtils.getTenantDomain(username);
        String tenantUserName = MultitenantUtils.getTenantAwareUsername(username);
        int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getTenantId(
                tenantDomainName);
        Registry registry = ServiceReferenceHolder.getInstance().
                getRegistryService().getGovernanceUserRegistry(tenantUserName, tenantId);

        GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                                                                                   AppMConstants.MOBILE_ASSET_TYPE);
        artifactManager.removeGenericArtifact(webApp.getUUID());
    }

    private String getHistoryPath(GenericArtifact genericArtifact) throws GovernanceException {
        String assetPath = genericArtifact.getPath();
        //Replace the / in the assetPath
        String partialHistoryPath = assetPath.replace("/", "_");
        String fullPath = RestApiConstants.HISTORY_PATH + "__system_governance" + partialHistoryPath;
        return fullPath;
    }
}
