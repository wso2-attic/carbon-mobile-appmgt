package org.wso2.carbon.appmgt.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APPLifecycleActions;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.FileContent;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.api.model.OneTimeDownloadLink;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.appmgt.impl.utils.AppMgtDataSourceProvider;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.governance.api.exception.GovernanceException;
import org.wso2.carbon.governance.api.generic.GenericArtifactManager;
import org.wso2.carbon.governance.api.generic.dataobjects.GenericArtifact;
import org.wso2.carbon.governance.api.util.GovernanceUtils;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.registry.core.utils.RegistryUtils;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.xml.namespace.QName;
import java.io.InputStream;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The default implementation of DefaultAppRepository which uses RDBMS and Carbon registry for persistence.
 */
public class DefaultAppRepository implements AppRepository {

    private static final Log log = LogFactory.getLog(DefaultAppRepository.class);

    private static final String POLICY_GROUP_TABLE_NAME = "APM_POLICY_GROUP";
    private static final String POLICY_GROUP_PARTIAL_MAPPING_TABLE_NAME = "APM_POLICY_GRP_PARTIAL_MAPPING";

    private Registry registry;

    public DefaultAppRepository(){

    }

    public DefaultAppRepository(Registry registry){
        this.registry = registry;
    }

    // ------------------- START : Repository API implementation methods. ----------------------------------

    @Override
    public String saveApp(App app) throws AppManagementException {
        if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
            return persistMobileApp((MobileApp) app);
        }

        return null;
    }

    @Override
    public String createNewVersion(App app) throws AppManagementException {
        if (AppMConstants.MOBILE_ASSET_TYPE.equals(app.getType())) {
            MobileApp newVersion = createNewMobileAppVersion((MobileApp) app);
            return newVersion.getUUID();
        }

        return null;
    }

    @Override
    public void updateApp(App app) throws AppManagementException {
    }

    @Override
    public App getApp(String type, String uuid) throws AppManagementException {


        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, type);
            GenericArtifact artifact = artifactManager.getGenericArtifact(uuid);

            if(artifact != null){
                App app = getApp(type, artifact);
                app.setType(type);
                return app;
            }else{
                return null;
            }
        } catch (GovernanceException e) {
            throw new AppManagementException(String.format("Error while querying registry for '%s':'%s'", type, uuid));
        }
    }

    @Override
    public List<App> searchApps(String type, Map<String, String> searchTerms) throws AppManagementException {

        List<App> apps = new ArrayList<App>();
        List<GenericArtifact> appArtifacts = null;

        try {
            appArtifacts = getAllAppArtifacts(type);
        } catch (GovernanceException e) {
            handleException(String.format("Error while retrieving registry artifacts during app search for the type '%s'", type), e);
        }

        for(GenericArtifact artifact : appArtifacts){
            if(isSearchHit(artifact, searchTerms)){
                App app = getApp(type, artifact);
                app.setType(type);
                apps.add(app);
            }
        }

        return apps;

    }

    @Override
    public void persistStaticContents(FileContent fileContent) throws AppManagementException {
        Connection connection = null;

        PreparedStatement preparedStatement = null;
        String query = "INSERT INTO resource (UUID,TENANTID,FILENAME,CONTENTLENGTH,CONTENTTYPE,CONTENT) VALUES (?,?,?,?,?,?)";
        try {
            connection = AppMgtDataSourceProvider.getStorageDBConnection();
            if (connection.getMetaData().getDriverName().contains(AppMConstants.DRIVER_TYPE_ORACLE)) {
                query = "INSERT INTO \"resource\" (UUID,TENANTID,FILENAME,CONTENTLENGTH,CONTENTTYPE,CONTENT) VALUES " +
                        "(?,?,?,?,?,?)";
            }
            preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, fileContent.getUuid());
            preparedStatement.setString(2, getTenantDomainOfCurrentUser());
            preparedStatement.setString(3, fileContent.getFileName());
            preparedStatement.setInt(4, fileContent.getContentLength());
            preparedStatement.setString(5, fileContent.getContentType());
            preparedStatement.setBlob(6, fileContent.getContent());
            preparedStatement.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                handleException(String.format("Couldn't rollback save operation for the static content"), e1);
            }
            handleException("Error occurred while saving static content :" + fileContent.getFileName(), e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStatement, connection, null);
        }
    }

    @Override
    public FileContent getStaticContent(String contentId)throws AppManagementException {
        Connection connection = null;
        FileContent fileContent = null;

        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            String query = "SELECT CONTENT,CONTENTTYPE FROM resource WHERE FILENAME = ? AND TENANTID = ?";
            connection = AppMgtDataSourceProvider.getStorageDBConnection();
            preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, contentId);
            preparedStatement.setString(2, getTenantDomainOfCurrentUser());
            resultSet = preparedStatement.executeQuery();
            while (resultSet.next()){
                Blob staticContentBlob = resultSet.getBlob("CONTENT");
                InputStream inputStream = staticContentBlob.getBinaryStream();
                fileContent = new FileContent();
                fileContent.setContentType(resultSet.getString("CONTENTTYPE"));
                fileContent.setContent(inputStream);
            }
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                handleException(String.format("Couldn't rollback retrieve operation for the static content '"+contentId+"'"), e1);
            }
            handleException("Error occurred while saving static content :" + contentId, e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStatement, connection, null);
        }
        return fileContent;

    }

    /**
     * Persist one-tim download link reference in database
     * @param oneTimeDownloadLink
     * @throws AppManagementException
     */
    @Override
    public void persistOneTimeDownloadLink(OneTimeDownloadLink oneTimeDownloadLink) throws AppManagementException {
        Connection connection = null;

        PreparedStatement preparedStatement = null;
        String queryToPersistOneTimeDownload =
                "INSERT INTO APM_ONE_TIME_DOWNLOAD_LINK (BINARY_FILE,UUID,IS_DOWNLOADED,USERNAME, TENANT_ID, TENANT_DOMAIN, CREATED_TIME) VALUES (?,?,?,?,?,?,?)";
        try {
            connection = getRDBMSConnectionWithoutAutoCommit();
            preparedStatement = connection.prepareStatement(queryToPersistOneTimeDownload);
            preparedStatement.setString(1, oneTimeDownloadLink.getFileName());
            preparedStatement.setString(2, oneTimeDownloadLink.getUUID());
            preparedStatement.setBoolean(3, oneTimeDownloadLink.isDownloaded());
            preparedStatement.setString(4, getUsernameOfCurrentUser());
            preparedStatement.setInt(5, getTenantIdOfCurrentUser());
            preparedStatement.setString(6, getTenantDomainOfCurrentUser());
            preparedStatement.setTimestamp(7, new Timestamp(new java.util.Date().getTime()));
            preparedStatement.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                handleException(
                        String.format("Couldn't rollback save operation of one-time download link reference for uuid "+
                                oneTimeDownloadLink.getUUID()), e1);
            }
            handleException("Error occurred while persisting one-time download link reference for uuid " +
                    oneTimeDownloadLink.getUUID(), e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStatement, connection, null);
        }
    }

    /**
     * Retrieve one-time download link details from database
     * @param UUID
     * @return
     * @throws AppManagementException
     */
    @Override
    public OneTimeDownloadLink getOneTimeDownloadLinkDetails(String UUID) throws AppManagementException {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        OneTimeDownloadLink oneTimeDownloadLink = null;
        String queryToRetrieveOneTimeDownloadLinkDetails =
                "SELECT BINARY_FILE, IS_DOWNLOADED, USERNAME, TENANT_ID, TENANT_DOMAIN FROM APM_ONE_TIME_DOWNLOAD_LINK WHERE UUID = ?";
        ResultSet downloadLinkData = null;
        try {
            connection = getRDBMSConnectionWithoutAutoCommit();
            preparedStatement = connection.prepareStatement(queryToRetrieveOneTimeDownloadLinkDetails);
            preparedStatement.setString(1, UUID);
            downloadLinkData = preparedStatement.executeQuery();
            while (downloadLinkData.next()){
                oneTimeDownloadLink = new OneTimeDownloadLink();
                oneTimeDownloadLink.setUUID(UUID);
                oneTimeDownloadLink.setFileName(downloadLinkData.getString("BINARY_FILE"));
                oneTimeDownloadLink.setDownloaded(downloadLinkData.getBoolean("IS_DOWNLOADED"));
                oneTimeDownloadLink.setCreatedUserName(downloadLinkData.getString("USERNAME"));
                oneTimeDownloadLink.setCreatedTenantID(downloadLinkData.getInt("TENANT_ID"));
                oneTimeDownloadLink.setCreatedTenantDomain(downloadLinkData.getString("TENANT_DOMAIN"));
//                oneTimeDownloadLink.setCreatedTime(downloadLinkData.getTimestamp("CREATED_TIME").getTime());
            }

        } catch (SQLException e) {

            handleException("Error occurred while retrieving one-time download link details for uuid " +
                    oneTimeDownloadLink.getUUID(), e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStatement, connection, downloadLinkData);
        }
        return oneTimeDownloadLink;
    }

    @Override
    public void updateOneTimeDownloadLinkStatus(OneTimeDownloadLink oneTimeDownloadLink) throws AppManagementException{
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        String queryToUpdateOneTimeDownloadLinkStatus =
                "UPDATE APM_ONE_TIME_DOWNLOAD_LINK SET IS_DOWNLOADED=? WHERE UUID = ?";
        try {
            connection = getRDBMSConnectionWithoutAutoCommit();
            preparedStatement = connection.prepareStatement(queryToUpdateOneTimeDownloadLinkStatus);
            preparedStatement.setBoolean(1, oneTimeDownloadLink.isDownloaded());
            preparedStatement.setString(2, oneTimeDownloadLink.getUUID());
            preparedStatement.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                handleException(
                        String.format("Couldn't rollback update operation of one-time download link reference for uuid "+
                                oneTimeDownloadLink.getUUID()), e1);
            }
            handleException("Error occurred while retrieving one-time download link details for uuid " +
                    oneTimeDownloadLink.getUUID(), e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStatement, connection, null);
        }
    }

    // ------------------- END : Repository API implementation methods. ----------------------------------

    private AppFactory getAppFactory(String appType) {
        if(AppMConstants.MOBILE_ASSET_TYPE.equals(appType)){
            return new MobileAppFactory();
        }else{
            return null;
        }
    }

    private App getApp(String type, GenericArtifact appArtifact) throws AppManagementException {
        if (AppMConstants.MOBILE_ASSET_TYPE.equals(type)) {
            return getMobileApp(appArtifact);
        }
        return null;
    }

    private boolean isSearchHit(GenericArtifact artifact, Map<String, String> searchTerms) throws AppManagementException {

        boolean isSearchHit = true;

        for(Map.Entry<String, String> term : searchTerms.entrySet()){
            try {
                if("ID".equalsIgnoreCase(term.getKey())) {
                    if(!artifact.getId().equals(term.getValue())){
                        isSearchHit = false;
                        break;
                    }
                }else if(!term.getValue().equalsIgnoreCase(artifact.getAttribute(getRxtAttributeName(term.getKey())))){
                    isSearchHit = false;
                    break;
                }
            } catch (GovernanceException e) {
                String errorMessage = String.format("Error while determining whether artifact '%s' is a search hit.", artifact.getId());
                throw new AppManagementException(errorMessage, e);
            }
        }

        return isSearchHit;
    }

    private String getRxtAttributeName(String searchKey) {

        String rxtAttributeName = null;

        if (searchKey.equalsIgnoreCase("NAME")) {
            rxtAttributeName = AppMConstants.API_OVERVIEW_NAME;
        } else if (searchKey.equalsIgnoreCase("PROVIDER")) {
            rxtAttributeName = AppMConstants.API_OVERVIEW_PROVIDER;
        } else if (searchKey.equalsIgnoreCase("VERSION")) {
            rxtAttributeName = AppMConstants.API_OVERVIEW_VERSION;
        }

        return rxtAttributeName;
    }

    private List<GenericArtifact> getAllAppArtifacts(String appType) throws GovernanceException, AppManagementException {

        List<GenericArtifact> appArtifacts = new ArrayList<GenericArtifact>();

        GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, appType);
        GenericArtifact[] artifacts = artifactManager.getAllGenericArtifacts();
        for (GenericArtifact artifact : artifacts) {
            appArtifacts.add(artifact);
        }

        return appArtifacts;
    }

    private MobileApp getMobileApp(GenericArtifact mobileAppArtifact) throws AppManagementException {
        AppFactory appFactory = getAppFactory(AppMConstants.MOBILE_ASSET_TYPE);
        MobileApp mobileApp = (MobileApp) appFactory.createApp(mobileAppArtifact, registry);
        return mobileApp;
    }

    private String persistMobileApp(MobileApp mobileApp) throws AppManagementException {
        String artifactId = null;
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                                                                                       AppMConstants.MOBILE_ASSET_TYPE);

            registry.beginTransaction();
            GenericArtifact genericArtifact =
                    artifactManager.newGovernanceArtifact(new QName(mobileApp.getAppName()));
            GenericArtifact artifact = AppManagerUtil.createMobileAppArtifactContent(genericArtifact, mobileApp);
            artifactManager.addGenericArtifact(artifact);
            artifactId = artifact.getId();
            mobileApp.setUUID(artifactId);
            changeLifeCycleStatus(AppMConstants.MOBILE_ASSET_TYPE, artifactId, APPLifecycleActions.CREATE.getStatus());
            String artifactPath = GovernanceUtils.getArtifactPath(registry, artifact.getId());
            Set<String> tagSet = mobileApp.getTags();
            if (tagSet != null) {
                for (String tag : tagSet) {
                    registry.applyTag(artifactPath, tag);
                }
            }

            if (mobileApp.getAppVisibility() != null) {
                AppManagerUtil.setResourcePermissions(mobileApp.getAppProvider(),
                                                      AppMConstants.API_RESTRICTED_VISIBILITY,
                                                      mobileApp.getAppVisibility(), artifactPath);
            }
            registry.commitTransaction();
        } catch (RegistryException e) {
            try {
                registry.rollbackTransaction();
            } catch (RegistryException re) {
                handleException(
                        "Error while rolling back the transaction for mobile application: "
                                + mobileApp.getAppName(), re);
            }
            handleException("Error occurred while creating the mobile application : " + mobileApp.getAppName(), e);
        }
        return artifactId;
    }


    /**
     * Change the lifecycle state of a given application
     *
     * @param appType         application type ie: webapp, mobileapp
     * @param appId           application uuid
     * @param lifecycleAction lifecycle action perform on the application
     * @throws AppManagementException
     */
    private void changeLifeCycleStatus(String appType, String appId, String lifecycleAction)
            throws AppManagementException, RegistryException {

        try {
            String username = getUsernameOfCurrentUser();
            String tenantDomain = getTenantDomainOfCurrentUser();

            String requiredPermission = null;

            if (AppMConstants.LifecycleActions.SUBMIT_FOR_REVIEW.equals(lifecycleAction)) {
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.MOBILE_APP_CREATE;
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.WEB_APP_CREATE;
                }
            } else {
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.MOBILE_APP_PUBLISH;
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.WEB_APP_PUBLISH;
                }
            }

            if (!AppManagerUtil.checkPermissionQuietly(username, requiredPermission)) {
                handleException("The user " + username +
                                        " is not authorized to perform lifecycle action " + lifecycleAction + " on " +
                                        appType + " with uuid " + appId, null);
            }
            //Check whether the user has enough permissions to change lifecycle
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);

            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().
                    getTenantId(tenantDomain);

            AuthorizationManager authManager = ServiceReferenceHolder.getInstance().getRealmService().
                    getTenantUserRealm(tenantId).getAuthorizationManager();

            //Get system registry for logged in tenant domain
            Registry systemRegistry = ServiceReferenceHolder.getInstance().
                    getRegistryService().getGovernanceSystemRegistry(tenantId);
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(systemRegistry, appType);
            GenericArtifact appArtifact = artifactManager.getGenericArtifact(appId);
            String resourcePath = RegistryUtils.getAbsolutePath(RegistryContext.getBaseInstance(),
                                                                RegistryConstants.GOVERNANCE_REGISTRY_BASE_PATH +
                                                                        appArtifact.getPath());

            if (appArtifact != null) {
                if (!authManager.isUserAuthorized(username, resourcePath, "authorize")) {
                    //Throws resource authorization exception
                    handleException("The user " + username +
                                            " is not authorized to" + appType + " with uuid " + appId, null);
                }
                //Change lifecycle status
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    appArtifact.invokeAction(lifecycleAction, AppMConstants.MOBILE_LIFE_CYCLE);
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    appArtifact.invokeAction(lifecycleAction, AppMConstants.WEBAPP_LIFE_CYCLE);
                }

                //If application is role restricted, deny read rights for Internal/everyone and system/wso2.anonymous
                // .role roles
                if ((AppMConstants.LifecycleActions.PUBLISH.equals(lifecycleAction) ||
                        AppMConstants.LifecycleActions.RE_PUBLISH.equals(lifecycleAction)) &&
                        !StringUtils.isBlank(appArtifact.getAttribute("overview_visibleRoles"))) {

                    authManager.denyRole(AppMConstants.EVERYONE_ROLE, resourcePath, ActionConstants.GET);
                    authManager.denyRole(AppMConstants.ANONYMOUS_ROLE, resourcePath, ActionConstants.GET);
                }

                if (log.isDebugEnabled()) {
                    String logMessage =
                            "Lifecycle action " + lifecycleAction + " has been successfully performed on " + appType
                                    + " with id" + appId;
                    log.debug(logMessage);
                }
            } else {
                handleException("Failed to get " + appType + " artifact corresponding to artifactId " +
                                        appId + ". Artifact does not exist", null);
            }
        } catch (UserStoreException e) {
            handleException("Error occurred while performing lifecycle action : " + lifecycleAction + " on " + appType +
                                    " with id : " + appId + ". Failed to retrieve tenant id for user : ", e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private MobileApp createNewMobileAppVersion(MobileApp targetApp) throws AppManagementException {

        // Get the attributes of the source.
        MobileApp sourceApp = (MobileApp) getApp(targetApp.getType(), targetApp.getUUID());

        //check if the new app identity already exists
        final String appName = sourceApp.getAppName().toString();
        final String appVersion = targetApp.getVersion();
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                                                                                       AppMConstants.MOBILE_ASSET_TYPE);
            Map<String, List<String>> attributeListMap = new HashMap<String, List<String>>();
            attributeListMap.put(AppMConstants.API_OVERVIEW_NAME, new ArrayList<String>() {{
                add(appName);
            }});
            attributeListMap.put(AppMConstants.API_OVERVIEW_VERSION, new ArrayList<String>() {{
                add(appVersion);
            }});

            GenericArtifact[] existingArtifacts = artifactManager.findGenericArtifacts(attributeListMap);

            if (existingArtifacts != null && existingArtifacts.length > 0) {
                handleException("A duplicate webapp already exists with name '" +
                                        appName + "' and version '" + appVersion + "'", null);
            }
        } catch (GovernanceException e) {
            handleException("Error occurred while checking existence for webapp with name '" + appName +
                                    "' and version '" + appVersion + "'", null);
        }


        // Clear the ID.
        sourceApp.setUUID(null);

        // Set New Version.
        sourceApp.setOriginVersion(sourceApp.getVersion());
        sourceApp.setVersion(targetApp.getVersion());

        // Set the other properties accordingly.
        sourceApp.setDisplayName(targetApp.getDisplayName());
        sourceApp.setCreatedTime(String.valueOf(new Date().getTime()));
        saveApp(sourceApp);
        return sourceApp;
    }

    public static GenericArtifactManager getArtifactManager(Registry registry, String key) throws RegistryException {

        GenericArtifactManager artifactManager = null;

        GovernanceUtils.loadGovernanceArtifacts((UserRegistry) registry);
        if (GovernanceUtils.findGovernanceArtifactConfiguration(key, registry) != null) {
            artifactManager = new GenericArtifactManager(registry, key);
        }

        return artifactManager;
    }

    private String buildIssuerName(APIIdentifier appIdentifier) {
        String tenantDomain = getTenantDomainOfCurrentUser();

        String issuerName = null;
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            issuerName = appIdentifier.getApiName() + "-" + appIdentifier.getVersion();
        } else {
            issuerName = appIdentifier.getApiName() + "-" + tenantDomain + "-" + appIdentifier.getVersion();
        }
        return issuerName;
    }

    private void updateSubscription(Connection connection, int subscriptionId, String subscriptionType,
                                    String trustedIDPs, String subscriptionStatus) throws AppManagementException {

        PreparedStatement preparedStmtToUpdateSubscription = null;
        ResultSet resultSet = null;

        try{
            String queryToUpdateSubscription =
                    "UPDATE APM_SUBSCRIPTION " +
                            "SET SUBSCRIPTION_TYPE = ?, TRUSTED_IDP = ? , SUB_STATUS = ?" +
                            "WHERE SUBSCRIPTION_ID = ?";

            preparedStmtToUpdateSubscription = connection.prepareStatement(queryToUpdateSubscription);
            preparedStmtToUpdateSubscription.setString(1, subscriptionType);
            preparedStmtToUpdateSubscription.setString(2, trustedIDPs);
            preparedStmtToUpdateSubscription.setString(3, subscriptionStatus);
            preparedStmtToUpdateSubscription.setInt(4, subscriptionId);

            preparedStmtToUpdateSubscription.executeUpdate();
            connection.commit();
        }catch (SQLException e){
            handleException(String.format("Failed updating subscription with Id : %d", subscriptionId), e);
        }finally {
            APIMgtDBUtil.closeAllConnections(preparedStmtToUpdateSubscription, connection, resultSet);
        }
    }

    private int getTenantIdOfCurrentUser(){
        return CarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    private String getUsernameOfCurrentUser(){
        return CarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    private String getTenantDomainOfCurrentUser() {
        return CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    private Connection getRDBMSConnectionWithoutAutoCommit() throws SQLException {
        return getRDBMSConnection(false);
    }

    private Connection getRDBMSConnectionWithAutoCommit() throws SQLException {
        return getRDBMSConnection(true);
    }

    private Connection getRDBMSConnection(boolean setAutoCommit) throws SQLException {

        Connection connection = APIMgtDBUtil.getConnection();
        connection.setAutoCommit(setAutoCommit);

        return connection;
    }

    private void rollbackTransactions(App app, Registry registry, Connection connection) {

        try {
            if(registry != null){
                registry.rollbackTransaction();
            }

            if(connection != null){
                connection.rollback();
            }
        } catch (RegistryException e) {
            // No need to throw this exception.
            log.error(String.format("Can't rollback registry persist operation for the app '%s:%s'", app.getType(), app.getDisplayName()));
        } catch (SQLException e) {
            // No need to throw this exception.
            log.error(String.format("Can't rollback RDBMS persist operation for the app '%s:%s'", app.getType(), app.getDisplayName()));
        }
    }

    private void handleException(String msg, Exception e) throws AppManagementException {
        log.error(msg, e);
        throw new AppManagementException(msg, e);
    }
}
