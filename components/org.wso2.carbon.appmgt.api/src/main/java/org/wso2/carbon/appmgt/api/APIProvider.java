/*
*  Copyright (c) 2005-2011, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.appmgt.api;

import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.FileContent;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.api.model.OneTimeDownloadLink;
import org.wso2.carbon.appmgt.api.model.Provider;
import org.wso2.carbon.appmgt.api.model.Tier;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * APIProvider responsible for providing helper functionality
 */
public interface APIProvider extends APIManager {

    public Set<Provider> getAllProviders() throws AppManagementException;

    /**
     * get details of provider
     *
     * @param providerName name of the provider
     * @return Provider
     * @throws AppManagementException if failed to get Provider
     */
    public Provider getProvider(String providerName) throws AppManagementException;

    public void addTier(Tier tier) throws AppManagementException;

    public void updateTier(Tier tier) throws AppManagementException;

    public void removeTier(Tier tier) throws AppManagementException;

    /**
     * Adds a new Mobile Application to the Store
     *
     * @param mobileApp Mobile application
     * @throws AppManagementException if failed to add MobileApp
     */
    public String createMobileApp(MobileApp mobileApp) throws AppManagementException;

    /**
     *
     * Creates a new versions using the attributes (inlcuding the new version number) of the given app.
     *
     * @param app
     * @return The UUID of the newly created version.
     * @throws AppManagementException
     */
    public String createNewVersion(App app)throws AppManagementException;

    /**
     * Updates an existing Mobile Application. This method must not be used to change Mobile App status. Implementations
     * should throw an exceptions when such attempts are made. All life cycle state changes
     * should be carried out using the changeAPIStatus method of this interface.
     *
     * @param mobileApp Mobile App
     * @throws AppManagementException if failed to update WebApp
     */
    public void updateMobileApp(MobileApp mobileApp) throws AppManagementException;

    /**
     * Change the lifecycle state of the specified WebApp
     *
     * @param api The WebApp whose status to be updated
     * @param status New status of the WebApp
     * @param userId User performing the WebApp state change
     * @param updateGatewayConfig Whether the changes should be pushed to the WebApp gateway or not
     * @throws AppManagementException on error
     */

    /**
     * Returns details of a Mobile App
     * @param uuid  uuid of the App
     * @return A MobileApp object related ro given identifier or null
     * @throws AppManagementException
     */
    public MobileApp getMobileApp(String uuid) throws AppManagementException;

    /**
     *
     * Searches and returns the apps for the given search terms.
     *
     * @param appType
     * @param searchTerms
     * @return
     * @throws AppManagementException
     */
    public List<App> searchApps(String appType, Map<String, String> searchTerms) throws AppManagementException;

    public void updateTierPermissions(String tierName, String permissionType, String roles) throws
                                                                                            AppManagementException;

    public Set getTierPermissions() throws AppManagementException;

    /**
     * Change the lifecycle status of a given application
     * @param appType application type
     * @param appId application type
     * @param action lifecycle action perform on the application
     * @throws AppManagementException
     */
    public void changeLifeCycleStatus(String appType, String appId, String action) throws AppManagementException;

    /**
     * Get allowed lifecycle actions to perform on a given application
     * @param appType application type
     * @param appId application type
     * @return list of allowed lifecycle actions perform on the app
     */
    public String[] getAllowedLifecycleActions(String appType, String appId) throws AppManagementException;

    /**
     * Add mobile application subscription for a given user
     * @param userId userId
     * @param appId application id
     * @return
     * @throws AppManagementException
     */
    public boolean subscribeMobileApp(String userId, String appId) throws AppManagementException;

    /**
     * Remove mobile application subscription for a given user
     * @param userId username
     * @param appId application id
     * @return
     * @throws AppManagementException
     */
    public boolean unSubscribeMobileApp(String userId, String appId) throws AppManagementException;

    /**
     * Updates the given app.
     *
     * @param app
     * @throws AppManagementException
     */
    void updateApp(App app)throws AppManagementException;

    /**
     * Remove mobile application binary file from storage
     * @param fileName
     * @throws AppManagementException
     */
    public void removeBinaryFromStorage(String fileName) throws AppManagementException;

    /**
     * Generate generated one-time download link URL
     * @param appId mobile application id that the one-time download link generated for
     * @throws AppManagementException
     */
    public String generateOneTimeDownloadLink(String appId) throws AppManagementException;

    /**
     * Retrieve one-time download link details from database
     * @param UUID UUID of the one-time download link
     * @return
     * @throws AppManagementException
     */
    public OneTimeDownloadLink getOneTimeDownloadLinkDetails(String UUID) throws AppManagementException;

    /**
     * Update one-time download link details in database
     * @param oneTimeDownloadLink OneTimeDownloadLink content
     * @throws AppManagementException
     */
    public void updateOneTimeDownloadLinkStatus(OneTimeDownloadLink oneTimeDownloadLink) throws AppManagementException;

    public String uploadImage(FileContent fileContent) throws AppManagementException;

}
