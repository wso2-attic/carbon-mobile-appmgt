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

import org.wso2.carbon.appmgt.api.model.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * APIConsumer responsible for providing helper functionality
 */
public interface APIConsumer extends APIManager {
    /**
     * @param subscriberId id of the Subscriber
     * @return Subscriber
     * @throws AppManagementException if failed to get Subscriber
     */
    public Subscriber getSubscriber(String subscriberId) throws AppManagementException;

    /**
     * Get average rating of an App by UUID
     *
     * @param uuid
     * @param assetType
     * @return average rating
     * @throws AppManagementException
     */
    public float getAverageRating(String uuid, String assetType) throws AppManagementException;

    /**
     * Returns a set of SubscribedAPI purchased by the given Subscriber
     *
     * @param subscriber Subscriber
     * @return Set<WebApp>
     * @throws AppManagementException if failed to get WebApp for subscriber
     */
    public Set<SubscribedAPI> getSubscribedAPIs(Subscriber subscriber) throws
                                                                       AppManagementException;

    /**
     * Returns a set of SubscribedAPIs filtered by the given application name.
     *
     * @param subscriber Subscriber
     * @return Set<WebApp>
     * @throws AppManagementException if failed to get WebApp for subscriber
     */
    public Set<SubscribedAPI> getSubscribedAPIs(Subscriber subscriber, String applicationName) throws
                                                                                               AppManagementException;

    /**
     * Returns true if a given user has subscribed to the WebApp
     *
     * @param apiIdentifier APIIdentifier
     * @param userId        user id
     * @return true, if giving api identifier is already subscribed
     * @throws AppManagementException if failed to check the subscribed state
     */
    public boolean isSubscribed(APIIdentifier apiIdentifier, String userId) throws
                                                                            AppManagementException;

    /**
     * Get the subscription for given search criteria.
     *
     * @param apiIdentifier APIIdentifier
     * @param applicationId Application Id
     * @return Subscription if there is one, null otherwise.
     * @throws AppManagementException If an error occurred while getting the subscription.
     */
    public Subscription getSubscription(APIIdentifier apiIdentifier, int applicationId, String subscriptionType) throws
                                                                                                                 AppManagementException;

    /**
     * Unsubscribe the specified user from the specified WebApp in the given application
     *
     * @param identifier    APIIdentifier
     * @param userId        id of the user
     * @param applicationId Application Id
     * @throws AppManagementException if failed to add subscription details to database
     */
    public void removeSubscription(APIIdentifier identifier, String userId, int applicationId)
            throws AppManagementException;


    public void removeAPISubscription(APIIdentifier identifier, String userId, String applicationName)
            throws AppManagementException;


    /**
     * Remove a Subscriber
     *
     * @param identifier APIIdentifier
     * @param userId     id of the user
     * @throws AppManagementException if failed to add subscription details to database
     */
    public void removeSubscriber(APIIdentifier identifier, String userId)
            throws AppManagementException;

    /**
     * Adds an application
     *
     * @param application Application
     * @param userId      User Id
     * @throws AppManagementException if failed to add Application
     */
    public String addApplication(Application application, String userId) throws
                                                                         AppManagementException;

    /**
     * Updates the details of the specified user application.
     *
     * @param application Application object containing updated data
     * @throws AppManagementException If an error occurs while updating the application
     */
    public void updateApplication(Application application) throws AppManagementException;

    public Set<SubscribedAPI> getSubscribedIdentifiers(Subscriber subscriber,
                                                       APIIdentifier identifier) throws
                                                                                 AppManagementException;

    public Map<String, Object> searchPaginatedAPIs(String searchTerm, String searchType, String tenantDomain, int start,
                                                   int end) throws
                                                            AppManagementException;

    /**
     * Check whether an application access token is already persist in database.
     *
     * @param accessToken
     * @return
     * @throws AppManagementException
     */
    public boolean isApplicationTokenExists(String accessToken) throws AppManagementException;

    /**
     * Returns a list of Tiers denied for the current user
     *
     * @return Set<String>
     * @throws AppManagementException if failed to get the tiers
     */
    public Set<String> getDeniedTiers() throws AppManagementException;

    /**
     * Check whether given Tier is denied for the user
     *
     * @param tierName
     * @return
     * @throws AppManagementException if failed to get the tiers
     */
    public boolean isTierDeneid(String tierName) throws AppManagementException;

    /**
     * Returns a list of applications for a given subscriber
     *
     * @param subscriber Subscriber
     * @return Applications
     * @throws AppManagementException if failed to applications for given subscriber
     */
    public Application[] getApplications(Subscriber subscriber) throws AppManagementException;

    /**
     * Returns the  accessible web apps(anonymous + subscribed) of given user for given tenant store.
     *
     * @param username        Username
     * @param tenantIdOfUser  Tenant Id Of User
     * @param tenantIdOfStore Tenant Id Of Store
     * @param sortOption      Sort Option
     * @param treatAsSite     Treat As Site (TRUE->site,FALSE->WebApp)
     * @throws AppManagementException
     */
    public List<APIIdentifier> getUserAccessibleApps(String username, int tenantIdOfUser, int tenantIdOfStore,
                                                     WebAppSortOption sortOption, boolean treatAsSite)
            throws AppManagementException;

    /**
     * Returns accessible apps(anonymous + subscribed) of given user based on give search option.
     *
     * @param username        UserName
     * @param tenantIdOfUser  Tenant Id of Logged in user
     * @param tenantIdOfStore Tenant Id of Store(=Tenant Id of App)
     * @param searchOption    Search Option
     * @param treatAsSite     Treat As Site (TRUE->site,FALSE->WebApp)
     * @return List of App Identifiers
     * @throws AppManagementException
     */
    public List<APIIdentifier> searchUserAccessibleApps(String username, int tenantIdOfUser, int tenantIdOfStore,
                                                        boolean treatAsSite, WebAppSearchOption searchOption,
                                                        String searchValue) throws AppManagementException;

    public boolean isSubscribedToMobileApp(String userId, String appId) throws AppManagementException;


}
