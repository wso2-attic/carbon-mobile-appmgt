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

import java.util.Set;

/**
 * APIConsumer responsible for providing helper functionality
 */
public interface APIConsumer extends APIManager {
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

    public boolean isSubscribedToMobileApp(String userId, String appId) throws AppManagementException;


}
