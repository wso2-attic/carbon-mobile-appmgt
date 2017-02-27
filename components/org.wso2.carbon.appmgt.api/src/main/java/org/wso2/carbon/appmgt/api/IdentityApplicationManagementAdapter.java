/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.appmgt.api;

import org.wso2.carbon.appmgt.api.model.SSOProvider;

/**
 * Abstraction on WSO2 Identity Server based Application Management remote calls.
 *
 */
public interface IdentityApplicationManagementAdapter {

    /**
     * Creates service provider in IS side.
     * @param provider
     * @param idpName
     * @param authenticationStep
     * @return
     */
    boolean createProvider(SSOProvider provider, String idpName, String authenticationStep);

    /**
     * Returns the Single sign on service provider given the SAML Issuer name.
     * @param issuerName
     * @return
     */
    SSOProvider getProvider(String issuerName);

    /**
     * Returns all the local claim URI in SAML.
     * @return
     */
    String[] getAllLocalClaimUris();

    /**
     * Returns all the Identity providers configured to given Service provider.
     * @param serviceProviderId
     * @return
     */
    String[] getIdentityProvidersInServiceProvider(String serviceProviderId);

}
