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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.appmgt.api.APIProvider;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.entitlement.EntitlementPolicyPartial;
import org.wso2.carbon.appmgt.rest.api.publisher.XacmlpoliciesApiService;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.PolicyPartialInfoDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.PolicyPartialListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.utils.mappings.XacmlMappingUtil;
import org.wso2.carbon.appmgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.appmgt.rest.api.util.utils.RestApiUtil;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

public class XacmlpoliciesApiServiceImpl extends XacmlpoliciesApiService {

    private static final Log log = LogFactory.getLog(XacmlpoliciesApiServiceImpl.class);


    @Override
    public Response xacmlpoliciesGet(Integer limit, Integer offset, String accept, String ifNoneMatch) {
        //setting default limit and offset values if they are not set
        limit = limit != null ? limit : RestApiConstants.PAGINATION_LIMIT_DEFAULT;
        offset = offset != null ? offset : RestApiConstants.PAGINATION_OFFSET_DEFAULT;

        PolicyPartialListDTO policyPartialListDTO = new PolicyPartialListDTO();
        try {
            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
            //get all available xacml policies list
            List<EntitlementPolicyPartial> policyPartialList = apiProvider.getSharedPolicyPartialsList();

            if (policyPartialList.size() == 0) {
                return RestApiUtil.buildNotFoundException("XACML policies", null).getResponse();
            }

            List<PolicyPartialInfoDTO> allMatchedPolicies = new ArrayList<>();
            for (EntitlementPolicyPartial entitlementPolicyPartial : policyPartialList) {
                PolicyPartialInfoDTO policyPartialInfoDTO = new PolicyPartialInfoDTO();
                policyPartialInfoDTO.setPolicyPartialId(entitlementPolicyPartial.getPolicyPartialId());
                policyPartialInfoDTO.setPolicyPartialName(entitlementPolicyPartial.getPolicyPartialName());
                allMatchedPolicies.add(policyPartialInfoDTO);
            }

            //set list
            policyPartialListDTO = XacmlMappingUtil.fromAPIListToDTO(allMatchedPolicies, offset, limit);
            //set pagination
            XacmlMappingUtil.setPaginationParams(policyPartialListDTO, offset, limit, allMatchedPolicies.size());

            if (policyPartialListDTO.getCount() == 0) {
                return RestApiUtil.buildNotFoundException("XACML policies", null).getResponse();
            }
        } catch (AppManagementException e) {
            String errorMessage = "Error while retrieving XACML policy details";
            RestApiUtil.handleInternalServerError(errorMessage, e, log);
        }
        return Response.ok().entity(policyPartialListDTO).build();
    }
}
