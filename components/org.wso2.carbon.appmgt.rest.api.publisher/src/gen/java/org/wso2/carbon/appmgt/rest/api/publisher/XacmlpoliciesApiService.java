package org.wso2.carbon.appmgt.rest.api.publisher;

import javax.ws.rs.core.Response;

public abstract class XacmlpoliciesApiService {
    public abstract Response xacmlpoliciesGet(Integer limit,Integer offset,String accept,String ifNoneMatch);
}

