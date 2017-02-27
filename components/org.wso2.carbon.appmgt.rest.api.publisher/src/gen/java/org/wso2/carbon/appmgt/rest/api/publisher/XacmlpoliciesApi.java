package org.wso2.carbon.appmgt.rest.api.publisher;

import io.swagger.annotations.ApiParam;
import org.wso2.carbon.appmgt.rest.api.publisher.dto.PolicyPartialListDTO;
import org.wso2.carbon.appmgt.rest.api.publisher.factories.XacmlpoliciesApiServiceFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/xacmlpolicies")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/xacmlpolicies", description = "the xacmlpolicies API")
public class XacmlpoliciesApi  {

   private final XacmlpoliciesApiService delegate = XacmlpoliciesApiServiceFactory.getXacmlpoliciesApi();

    @GET
    @Path("/")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Get all XACML policies", notes = "Get a list of XACML policies.", response = PolicyPartialListDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "OK.\nList of XACML policies is returned."),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request.\nInvalid request or validation error."),
        
        @io.swagger.annotations.ApiResponse(code = 403, message = "Forbidden.\nThe request must be conditional but no condition has been specified."),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found.\nThe resource to be updated does not exist.") })

    public Response xacmlpoliciesGet(@ApiParam(value = "Maximum size of resource array to return.", defaultValue="25") @QueryParam("limit") Integer limit,
    @ApiParam(value = "Starting point within the complete list of items qualified.", defaultValue="0") @QueryParam("offset") Integer offset,
    @ApiParam(value = "Media types acceptable for the response. Default is JSON."  , defaultValue="JSON")@HeaderParam("Accept") String accept,
    @ApiParam(value = "Validator for conditional requests; based on the ETag of the formerly retrieved\nvariant of the resourec."  )@HeaderParam("If-None-Match") String ifNoneMatch)
    {
    return delegate.xacmlpoliciesGet(limit,offset,accept,ifNoneMatch);
    }
}

