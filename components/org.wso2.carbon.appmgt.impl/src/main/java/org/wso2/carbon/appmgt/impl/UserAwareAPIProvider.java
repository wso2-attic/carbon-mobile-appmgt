/*
 *  Copyright WSO2 Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.appmgt.impl;

import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;

/**
 * User aware APIProvider implementation which ensures that the invoking user has the
 * necessary privileges to execute the operations. Users can use this class as an
 * entry point to accessing the core WebApp provider functionality. In order to ensure
 * proper initialization and cleanup of these objects, the constructors of the class
 * has been hidden. Users should use the APIManagerFactory class to obtain an instance
 * of this class. This implementation also allows anonymous access to some of the
 * available operations. However if the user attempts to execute a privileged operation
 * when the object had been created in the anonymous mode, an exception will be thrown.
 */
public class UserAwareAPIProvider extends APIProviderImpl {

    private String username;

    UserAwareAPIProvider(String username) throws AppManagementException {
        super(username);
        this.username = username;
    }

    @Override
    public String createNewVersion(App app) throws AppManagementException {
        checkCreatePermission();
        return super.createNewVersion(app);
    }

    public void checkDocumentRemovePermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.DOCUMENT_EDIT);
    }

    public void checkDocumentEditPermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.DOCUMENT_EDIT);
    }

    public void checkDocumentAddPermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.DOCUMENT_ADD);
    }

    public void checkCreatePermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.WEB_APP_CREATE);
    }

    public void checkWebappUpdatePermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.WEB_APP_UPDATE);
    }

    public void checkWebappDeletePermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.WEB_APP_DELETE);
    }

    public void checkManageTiersPermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.MANAGE_TIERS);
    }

    public void checkPublishPermission() throws AppManagementException {
        AppManagerUtil.checkPermission(username, AppMConstants.Permissions.WEB_APP_PUBLISH);
    }

    public void checkPublishPermissionTenantMode(String userId) throws AppManagementException {
        AppManagerUtil.checkPermission(userId, AppMConstants.Permissions.WEB_APP_PUBLISH);
    }

    @Override
    public boolean deleteEntitlementPolicyPartial(int policyPartialId, String author) throws
                                                                                      AppManagementException {
        checkWebappDeletePermission();
        return super.deleteEntitlementPolicyPartial(policyPartialId, author);
    }

    @Override
    public int saveEntitlementPolicyPartial(String policyPartialName, String policyPartial, boolean isSharedPartial,
                                            String policyAuthor, String policyPartialDesc)
            throws AppManagementException {
        checkCreatePermission();
        return super.saveEntitlementPolicyPartial(policyPartialName, policyPartial, isSharedPartial, policyAuthor,
                policyPartialDesc);
    }


}
