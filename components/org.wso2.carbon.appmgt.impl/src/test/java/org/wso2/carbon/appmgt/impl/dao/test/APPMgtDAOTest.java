/*
 * Copyright (c) 2005-2011, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.appmgt.impl.dao.test;

import junit.framework.TestCase;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.AppManagerConfigurationServiceImpl;
import org.wso2.carbon.appmgt.impl.dao.AppMDAO;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

public class APPMgtDAOTest extends TestCase {

	AppMDAO appMDAO;

	@Override
	protected void setUp() throws Exception {
		String dbConfigPath = System.getProperty("APIManagerDBConfigurationPath");
		AppManagerConfiguration config = new AppManagerConfiguration();
		config.load(dbConfigPath);
		ServiceReferenceHolder.getInstance()
		                      .setAPIManagerConfigurationService(new AppManagerConfigurationServiceImpl(
		                                                                                                config));
		APIMgtDBUtil.initialize();
		appMDAO = new AppMDAO();
		IdentityTenantUtil.setRealmService(new TestRealmService());
		String identityConfigPath = System.getProperty("IdentityConfigurationPath");
		IdentityConfigParser.getInstance(identityConfigPath);
	}

}
