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

package org.wso2.carbon.appmgt.rest.api.publisher.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.FileContent;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfiguration;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.rest.api.util.utils.RestApiUtil;

import java.io.File;
import java.security.SecureRandom;
import java.util.Date;

/**
 * This class contains REST API Publisher related utility operations
 */
public class RestApiPublisherUtils {

    private static final Log log = LogFactory.getLog(RestApiPublisherUtils.class);


    public static String generateBinaryUUID() {
        SecureRandom secRandom = new SecureRandom();
        byte[] result = new byte[8];
        secRandom.nextBytes(result);
        String uuid = String.valueOf(Hex.encodeHex(result));
        return uuid;
    }

    public static String uploadFileIntoStorage(FileContent fileContent) throws AppManagementException {
        AppManagerConfiguration appManagerConfiguration = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();
        String directoryLocation =
                appManagerConfiguration.getFirstProperty(AppMConstants.BINARY_FILE_STORAGE_ABSOLUTE_LOCATION);
        File binaryFile = new File(directoryLocation);
        //Generate UUID for the uploading file
        RestApiUtil.transferFile(fileContent.getContent(), fileContent.getFileName(), binaryFile.getAbsolutePath());
        return directoryLocation + File.separator + fileContent.getFileName();
    }

    public static String getCreatedTimeEpoch() {

        int prefix = AppMConstants.ASSET_CREATED_DATE_LENGTH;
        long createdTimeStamp = new Date().getTime();
        String time = String.valueOf(createdTimeStamp);

        if (time.length() != prefix) {
            for (int i = 0; i < prefix - time.length(); i++) {
                time =  "0"+time;
            }
        }
        return time;
    }
}
