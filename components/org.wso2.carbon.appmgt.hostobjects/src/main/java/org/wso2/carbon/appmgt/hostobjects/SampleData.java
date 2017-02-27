/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.appmgt.hostobjects;

class Services {
    String name;

    public String getName() {
        return name;
    }

    public int getRating() {
        return rating;
    }

    public String getAuthor() {
        return author;
    }

    int rating;
    String author;

    public Services(String n, int r, String a) {
        this.name = n;
        this.rating = r;
        this.author = a;
    }
}

class purchasedServices {
    String path;
    String purchased;
    String description;
    String supportForumURL;
    String version;
    String author;
    String rating;
    String namespace;
    String name;
    String canDelete;
    String thumbURL;

    public String getAuthor() {
        return author;
    }

    public String getName() {
        return name;
    }

    public String getRating() {
        return rating;
    }

    public String getDescription() {
        return description;
    }

    public String getNamespace() {
        return namespace;
    }

    public String getPath() {
        return path;
    }

    public String getVersion() {
        return version;
    }

    public String getThumbURL() {
        return thumbURL;
    }

    public String getSupportForumURL() {
        return supportForumURL;
    }

    public String getPurchased() {
        return purchased;
    }

    public String getCanDelete() {
        return canDelete;
    }


    public purchasedServices(String path, String purchased, String description,
                             String supportForumURL, String version, String author, String rating,
                             String namespace, String name, String canDelete, String thumbURL) {
        this.author = author;
        this.canDelete = canDelete;
        this.description = description;
        this.name = name;
        this.namespace = namespace;
        this.path = path;
        this.purchased = purchased;
        this.rating = rating;
        this.supportForumURL = supportForumURL;
        this.thumbURL = thumbURL;
        this.version = version;

    }


}