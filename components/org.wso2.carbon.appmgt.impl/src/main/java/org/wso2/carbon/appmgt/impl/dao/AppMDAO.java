/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.appmgt.impl.dao;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIKey;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.dto.TierPermissionDTO;
import org.wso2.carbon.appmgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data Access Layer for App Management
 */
public class AppMDAO {

    private static final Log log = LogFactory.getLog(AppMDAO.class);

    private static final String ENABLE_JWT_GENERATION =
            "AppConsumerAuthConfiguration.EnableTokenGeneration";
    private static final String ENABLE_JWT_CACHE = "APIKeyManager.EnableJWTCache";

    private static final String GATEWAY_URL = "APIGateway.Environments.Environment.GatewayEndpoint";

    // Primary/Secondary Login configuration
    private static final String USERID_LOGIN = "UserIdLogin";
    private static final String EMAIL_LOGIN = "EmailLogin";
    private static final String PRIMARY_LOGIN = "primary";
    private static final String CLAIM_URI = "ClaimUri";

    private static final String oracleDriverName = "Oracle";
    private static final String mySQLDriverName = "MySQL";
    private static final String msSQLDriverName = "MS SQL";
    private static final String microsoftDriverName = "Microsoft";
    private static final String postgreDriverName = "PostgreSQL";

	public Boolean isAccessTokenExists(String accessToken) throws AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet result = null;

		String accessTokenStoreTable = AppMConstants.ACCESS_TOKEN_STORE_TABLE;
		if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
		    AppManagerUtil.checkUserNameAssertionEnabled()) {
			accessTokenStoreTable = AppManagerUtil.getAccessTokenStoreTableFromAccessToken(accessToken);
		}

        String getTokenSql = "SELECT ACCESS_TOKEN FROM " + accessTokenStoreTable +
                " WHERE ACCESS_TOKEN = ? ";
        Boolean tokenExists = false;
		try {
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken = connection.prepareStatement(getTokenSql);
			String encryptedAccessToken = AppManagerUtil.encryptToken(accessToken);
			getToken.setString(1, encryptedAccessToken);
			ResultSet getTokenRS = getToken.executeQuery();
			while (getTokenRS.next()) {
				tokenExists = true;
			}
		} catch (SQLException e) {
			handleException("Failed to check availability of the access token. ", e);
		} catch (CryptoException e) {
			handleException("Failed to check availability of the access token. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, result);
		}
		return tokenExists;
	}

	public Boolean isAccessTokenRevoked(String accessToken) throws AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet result = null;

		String accessTokenStoreTable = AppMConstants.ACCESS_TOKEN_STORE_TABLE;
		if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
		    AppManagerUtil.checkUserNameAssertionEnabled()) {
			accessTokenStoreTable = AppManagerUtil.getAccessTokenStoreTableFromAccessToken(accessToken);
		}

        String getTokenSql = "SELECT TOKEN_STATE FROM " + accessTokenStoreTable +
                " WHERE ACCESS_TOKEN = ? ";

        Boolean tokenExists = false;
		try {
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken = connection.prepareStatement(getTokenSql);
			String encryptedAccessToken = AppManagerUtil.encryptToken(accessToken);
			getToken.setString(1, encryptedAccessToken);
			ResultSet getTokenRS = getToken.executeQuery();
			while (getTokenRS.next()) {
				if (!getTokenRS.getString("TOKEN_STATE").equals("REVOKED")) {
					tokenExists = true;
				}
			}
		} catch (SQLException e) {
			handleException("Failed to check availability of the access token. ", e);
		} catch (CryptoException e) {
			handleException("Failed to check availability of the access token. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, result);
		}
		return tokenExists;
	}

	public APIKey getAccessTokenData(String accessToken) throws AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet getTokenRS = null;
		APIKey apiKey = new APIKey();

		String accessTokenStoreTable = AppMConstants.ACCESS_TOKEN_STORE_TABLE;
		if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
		    AppManagerUtil.checkUserNameAssertionEnabled()) {
			accessTokenStoreTable = AppManagerUtil.getAccessTokenStoreTableFromAccessToken(accessToken);
		}

        String getTokenSql =
                "SELECT ACCESS_TOKEN, AUTHZ_USER, TOKEN_SCOPE, CONSUMER_KEY, " +
                        "TIME_CREATED, VALIDITY_PERIOD " +
                        "FROM " + accessTokenStoreTable +
                        " WHERE ACCESS_TOKEN = ? AND TOKEN_STATE = 'ACTIVE' ";
        try {
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken = connection.prepareStatement(getTokenSql);
			getToken.setString(1, AppManagerUtil.encryptToken(accessToken));
			getTokenRS = getToken.executeQuery();
			while (getTokenRS.next()) {

                String decryptedAccessToken =
                        AppManagerUtil.decryptToken(getTokenRS.getString("ACCESS_TOKEN")); // todo
                // -
                // check
                // redundant
                // decryption
                apiKey.setAccessToken(decryptedAccessToken);
				apiKey.setAuthUser(getTokenRS.getString("AUTHZ_USER"));
				apiKey.setTokenScope(getTokenRS.getString("TOKEN_SCOPE"));
				apiKey.setCreatedDate(getTokenRS.getTimestamp("TIME_CREATED").toString()
				                                .split("\\.")[0]);
				String consumerKey = getTokenRS.getString("CONSUMER_KEY");
				apiKey.setConsumerKey(AppManagerUtil.decryptToken(consumerKey));
				apiKey.setValidityPeriod(getTokenRS.getLong("VALIDITY_PERIOD"));

			}
		} catch (SQLException e) {
			handleException("Failed to get the access token data. ", e);
		} catch (CryptoException e) {
			handleException("Failed to get the access token data. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, getTokenRS);
		}
		return apiKey;
	}

	public Map<Integer, APIKey> getAccessTokens(String query) throws AppManagementException {
		Map<Integer, APIKey> tokenDataMap = new HashMap<Integer, APIKey>();
		if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
		    AppManagerUtil.checkUserNameAssertionEnabled()) {
			String[] keyStoreTables = AppManagerUtil.getAvailableKeyStoreTables();
            if (keyStoreTables != null) {
                for (String keyStoreTable : keyStoreTables) {
                    Map<Integer, APIKey> tokenDataMapTmp =
                            getAccessTokens(query,
                                            getTokenSql(keyStoreTable));
                    tokenDataMap.putAll(tokenDataMapTmp);
                }
            }
        } else {
			tokenDataMap = getAccessTokens(query, getTokenSql(null));
		}
		return tokenDataMap;
	}

	private Map<Integer, APIKey> getAccessTokens(String query, String getTokenSql)
	                                                                              throws
                                                                                  AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet getTokenRS = null;
		Map<Integer, APIKey> tokenDataMap = new HashMap<Integer, APIKey>();

		try {
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken = connection.prepareStatement(getTokenSql);
			getTokenRS = getToken.executeQuery();
			while (getTokenRS.next()) {
				String accessToken = AppManagerUtil.decryptToken(getTokenRS.getString("ACCESS_TOKEN"));
				String regex = "(?i)[a-zA-Z0-9_.-|]*" + query.trim() + "(?i)[a-zA-Z0-9_.-|]*";
				Pattern pattern;
				Matcher matcher;
				pattern = Pattern.compile(regex);
				matcher = pattern.matcher(accessToken);
				Integer i = 0;
				if (matcher.matches()) {
					APIKey apiKey = new APIKey();
					apiKey.setAccessToken(accessToken);
					apiKey.setAuthUser(getTokenRS.getString("AUTHZ_USER"));
					apiKey.setTokenScope(getTokenRS.getString("TOKEN_SCOPE"));
					apiKey.setCreatedDate(getTokenRS.getTimestamp("TIME_CREATED").toString()
					                                .split("\\.")[0]);
					String consumerKey = getTokenRS.getString("CONSUMER_KEY");
					apiKey.setConsumerKey(AppManagerUtil.decryptToken(consumerKey));
					apiKey.setValidityPeriod(getTokenRS.getLong("VALIDITY_PERIOD"));
					tokenDataMap.put(i, apiKey);
					i++;
				}
			}
		} catch (SQLException e) {
			handleException("Failed to get access token data. ", e);
		} catch (CryptoException e) {
			handleException("Failed to get access token data. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, getTokenRS);

		}
		return tokenDataMap;
	}

	private String getTokenSql(String accessTokenStoreTable) {
		String tokenStoreTable = "IDN_OAUTH2_ACCESS_TOKEN";
		if (accessTokenStoreTable != null) {
			tokenStoreTable = accessTokenStoreTable;
		}

        return "SELECT ACCESS_TOKEN,AUTHZ_USER,TOKEN_SCOPE,CONSUMER_KEY," +
                "TIME_CREATED,VALIDITY_PERIOD FROM " + tokenStoreTable +
                " WHERE TOKEN_STATE='ACTIVE' ";
    }

	public Map<Integer, APIKey> getAccessTokensByUser(String user, String loggedInUser)
	                                                                                   throws
                                                                                       AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet getTokenRS = null;
		Map<Integer, APIKey> tokenDataMap = new HashMap<Integer, APIKey>();

		String accessTokenStoreTable = AppMConstants.ACCESS_TOKEN_STORE_TABLE;
		if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
				AppManagerUtil.checkUserNameAssertionEnabled()) {
			accessTokenStoreTable = AppManagerUtil.getAccessTokenStoreTableFromUserId(user);
		}

        String getTokenSql = "SELECT ACCESS_TOKEN, AUTHZ_USER, TOKEN_SCOPE, CONSUMER_KEY, " +
                "TIME_CREATED, VALIDITY_PERIOD " +
                "FROM " + accessTokenStoreTable +
                " WHERE AUTHZ_USER = ? AND TOKEN_STATE = 'ACTIVE' ";
        try {
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken = connection.prepareStatement(getTokenSql);
			getToken.setString(1, user);
			getTokenRS = getToken.executeQuery();
			Integer i = 0;
			while (getTokenRS.next()) {
				String authorizedUser = getTokenRS.getString("AUTHZ_USER");
				if (AppManagerUtil.isLoggedInUserAuthorizedToRevokeToken(loggedInUser, authorizedUser)) {
					String accessToken = AppManagerUtil.decryptToken(getTokenRS.getString("ACCESS_TOKEN"));
					APIKey apiKey = new APIKey();
					apiKey.setAccessToken(accessToken);
					apiKey.setAuthUser(authorizedUser);
					apiKey.setTokenScope(getTokenRS.getString("TOKEN_SCOPE"));
					apiKey.setCreatedDate(getTokenRS.getTimestamp("TIME_CREATED").toString()
							.split("\\.")[0]);
					String consumerKey = getTokenRS.getString("CONSUMER_KEY");
					apiKey.setConsumerKey(AppManagerUtil.decryptToken(consumerKey));
					apiKey.setValidityPeriod(getTokenRS.getLong("VALIDITY_PERIOD"));
					tokenDataMap.put(i, apiKey);
					i++;
				}
			}
		} catch (SQLException e) {
			handleException("Failed to get access token data. ", e);
		} catch (CryptoException e) {
			handleException("Failed to get access token data. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, getTokenRS);
		}
		return tokenDataMap;
	}

	public Map<Integer, APIKey> getAccessTokensByDate(String date, boolean latest,
	                                                  String loggedInUser)
	                                                                      throws
                                                                          AppManagementException {
		Map<Integer, APIKey> tokenDataMap = new HashMap<Integer, APIKey>();

        if (AppManagerUtil.checkAccessTokenPartitioningEnabled() &&
                AppManagerUtil.checkUserNameAssertionEnabled()) {
            String[] keyStoreTables = AppManagerUtil.getAvailableKeyStoreTables();
            if (keyStoreTables != null) {
                for (String keyStoreTable : keyStoreTables) {
                    Map<Integer, APIKey> tokenDataMapTmp =
                            getAccessTokensByDate(date,
                                                  latest,
                                                  getTokenByDateSqls(keyStoreTable),
                                                  loggedInUser);
                    tokenDataMap.putAll(tokenDataMapTmp);
                }
            }
        } else {
            tokenDataMap =
                    getAccessTokensByDate(date, latest, getTokenByDateSqls(null),
                                          loggedInUser);
        }

		return tokenDataMap;
	}

	public Map<Integer, APIKey> getAccessTokensByDate(String date, boolean latest,
	                                                  String[] querySql, String loggedInUser)
	                                                                                         throws
                                                                                             AppManagementException {
		Connection connection = null;
		PreparedStatement ps = null;
		ResultSet getTokenRS = null;
		Map<Integer, APIKey> tokenDataMap = new HashMap<Integer, APIKey>();

		try {
			SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
			java.util.Date searchDate = fmt.parse(date);
			Date sqlDate = new Date(searchDate.getTime());
			connection = APIMgtDBUtil.getConnection();
			PreparedStatement getToken;
			if (latest) {
				getToken = connection.prepareStatement(querySql[0]);
			} else {
				getToken = connection.prepareStatement(querySql[1]);
			}
			getToken.setDate(1, sqlDate);

			getTokenRS = getToken.executeQuery();
			Integer i = 0;
			while (getTokenRS.next()) {
				String authorizedUser = getTokenRS.getString("AUTHZ_USER");
				if (AppManagerUtil.isLoggedInUserAuthorizedToRevokeToken(loggedInUser, authorizedUser)) {
					String accessToken = AppManagerUtil.decryptToken(getTokenRS.getString("ACCESS_TOKEN"));
					APIKey apiKey = new APIKey();
					apiKey.setAccessToken(accessToken);
					apiKey.setAuthUser(authorizedUser);
					apiKey.setTokenScope(getTokenRS.getString("TOKEN_SCOPE"));
					apiKey.setCreatedDate(getTokenRS.getTimestamp("TIME_CREATED").toString()
					                                .split("\\.")[0]);
					String consumerKey = getTokenRS.getString("CONSUMER_KEY");
					apiKey.setConsumerKey(AppManagerUtil.decryptToken(consumerKey));
					apiKey.setValidityPeriod(getTokenRS.getLong("VALIDITY_PERIOD"));
					tokenDataMap.put(i, apiKey);
					i++;
				}
			}
		} catch (SQLException e) {
			handleException("Failed to get access token data. ", e);
		} catch (ParseException e) {
			handleException("Failed to get access token data. ", e);
		} catch (CryptoException e) {
			handleException("Failed to get access token data. ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, connection, getTokenRS);
		}
		return tokenDataMap;
	}


	public String[] getTokenByDateSqls(String accessTokenStoreTable) {
		String[] querySqlArr = new String[2];
		String tokenStoreTable = AppMConstants.ACCESS_TOKEN_STORE_TABLE;
		if (accessTokenStoreTable != null) {
			tokenStoreTable = accessTokenStoreTable;
		}

        querySqlArr[0] = "SELECT ACCESS_TOKEN, AUTHZ_USER, TOKEN_SCOPE, CONSUMER_KEY, " +
                "TIME_CREATED, VALIDITY_PERIOD " +
                "FROM " + tokenStoreTable +
                " WHERE TOKEN_STATE ='ACTIVE' AND TIME_CREATED >= ? ";

        querySqlArr[1] = "SELECT ACCESS_TOKEN, AUTHZ_USER, TOKEN_SCOPE, CONSUMER_KEY," +
                "TIME_CREATED, VALIDITY_PERIOD " +
                "FROM " + tokenStoreTable +
                " WHERE TOKEN_STATE ='ACTIVE' AND TIME_CREATED <= ? ";

		return querySqlArr;
	}

	public void updateTierPermissions(String tierName, String permissionType, String roles,
	                                  int tenantId) throws AppManagementException {
		Connection conn = null;
		ResultSet rs = null;
		PreparedStatement ps = null;
		ResultSet resultSet = null;
		int tierPermissionId = -1;

		try {
			conn = APIMgtDBUtil.getConnection();
            String getTierPermissionQuery =
                    "SELECT TIER_PERMISSIONS_ID FROM APM_TIER_PERMISSIONS WHERE TIER = ? AND " +
                            "TENANT_ID = ?";

            ps = conn.prepareStatement(getTierPermissionQuery);
			ps.setString(1, tierName);
			ps.setInt(2, tenantId);
			resultSet = ps.executeQuery();
			if (resultSet.next()) {
				tierPermissionId = resultSet.getInt("TIER_PERMISSIONS_ID");
			}
			resultSet.close();
			ps.close();

			if (tierPermissionId == -1) {
                String query =
                        "INSERT INTO APM_TIER_PERMISSIONS (TIER, PERMISSIONS_TYPE, ROLES, " +
                                "TENANT_ID) " +
                                "VALUES(?, ?, ?, ?)";
                ps = conn.prepareStatement(query);
				ps.setString(1, tierName);
				ps.setString(2, permissionType);
				ps.setString(3, roles);
				ps.setInt(4, tenantId);
				ps.execute();
			} else {
                String query =
                        "UPDATE APM_TIER_PERMISSIONS SET TIER = ?, PERMISSIONS_TYPE = ?, ROLES = ? "
                                + "WHERE TIER_PERMISSIONS_ID = ? AND TENANT_ID = ?";
                ps = conn.prepareStatement(query);
				ps.setString(1, tierName);
				ps.setString(2, permissionType);
				ps.setString(3, roles);
				ps.setInt(4, tierPermissionId);
				ps.setInt(5, tenantId);
				ps.executeUpdate();
			}
			conn.commit();

		} catch (SQLException e) {
			handleException("Error in updating tier permissions: " + e.getMessage(), e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, conn, rs);
		}
	}

	public Set<TierPermissionDTO> getTierPermissions(int tenantId) throws AppManagementException {
		Connection conn = null;
		ResultSet rs = null;
		PreparedStatement ps = null;
		ResultSet resultSet = null;

		Set<TierPermissionDTO> tierPermissions = new HashSet<TierPermissionDTO>();

		try {
			conn = APIMgtDBUtil.getConnection();
            String getTierPermissionQuery =
                    "SELECT TIER, PERMISSIONS_TYPE, ROLES FROM APM_TIER_PERMISSIONS " +
                            "WHERE TENANT_ID = ?";
            ps = conn.prepareStatement(getTierPermissionQuery);
			ps.setInt(1, tenantId);
			resultSet = ps.executeQuery();
			while (resultSet.next()) {
				TierPermissionDTO tierPermission = new TierPermissionDTO();
				tierPermission.setTierName(resultSet.getString("TIER"));
				tierPermission.setPermissionType(resultSet.getString("PERMISSIONS_TYPE"));
				String roles = resultSet.getString("ROLES");
				if (roles != null && !roles.equals("")) {
					String roleList[] = roles.split(",");
					tierPermission.setRoles(roleList);
				}
				tierPermissions.add(tierPermission);
			}
			resultSet.close();
			ps.close();
		} catch (SQLException e) {
			handleException("Failed to get Tier permission information ", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, conn, resultSet);
		}
		return tierPermissions;
	}

	public TierPermissionDTO getTierPermission(String tierName, int tenantId)
	                                                                         throws
                                                                             AppManagementException {
		Connection conn = null;
		ResultSet rs = null;
		PreparedStatement ps = null;
		ResultSet resultSet = null;

		TierPermissionDTO tierPermission = null;
		try {
			conn = APIMgtDBUtil.getConnection();
			String getTierPermissionQuery =
                    "SELECT PERMISSIONS_TYPE, ROLES  FROM APM_TIER_PERMISSIONS"
                            + " WHERE TIER = ? AND TENANT_ID = ?";
            ps = conn.prepareStatement(getTierPermissionQuery);
			ps.setString(1, tierName);
			ps.setInt(2, tenantId);
			resultSet = ps.executeQuery();
			while (resultSet.next()) {
				tierPermission = new TierPermissionDTO();
				tierPermission.setTierName(tierName);
				tierPermission.setPermissionType(resultSet.getString("PERMISSIONS_TYPE"));
				String roles = resultSet.getString("ROLES");
				if (roles != null) {
					String roleList[] = roles.split(",");
					tierPermission.setRoles(roleList);
				}
			}
			resultSet.close();
			ps.close();
		} catch (SQLException e) {
			handleException("Failed to get Tier permission information for Tier " + tierName, e);
		} finally {
			APIMgtDBUtil.closeAllConnections(ps, conn, resultSet);
		}
		return tierPermission;
	}

	private boolean isDuplicateConsumer(String consumerKey) throws AppManagementException {
		Connection connection = null;
		PreparedStatement prepStmt = null;
		ResultSet rSet = null;
        String sqlQuery = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = ?";
        boolean isDuplicateConsumer = false;
		try {
			consumerKey = AppManagerUtil.encryptToken(consumerKey);
			connection = APIMgtDBUtil.getConnection();
			prepStmt = connection.prepareStatement(sqlQuery);
			prepStmt.setString(1, consumerKey);

			rSet = prepStmt.executeQuery();
			if (rSet.next()) {
				isDuplicateConsumer = true;
			}
		} catch (SQLException e) {
			handleException("Error when reading the application information from"
					+ " the persistence store.", e);
		} catch (CryptoException e) {
			handleException("Error while encrypting consumer-key", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(prepStmt, connection, rSet);
		}
		return isDuplicateConsumer;
	}

	private static void handleException(String msg, Throwable t) throws AppManagementException {
		log.error(msg, t);
		throw new AppManagementException(msg, t);
	}

    /**
     * Save the entitlement policy partial
     *
     * @param policyPartialName policy partial name
     * @param policyPartial     policy partial content
     * @param isSharedPartial   is policy partial shared
     * @param policyAuthor      author of the policy partial
     * @param tenantId          logged users tenant Id
     * @return policy partial id
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    public int saveEntitlementPolicyPartial(String policyPartialName, String policyPartial, boolean isSharedPartial,
											String policyAuthor,String policyPartialDesc,int tenantId) throws AppManagementException {

		Connection connection = null;
		PreparedStatement statementToInsertRecord = null;

		int policyPartialId = -1;

		try {

			if (log.isDebugEnabled()) {
				log.debug("Saves Entitlement Policy Partial with name : " +
						policyPartialName + " from author : " + policyAuthor);
			}
			connection = APIMgtDBUtil.getConnection();
			String queryToInsertRecord = "INSERT INTO "
					+ "APM_ENTITLEMENT_POLICY_PARTIAL(NAME,CONTENT,SHARED,AUTHOR,DESCRIPTION,TENANT_ID)"
					+ " VALUES (?,?,?,?,?,?)";

			statementToInsertRecord = connection.prepareStatement(queryToInsertRecord, new String[]{"ENTITLEMENT_POLICY_PARTIAL_ID"});
			statementToInsertRecord.setString(1, policyPartialName);
			statementToInsertRecord.setString(2, policyPartial);
			statementToInsertRecord.setBoolean(3, isSharedPartial);
			statementToInsertRecord.setString(4, policyAuthor);
			statementToInsertRecord.setString(5, policyPartialDesc);
            statementToInsertRecord.setInt(6, tenantId);

			statementToInsertRecord.executeUpdate();

			ResultSet rs = statementToInsertRecord.getGeneratedKeys();
			while (rs.next()) {
				policyPartialId = Integer.parseInt(rs.getString(1));
			}
			rs.close();

			// Finally commit transaction.
			connection.commit();

		} catch (SQLException e) {
			if (connection != null) {
				try {
					connection.rollback();
				} catch (SQLException e1) {
					log.error("Failed to rollback the add entitlement policy partial with name : " +
							policyPartialName + " from author : " + policyAuthor, e1);
				}
			}
			handleException("Failed to add entitlement policy partial with name : " + policyPartialName +
					" from author : " + policyAuthor, e);
		} finally {
			APIMgtDBUtil.closeAllConnections(statementToInsertRecord, connection, null);
		}
		return policyPartialId;
	}

    /**
     * Update existing policy partial
     * @param policyPartialId
     * @param policyPartial
     * @param author
     * @param isShared
	 * @param policyPartialDesc
     * @return
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
	public boolean updateEntitlementPolicyPartial(int policyPartialId, String policyPartial
			, String author, boolean isShared, String policyPartialDesc) throws AppManagementException {

        Connection connection = null;
        PreparedStatement prepStmt = null;
        String queryToUpdatePolicyPartial = "UPDATE APM_ENTITLEMENT_POLICY_PARTIAL SET CONTENT=? ,SHARED=? ,DESCRIPTION=?" +
                " WHERE ENTITLEMENT_POLICY_PARTIAL_ID = ? ";

        ResultSet rs = null;
        String partialAuthor = null;
        boolean isSuccess = false;

        try {
			if (log.isDebugEnabled()) {
				log.debug("Updating Entitlement Policy Partial with id : " + policyPartial);
			}

            connection = APIMgtDBUtil.getConnection();
            partialAuthor = this.getPolicyPartialAuthor(policyPartialId,connection);


            if (partialAuthor != null && partialAuthor.equals(author)) {
                prepStmt = connection.prepareStatement(queryToUpdatePolicyPartial);
                prepStmt.setString(1, policyPartial);
                prepStmt.setBoolean(2, isShared);
				prepStmt.setString(3, policyPartialDesc);
				prepStmt.setInt(4, policyPartialId);
                prepStmt.executeUpdate();
                isSuccess = true;
            }
            // Finally commit transaction.
            connection.commit();

		} catch (SQLException e) {
			if (connection != null) {
				try {
					connection.rollback();
				} catch (SQLException e1) {
					log.error("Failed to rollback the update of entitlement policy partial with id : " + policyPartial, e1);
				}
			}
			handleException("Failed to update to entitlement policy partial with id : " + policyPartial, e);
		} finally {
			APIMgtDBUtil.closeAllConnections(prepStmt, connection, null);

		}
		return isSuccess;
	}


   /**
     * This method returns the author of a policy partial
     * @param policyPartialId policy partial id
     * @param connection
     * @return other of policy partial
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    private String getPolicyPartialAuthor(int policyPartialId, Connection connection) throws
                                                                                      AppManagementException {

        PreparedStatement prepStmt = null;
        String author = null;
        ResultSet rs = null;
        String queryToGetPartialAuthor = "SELECT AUTHOR FROM APM_ENTITLEMENT_POLICY_PARTIAL  " +
                "WHERE ENTITLEMENT_POLICY_PARTIAL_ID  = ?";


        try {
            prepStmt = connection.prepareStatement(queryToGetPartialAuthor);
            prepStmt.setInt(1,policyPartialId);

            rs = prepStmt.executeQuery();
            while (rs.next()) {
                author = rs.getString("AUTHOR");
            }

        } catch (SQLException e) {
            handleException("Error while retrieving author of the policy parital with policy id : " +
                    policyPartialId, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, null, rs);
        }
        return author;
    }

	/**
	 * Delete entitlement policy partial
	 *
	 * @param policyPartialId policy partial id
	 * @param author          author of the policy partial
	 * @return true if success else false
	 * @throws org.wso2.carbon.appmgt.api.AppManagementException
	 */
	public boolean deletePolicyPartial(int policyPartialId, String author) throws
                                                                           AppManagementException {

        Connection connection = null;
        PreparedStatement prepStmt = null;
        String queryToDeletePolicyPartial =
                "DELETE FROM APM_ENTITLEMENT_POLICY_PARTIAL  WHERE ENTITLEMENT_POLICY_PARTIAL_ID= ?";
        ResultSet rs = null;
        String partialAuthor = null;
        boolean isSuccess = false;

        try {

			if(log.isDebugEnabled()){
				log.debug("Deleting policy partial with partial id : " + policyPartialId);
			}

            connection = APIMgtDBUtil.getConnection();

            partialAuthor = this.getPolicyPartialAuthor(policyPartialId,connection);

            //Only author of the policy partial can delete
            if (partialAuthor != null && partialAuthor.equals(author)) {
                prepStmt = connection.prepareStatement(queryToDeletePolicyPartial);
                prepStmt.setInt(1, policyPartialId);
                prepStmt.execute();
                isSuccess = true;
            }
			// Finally commit transaction.
			connection.commit();

		} catch (SQLException e) {
			if (connection != null) {
				try {
					connection.rollback();
				} catch (SQLException e1) {
					log.error("Failed to rollback the deletion of entitlement policy partial with id : " +
							policyPartialId, e1);
				}
			}
			handleException("Failed to delete entitlement policy partial with partial id : " + policyPartialId, e);
		} finally {
			APIMgtDBUtil.closeAllConnections(prepStmt, connection, null);
		}
		return isSuccess;
	}

    private String exctractConditionFromPolicyPartialContent(String policyPartialContent){

    	try {
			StAXOMBuilder builder = new StAXOMBuilder(new ByteArrayInputStream(policyPartialContent.getBytes()));
			OMElement conditionNode = (OMElement) builder.getDocumentElement().getChildrenWithLocalName("Condition").next();

			return conditionNode.toString();

		} catch (XMLStreamException e) {
			log.error("Can't extract the 'Condition' node from the 'Rule' node.", e);
			return null;
		}
    }

	private String extractEffectFromPolicyPartialContent(String policyPartialContent) {

		try {
			StAXOMBuilder builder = new StAXOMBuilder(new ByteArrayInputStream(policyPartialContent.getBytes()));
			String effect = builder.getDocumentElement().getAttributeValue(new QName("Effect"));

			return effect;

		} catch (XMLStreamException e) {
			log.error("Can't extract the 'Effect' attribute value from the 'Rule' node.", e);
			return null;
		}

	}

    public static Map<String,String> getRegisteredAPIs(String webAppConsumerKey) throws
                                                                                 AppManagementException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        Map<String,String> registeredAPIs = new HashMap<String,String>();

        String query = "SELECT" + " API_CONSUMER_KEY, API_CONSUMER_SECRET, APP_NAME, API_TOKEN_ENDPOINT " + " FROM"
                       + " APM_API_CONSUMER_APPS " + " WHERE"
                       + " APP_CONSUMER_KEY = ?";

		try {
			connection = APIMgtDBUtil.getConnection();
            prepStmt = connection.prepareStatement(query);
			prepStmt.setString(1, webAppConsumerKey);

			rs = prepStmt.executeQuery();
            String apiConsumerKey;
            String apiConSecret;
            String apiName;
            String tokenEp;
			while (rs.next()) {
				apiConsumerKey = rs.getString("API_CONSUMER_KEY");
                apiConSecret = rs.getString("API_CONSUMER_SECRET");
                apiName = rs.getString("APP_NAME");
                tokenEp = rs.getString("API_TOKEN_ENDPOINT");

                registeredAPIs.put(apiName, apiConsumerKey + "," + apiConSecret + "," + tokenEp );
			}
		} catch (SQLException e) {
			handleException("Error while adding OAuth API configs to the database", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
		}

        return registeredAPIs;
    }

    public static String getSAML2SSOIssuerByAppConsumerKey(String webAppConsumerKey)
            throws AppManagementException {

        Connection con = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;

        String query = "SELECT SAML2_SSO_ISSUER " +
                       "FROM APM_API_CONSUMER_APPS " +
                       "WHERE APP_CONSUMER_KEY=?";

        String saml2SsoIssuer = null;

        try {
            con = APIMgtDBUtil.getConnection();
            prepStmt = con.prepareStatement(query);
            prepStmt.setString(1, webAppConsumerKey);
            rs = prepStmt.executeQuery();

            while(rs.next()) {
                saml2SsoIssuer = rs.getString("SAML2_SSO_ISSUER");
            }
        } catch (SQLException e) {
            handleException("Error while getting SAML2_SSO_ISSUER for webAppConsumerKey = " + webAppConsumerKey, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, con, rs);
        }

        return saml2SsoIssuer;
    }

    public static boolean webAppKeyPairExist(String consumerKey, String consumerSecret) throws
                                                                                        AppManagementException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        Map<String,String> registeredAPIs = new HashMap<String,String>();

        String query = "SELECT" + " CONSUMER_KEY, CONSUMER_SECRET   " + " FROM"
                       + " IDN_OAUTH_CONSUMER_APPS " + " WHERE"
                       + " CONSUMER_KEY = ? "
                       + " AND CONSUMER_SECRET = ?";

		try {
			connection = APIMgtDBUtil.getConnection();
            prepStmt = connection.prepareStatement(query);
			prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);

			rs = prepStmt.executeQuery();
			if (rs.next()) {
				return true;
			}
		} catch (SQLException e) {
			handleException("Error while adding OAuth API configs to the database", e);
		} finally {
			APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
		}

        return false;
    }

    public static List<String> getApplicationKeyPair(String appName, String webappProvider)
            throws AppManagementException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        String consumerKey;
        String consumerSecret;
        List<String> keys = new ArrayList<String>();
        int tenantId;

        String query = "SELECT CONSUMER_KEY,CONSUMER_SECRET " +
                       " FROM IDN_OAUTH_CONSUMER_APPS " +
                       " WHERE APP_NAME = ? AND TENANT_ID = ?";

        try {
            conn = APIMgtDBUtil.getConnection();
            ps = conn.prepareStatement(query);
            tenantId = IdentityTenantUtil.getTenantIdOfUser(webappProvider);
            ps.setString(1, appName);
            ps.setInt(2, tenantId);
            rs = ps.executeQuery();
            if (rs.next()) {
                consumerKey = rs.getString("CONSUMER_KEY");
                consumerSecret = rs.getString("CONSUMER_SECRET");
                keys.add(consumerKey);
                keys.add(consumerSecret);
            }
        } catch (SQLException e) {
            handleException("Error when executing the SQL ", e);
        } catch (IdentityRuntimeException e) {
            handleException("Error while getting tenantId of user", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, conn, rs);
        }

        return keys;
    }

    /**
	 * Save policy groups
	 *
	 * @param policyGroupName    :policy group name
	 * @param throttlingTier     : throttling Tier
	 * @param userRoles          : user roles
	 * @param isAnonymousAllowed : is anonymous access allowed to URL pattern
	 * @param objPartialMappings : Object which contains XACML policy partial details arrays
	 * @param policyGroupDesc    :Policy group Desciption
	 * @return : last saved policy group id
	 * @throws AppManagementException if any an error found while saving data to DB
	 */
    public static Integer savePolicyGroup(String policyGroupName, String throttlingTier,
                                          String userRoles, String isAnonymousAllowed,
                                          Object[] objPartialMappings, String policyGroupDesc)
            throws AppManagementException {
        PreparedStatement ps = null;
        Connection conn = null;
        ResultSet rs = null;
        String query = "INSERT INTO APM_POLICY_GROUP(NAME,THROTTLING_TIER,USER_ROLES,URL_ALLOW_ANONYMOUS,DESCRIPTION) "
                + "VALUES(?,?,?,?,?) ";
        int policyGroupId = -1;
		try {
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);
			ps = conn.prepareStatement(query, new String[]{"POLICY_GRP_ID"});
			ps.setString(1, policyGroupName);
			ps.setString(2, throttlingTier);
			ps.setString(3, userRoles);
			ps.setBoolean(4, Boolean.parseBoolean(isAnonymousAllowed));
			ps.setString(5, policyGroupDesc);
			ps.executeUpdate();
			rs = ps.getGeneratedKeys();
			if (rs.next()) {
				policyGroupId = Integer.parseInt(rs.getString(1));
			}
            // save partials mapped to policy group
            if (objPartialMappings != null) {
                if (objPartialMappings.length > 0) {
                    savePolicyPartialMappings(policyGroupId, objPartialMappings, conn);
                }
            }

			conn.commit();
			if (log.isDebugEnabled()) {
				StringBuilder strDataContext = new StringBuilder();
                strDataContext.append("(policyGroupName:").append(policyGroupName)
                        .append(", throttlingTier:").append(throttlingTier)
                        .append(", userRoles:").append(userRoles)
                        .append(", isAnonymousAllowed:").append(isAnonymousAllowed)
                        .append(", Partial Mappings:").append(objPartialMappings)
                        .append(")");
                log.debug("Record saved successfully." + strDataContext.toString());
			}
		} catch (SQLException e) {
			if (conn != null) {
				try {
					conn.rollback();
				} catch (SQLException e1) {
                    log.error("Failed to rollback while saving the policy group - " + policyGroupId, e);
                }
			}
            StringBuilder strDataContext = new StringBuilder();
            strDataContext.append("(policyGroupName:").append(policyGroupName)
                    .append(", throttlingTier:").append(throttlingTier)
                    .append(", userRoles:").append(userRoles)
                    .append(", isAnonymousAllowed:").append(isAnonymousAllowed)
                    .append(", Partial Mappings:").append(objPartialMappings)
                    .append(")");

            handleException("SQL Error while executing the query to save Policy Group : " + query +
                    " : " + strDataContext.toString(), e);
        } finally {
			APIMgtDBUtil.closeAllConnections(ps, conn, rs);
		}
		return policyGroupId;
	}

	/**
	 * save applications wise policy groups
	 *
	 * @param connection     : SQL connection
	 * @param applicationId  : application id
	 * @param policyGroupIds : policy groups id list
	 * @throws AppManagementException if any an error found while saving data to DB
	 */
	public void saveApplicationPolicyGroupsMappings(Connection connection, int applicationId, Object[] policyGroupIds)
            throws AppManagementException {
        PreparedStatement preparedStatement = null;
        String query = "INSERT INTO APM_POLICY_GROUP_MAPPING(APP_ID, POLICY_GRP_ID) VALUES(?,?)";
        try {
			preparedStatement = connection.prepareStatement(query);

			for (Object policyGroupId : policyGroupIds) {
				preparedStatement.setInt(1, applicationId);
				preparedStatement.setInt(2, Integer.parseInt(policyGroupId.toString()));
				preparedStatement.addBatch();
			}
			preparedStatement.executeBatch();
		} catch (SQLException e) {
            String strDataContext = "(applicationId:" + applicationId + ", policyGroupIds:" + policyGroupIds + ")";
            handleException("SQL Error while executing the query to save Policy Group mappings  : " + query + " : " +
                    strDataContext, e);
        } finally {
			APIMgtDBUtil.closeAllConnections(preparedStatement, null, null);
		}
	}

	/**
	 * Get Policy partial details related to Policy Group
	 * @param policyGroupId Policy Group Id
	 * @param connection sql connection
	 * @return array of policy partial details objects
	 * @throws AppManagementException on error
	 */
	private JSONArray getEntitledPartialListForPolicyGroup(Integer policyGroupId, Connection connection) throws
			AppManagementException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		JSONArray arrPartials = new JSONArray();
		String query = "SELECT POLICY_PARTIAL_ID, EFFECT, POLICY_ID " +
				"FROM APM_POLICY_GRP_PARTIAL_MAPPING WHERE POLICY_GRP_ID = ? ";
		try {
			ps = connection.prepareStatement(query);
			ps.setInt(1, policyGroupId);
			rs = ps.executeQuery();
			while (rs.next()) {
				JSONObject objPartial = new JSONObject();
				objPartial.put("POLICY_PARTIAL_ID", rs.getInt("POLICY_PARTIAL_ID"));
				objPartial.put("EFFECT", rs.getString("EFFECT"));
				objPartial.put("POLICY_ID", rs.getString("POLICY_ID"));
				objPartial.put("POLICY_GRP_ID", policyGroupId);
				arrPartials.add(objPartial);
			}
		} catch (SQLException e) {
            handleException("SQL Error while executing the query to fetch policy group wise entitled partials list  : "
                    + query + " : (Policy Group Id" +
                    policyGroupId + ")", e);
        } finally {
			APIMgtDBUtil.closeAllConnections(ps, null, rs);
		}
		return arrPartials;
	}

	/**
	 * Save XACML policies, policy group wise
	 *
	 * @param policyGroupId Policy Group Id
	 * @param objPartialMappings XACML policy related details object array
	 * @param conn sql connection
	 * @throws AppManagementException if any an error found while saving data to DB
	 */
    private static void savePolicyPartialMappings(int policyGroupId,
                                                  Object[] objPartialMappings, Connection conn)
            throws SQLException {
        String query = "INSERT INTO APM_POLICY_GRP_PARTIAL_MAPPING(POLICY_GRP_ID, POLICY_PARTIAL_ID) "
                + "VALUES(?,?) ";
        PreparedStatement preparedStatement = null;

		try {
			preparedStatement = conn.prepareStatement(query);

			for (int i = 0; i < objPartialMappings.length; i++) {
				preparedStatement.setInt(1, policyGroupId);
				preparedStatement.setInt(2, ((Double)(objPartialMappings[i])).intValue());
				preparedStatement.addBatch();
			}
			preparedStatement.executeBatch();
		} catch (SQLException e) {
            log.error("SQL Error while executing the query to save policy partial mappings: " +
                    query + " : (Policy Group Id:" + policyGroupId + ", Policy Partial Mappings:" +
                    objPartialMappings + ")", e);
            /* In the code im using a single SQL connection passed from the parent function so I'm logging the error here
            and throwing the SQLException so  the connection will be disposed by the parent function. */
            throw e;
		} finally {
			APIMgtDBUtil.closeAllConnections(preparedStatement, null, null);
		}
	}

	/**
	 * Delete XACML policies, policy group wise
	 *
	 * @param policyGroupId Policy Group Id
	 * @param conn sql connection
	 * @throws AppManagementException if any an error found while saving data to DB
	 */
    private static void deletePolicyPartialMappings(Integer policyGroupId, Connection conn)
            throws SQLException {

        String query = " DELETE FROM APM_POLICY_GRP_PARTIAL_MAPPING WHERE POLICY_GRP_ID = ? ";
        PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(query);
			ps.setInt(1, policyGroupId);
			ps.executeUpdate();

		} catch (SQLException e) {
            log.error("SQL Error while executing the query to delete policy partial mappings: "
                    + query + " : (Policy Group Id:" +
                    policyGroupId + ")", e);
            /* In the code im using a single SQL connection passed from the parent function so I'm logging the error here
            and throwing the SQLException so  the connection will be disposed by the parent function. */
            throw e;
        } finally {
			APIMgtDBUtil.closeAllConnections(ps, null, null);
		}
	}

	/**
	 * save java policy and application mapping
	 *
	 * @param connection    : SQL Connection
	 * @param applicationId : Application Id
	 * @param javaPolicyIds : selected Java Policy
	 * @throws AppManagementException
	 */
	public void saveJavaPolicyMappings(Connection connection, int applicationId, Object[] javaPolicyIds)
			throws SQLException {

		PreparedStatement preparedStatement = null;
		String query = " INSERT INTO APM_APP_JAVA_POLICY_MAPPING(APP_ID, JAVA_POLICY_ID) VALUES(?,?) ";

		try {
			preparedStatement = connection.prepareStatement(query);

			for (Object policyId : javaPolicyIds) {
				preparedStatement.setInt(1, applicationId);
				preparedStatement.setInt(2, Integer.parseInt(policyId.toString()));
				preparedStatement.addBatch();
			}
			preparedStatement.executeBatch();

		} catch (SQLException e) {
			StringBuilder builder = new StringBuilder(); //build log description String
			builder.append("SQL Error while executing the query to save Java Policy mappings : ").append(query)
					.append(" : (applicationId:").append(applicationId).append(", Java Policy Ids:")
					.append(javaPolicyIds).append(") : ").append(e.getMessage());
			log.error(builder.toString(), e);
			/*
			In the code im using a single SQL connection passed from the parent function so I'm logging the error here
			and throwing the SQLException so the connection will be disposed by the parent function.
			*/
			throw e;
		} finally {
			APIMgtDBUtil.closeAllConnections(preparedStatement, null, null);
		}
	}

}
