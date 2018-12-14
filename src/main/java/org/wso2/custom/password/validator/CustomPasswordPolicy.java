package org.wso2.custom.password.validator;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.password.validator.internal.CustomPasswordPolicyValidatorServiceComponent;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Map;

public class CustomPasswordPolicy extends AbstractPasswordPolicyEnforcer {
    private static Log log = LogFactory.getLog(CustomPasswordPolicy.class);

    private String blackListGetQuery;
    private String tenantDomain;
    private String userName;
    private HashSet<String> blackList;
    private String errorMsg;
    private HashSet<String> userNameComponents;

    @Override
    public boolean enforce(Object... objects) {
        if (objects != null) {
            String password = objects[0].toString();

            boolean userNameContains = false;
            boolean blackListWordContains = false;

            for (String userNameComp :
                    userNameComponents) {
                userNameContains = password.toLowerCase().contains(userNameComp.toLowerCase());
                if (userNameContains)
                    break;
            }
            if (!userNameContains) {
                for (String blackListWord :
                        blackList) {
                    blackListWordContains = password.toLowerCase().contains(blackListWord.toLowerCase());
                    if (blackListWordContains)
                        break;
                }
            }

            if (userNameContains) {
                if (StringUtils.isEmpty(errorMsg)) {
                    errorMessage = String.format("Password cannot contain their username, firstname or lastname. :", password);
                } else {
                    errorMessage = String.format("Password cannot contain their username, firstname or lastname. :", errorMsg, password);
                }
                return false;
            } else if (blackListWordContains) {
                if (StringUtils.isEmpty(errorMsg)) {
                    errorMessage = String.format("Password contains black list values. ", password);
                } else {
                    errorMessage = String.format("Password contains black list values.", errorMsg, password);
                }
                return false;
            } else {
                return true;
            }
        }
        return true;
    }


    @Override
    public void init(Map<String, String> map) {

        if (!MapUtils.isEmpty(map)) {
            blackListGetQuery = map.get(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_SQL_QUERY);
            tenantDomain = map.get(CustomPasswordPolicyConstant.TENANT_DOMAIN);
            userName = map.get(CustomPasswordPolicyConstant.USERNAME);
            errorMsg = map.get(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_ERROR_MSG);
        }


        loadPasswordBlackList();
        getNameComponentsOfUser();

    }

    private void loadPasswordBlackList() {

        blackList = new HashSet();

        String query = blackListGetQuery;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); Statement stmt = connection.createStatement()) {
            ResultSet rs;

            rs = stmt.executeQuery(query);
            while (rs.next()) {
                String lastName = rs.getString(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_COLUMN_NAME);
                System.out.println(lastName);
                blackList.add(lastName);

            }
        } catch (SQLException e) {
            log.error("Error while getting blacklist word from the database", e);
        }

    }

    private void getNameComponentsOfUser() {
        userNameComponents = new HashSet<>();
        RealmService realmService = CustomPasswordPolicyValidatorServiceComponent.getRealmService();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            if (realmService != null && tenantId != MultitenantConstants.INVALID_TENANT_ID) {
                UserStoreManager userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(tenantId)
                        .getUserStoreManager();

                userNameComponents.add(userStoreManager.getUserClaimValue(userName, CustomPasswordPolicyConstant.USER_FIRSTNAME_CLAIM_URI, CustomPasswordPolicyConstant.DEFAULT));
                userNameComponents.add(userStoreManager.getUserClaimValue(userName, CustomPasswordPolicyConstant.USER_USENAME_CLAIM_URI, CustomPasswordPolicyConstant.DEFAULT));
                userNameComponents.add(userStoreManager.getUserClaimValue(userName, CustomPasswordPolicyConstant.USER_LASTNAME_CLAIM_URI, CustomPasswordPolicyConstant.DEFAULT));
            }
        } catch (UserStoreException e) {
            log.error("Error while getting claim values from the user store", e);
        }
    }
}