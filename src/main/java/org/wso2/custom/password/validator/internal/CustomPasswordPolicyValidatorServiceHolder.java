
package org.wso2.custom.password.validator.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.service.RealmService;

public class CustomPasswordPolicyValidatorServiceHolder {
    private static CustomPasswordPolicyValidatorServiceHolder instance = new
            CustomPasswordPolicyValidatorServiceHolder();

    private RealmService realmService;
    private IdentityGovernanceService identityGovernanceService;
    private BundleContext bundleContext;


    private CustomPasswordPolicyValidatorServiceHolder() {
    }

    public static CustomPasswordPolicyValidatorServiceHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

}