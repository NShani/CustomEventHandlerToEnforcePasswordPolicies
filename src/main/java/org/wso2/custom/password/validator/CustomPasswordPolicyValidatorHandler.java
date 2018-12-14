package org.wso2.custom.password.validator;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.mgt.policy.PolicyRegistry;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.password.policy.constants.PasswordPolicyConstants;
import org.wso2.carbon.identity.password.policy.internal.IdentityPasswordPolicyServiceDataHolder;
import org.wso2.carbon.identity.password.policy.util.Utils;

import java.util.*;

public class CustomPasswordPolicyValidatorHandler extends AbstractEventHandler implements IdentityConnectorConfig {
    private static final Log log = LogFactory.getLog(CustomPasswordPolicyValidatorHandler.class);

    public CustomPasswordPolicyValidatorHandler() {
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> eventProperties = event.getEventProperties();

        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        Object credentials = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);

        for (Object entry :
                event.getEventProperties().entrySet()) {
            System.out.println(entry.toString());
        }

        Property[] identityProperties;
        try {
            identityProperties = IdentityPasswordPolicyServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving password policy properties.", e);
        }

        boolean passwordPolicyValidation = false;
        String passwordBlackListReadQuery = null;
        String passwordBlackListErrorMsg = null;


        for (Property identityProperty : identityProperties) {
            if (identityProperty == null) {
                continue;
            }
            String propertyName = identityProperty.getName();
            String propertyValue = identityProperty.getValue();

            if (identityProperty == null) {
                continue;
            }
            if (CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE.equals(propertyName)) {
                passwordPolicyValidation = BooleanUtils.toBoolean(propertyValue);
                if (!passwordPolicyValidation) {
                    if (log.isDebugEnabled()) {
                        log.debug("Password Policy validation is disabled");
                    }
                    return;
                }
                continue;
            } else if (CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY.equals(propertyName)) {
                passwordBlackListReadQuery = propertyValue;
                continue;
            } else if (CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG.equals(propertyName)) {
                passwordBlackListErrorMsg = propertyValue;
                continue;
            }
        }

        PolicyRegistry policyRegistry = new PolicyRegistry();

        String pwBlacklistPolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ);

        try {
            if (pwBlacklistPolicyCls != null) {
                CustomPasswordPolicy passwordBlackListPolicy = (CustomPasswordPolicy) Class.
                        forName(pwBlacklistPolicyCls).newInstance();
                HashMap pwBlackListParams = new HashMap<String, String>();
                pwBlackListParams.put(CustomPasswordPolicyConstant.TENANT_DOMAIN, tenantDomain);
                pwBlackListParams.put(CustomPasswordPolicyConstant.USERNAME, userName);
                pwBlackListParams.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_SQL_QUERY, passwordBlackListReadQuery);
                pwBlackListParams.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_ERROR_MSG, passwordBlackListErrorMsg);
                passwordBlackListPolicy.init(pwBlackListParams);
                policyRegistry.addPolicy(passwordBlackListPolicy);
            }

        } catch (Exception e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_LOADING_PASSWORD_POLICY_CLASSES, null, e);
        }

        try {
            policyRegistry.enforcePasswordPolicies(credentials.toString(), userName);
        } catch (PolicyViolationException e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY, e.getMessage(), e);
        }
    }


    @Override
    public String getName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getFriendlyName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getCategory() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap();
        nameMapping.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE, "Enable Password Policy Feature");
        nameMapping.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ, "Password Policy Min Length");
        nameMapping.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG, "Password Policy Error Message");
        nameMapping.put(CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY, "Password Policy Error Message");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap();
        descriptionMapping.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE, "Enable Password Policy Feature");
        descriptionMapping.put((CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ), "Password Policy class");
        descriptionMapping.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG, "Password Policy Error Message");
        descriptionMapping.put(CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY, "Password Policy Error Message");
        return descriptionMapping;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityPasswordPolicyServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ);
        properties.add(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG);
        properties.add(CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY);
        return properties.toArray(new String[properties.size()]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {
        Map<String, String> defaultProperties = new HashMap();
        defaultProperties.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ENABLE));
        defaultProperties.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_CLAZZ));
        defaultProperties.put(CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstant.GET_BLACKLIST_SQL_QUERY));
        defaultProperties.put(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstant.PASSWORD_BLACKLIST_POLICY_ERROR_MSG));
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {
        return null;
    }
}