/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.iwa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * IWAFederatedAuthenticator authenticates a user from a Kerberos Token (GSS Token) sent by a pre-registered KDC.
 */
public class IWAFederatedAuthenticator implements FederatedApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWAKerberosAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "IWA Kerberos";

    private static final long serialVersionUID = -713445365110141169L;
    private static final Log log = LogFactory.getLog(IWAFederatedAuthenticator.class);

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property spnName = new Property();
        spnName.setName(IWAConstants.SPN_NAME);
        spnName.setDisplayName("Service Principal Name");
        spnName.setRequired(true);
        spnName.setDescription("Kerberos Service Principal Name");
        spnName.setDisplayOrder(1);
        configProperties.add(spnName);

        Property spnPassword = new Property();
        spnPassword.setName(IWAConstants.SPN_PASSWORD);
        spnPassword.setDisplayName("Service Principal Password");
        spnPassword.setRequired(true);
        spnPassword.setDescription("Kerberos Service Principal Password");
        spnPassword.setDisplayOrder(2);
        spnPassword.setConfidential(true);
        configProperties.add(spnPassword);

        Property userStoreDomains = new Property();
        userStoreDomains.setName(IWAConstants.USER_STORE_DOMAINS);
        userStoreDomains.setDisplayName("User Store Domains");
        userStoreDomains.setRequired(false);
        userStoreDomains.setDisplayOrder(3);
        userStoreDomains.setDescription("Comma (,) separated UserStore Domains (Leave this blank if you don't want " +
                "to check user's presence in mounted user stores.)");
        configProperties.add(userStoreDomains);

        return configProperties;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getClaimDialectURI() {
        return null;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return false;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext)
            throws AuthenticationFailedException, LogoutFailedException {
        return null;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }
}
