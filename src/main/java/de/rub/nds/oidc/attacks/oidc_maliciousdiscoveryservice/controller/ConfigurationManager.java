package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.controller;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.Utils;
import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.web.WebFingerServlet;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.Properties;
import javax.faces.bean.ManagedBean;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import net.minidev.json.JSONUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */

public class ConfigurationManager implements ServletContextListener,Serializable {
    private static final Logger log = LoggerFactory.getLogger(ConfigurationManager.class);
    private static ConfigurationManager cfgManager;
    
    
    private String tokenEndpoint; //Endpoints of the Honest IdP
    private String userInfoEndpoint; //Endpoints of the Honest IdP
    
    private final String WebfingerFile = "webfinger";
    private final String MetadataFile = "openid-configuration";
    
    
    private Database database; //Collecting the intercepted tokens and credentials
    
    //Config Files
    private final String logFile = "database.log";
    private final String configFile = "config.properties";
    
    /**
     * The method will be started by starting the web application
     * Initialization of the configuration files and database
     * 
     * @param sce
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        try {
            log.info("Initialize the ConfigurationManager");
            cfgManager = this;
            database = new Database();
            setProperties();
            setMaliciousEndpointsConfig();
            parseMaliciousEndpointsConfig();
            sce.getServletContext().setAttribute("database", database);
        } catch (Exception ex) {
            throw new RuntimeException("Cannot initialize the cofiguration!", ex);
        }
    }

    /**
     * Allocates the memory if the web application is stopped
     * @param sce
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
         cfgManager = null;
        sce.getServletContext().removeAttribute("database");
    }

    /**
     *
     * @return
     */
    public static ConfigurationManager getCfgManager() {
        return cfgManager;
    }

    /**
     *
     * @param cfgManager
     */
    public static void setCfgManager(ConfigurationManager cfgManager) {
        ConfigurationManager.cfgManager = cfgManager;
    }

    /**
     *
     * @return
     */
    public Database getDatabase() {
        return database;
    }

    /**
     *
     * @param database
     */
    public void setDatabase(Database database) {
        this.database = database;
    }

    /**
     *
     * @return
     */
    public String getLogFile() {
        return logFile;
    }
    
    private void setProperties() throws IOException{
        Properties prop = new Properties();
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(configFile);
        
        if(inputStream != null){
            prop.load(inputStream);
        }
        else{
            throw new FileNotFoundException("property file " + configFile + "notFound");
        }
        tokenEndpoint = prop.getProperty("tokenEndpoint");
        userInfoEndpoint = prop.getProperty("userInfoEndpoint");
    }

    /**
     *
     * @return
     */
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     *
     * @param tokenEndpoint
     */
    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     *
     * @return
     */
    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    /**
     *
     * @param userInfoEndpoint
     */
    public void setUserInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }
    
    public void setMaliciousEndpointsConfig() throws IOException{
        File file = new File(WebFingerServlet.class.getClassLoader().getResource(WebfingerFile).getFile());
        database.setWebfingerAsString(Utils.readFile(file.getPath(), Charset.defaultCharset()));
        
        file = new File(WebFingerServlet.class.getClassLoader().getResource(MetadataFile).getFile());
        database.setOpenidConfigAsString(Utils.readFile(file.getPath(), Charset.defaultCharset()));
    }
    
    public void parseMaliciousEndpointsConfig() throws ParseException{
        String issuer = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("issuer");
        String registrationEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("registration_endpoint");
        String tokenEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("token_endpoint");
        String authEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("authorization_endpoint");
        String revocationEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("revocation_endpoint");
        String userInfoEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("userinfo_endpoint");
        String jswksEndpoint = (String) JSONObjectUtils.parse(database.getOpenidConfigAsString()).get("jwks_uri");
                
        database.setConfigIssuer(issuer);
        database.setConfigRegEndpoint(registrationEndpoint);
        database.setConfigTokenEndpoint(tokenEndpoint);
        database.setConfigAuthEndpoint(authEndpoint);
        database.setConfigRevocationEndpoint(revocationEndpoint);
        database.setConfigUserInfoEndpoint(userInfoEndpoint);
        database.setJwksEndpoint(jswksEndpoint); 
    }
}
