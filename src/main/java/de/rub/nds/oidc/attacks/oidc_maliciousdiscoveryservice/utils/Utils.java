package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 *
 * @author vladi
 */
public class Utils {
    public static final String HTTP_FLOW_PARAM = "authFlow";
    
    public static String readFile(String path, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }
}
