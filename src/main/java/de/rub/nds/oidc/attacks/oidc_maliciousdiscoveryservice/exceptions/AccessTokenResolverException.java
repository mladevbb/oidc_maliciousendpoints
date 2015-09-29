package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class AccessTokenResolverException extends Exception {

    /**
     * Creates a new instance of <code>AccessTokenResolverException</code>
     * without detail message.
     */
    public AccessTokenResolverException() {
    }

    /**
     * Constructs an instance of <code>AccessTokenResolverException</code> with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public AccessTokenResolverException(String msg) {
        super(msg);
    }
}
