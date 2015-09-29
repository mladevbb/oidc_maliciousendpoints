package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.exceptions;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class CodeFlowResolverException extends Exception {

    /**
     * Creates a new instance of <code>CodeFlowResolverException</code> without
     * detail message.
     */
    public CodeFlowResolverException() {
    }

    /**
     * Constructs an instance of <code>CodeFlowResolverException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public CodeFlowResolverException(String msg) {
        super(msg);
    }
}
