
relaystate = /realme/acsendpoint
SAMLRequest = encoded AuthRequest xml data

security parameters
Array
(
    [nameIdEncrypted] => 1
    [authnRequestsSigned] => 1
    [logoutRequestSigned] => 1
    [logoutResponseSigned] => 1
    [signatureAlgorithm] => http://www.w3.org/2000/09/xmldsig#rsa-sha1
    [wantMessagesSigned] => 1
    [wantAssertionsSigned] => 1
    [wantNameIdEncrypted] =>
    [requestedAuthnContext] => 1
    [wantXMLValidation] => 1
    [signMetadata] =>
    [wantAssertionsEncrypted] =>
)

crypparams
Array
(
    [library] => openssl
    [method] => http://www.w3.org/2000/09/xmldsig#rsa-sha1
    [padding] => 1
    [type] => private
)


loadkey = private key certificate

XMLSecurityKey Object
(
    [cryptParams:XMLSecurityKey:private] => Array
        (
            [library] => openssl
            [method] => http://www.w3.org/2000/09/xmldsig#rsa-sha1
            [padding] => 1
            [type] => private
        )

    [type] => 0
    [key] =>
    [passphrase] =>
    [iv] =>
    [name] =>
    [keyChain] =>
    [isEncrypted] =>
    [encryptedCtx] =>
    [guid] =>
    [x509Certificate:XMLSecurityKey:private] =>
    [X509Thumbprint:XMLSecurityKey:private] =>
)
