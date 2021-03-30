<?php


namespace camilord\nzrealme\RealMe;

/**
 * Class RealMeConfig
 * @package camilord\nzrealme\RealMe
 */
class RealMeConfig
{
    /**
     * @var array
     */
    private $settings;

    /**
     * @var string
     */
    private $cert_dir;

    /**
     * RealMeConfig constructor.
     */
    public function __construct()
    {
        /*
         * config structure credits to Kian Nguyen the Invoker
         */
        $this->settings = array (
            // If 'strict' is True, then the PHP Toolkit will reject unsigned
            // or unencrypted messages if it expects them signed or encrypted
            // Also will reject the messages if not strictly follow the SAML
            // standard: Destination, NameId, Conditions ... are validated too.
            'strict' => true,

            // Enable debug mode (to print errors)
            'debug' => false,

            // Service Provider Data that we are deploying
            'sp' => array (
                // Identifier of the SP entity  (must be a URI)
                'entityId' => 'http://sample.com/realme/login',
                // Specifies info about where and how the <AuthnResponse> message MUST be
                // returned to the requester, in this case our SP.
                'assertionConsumerService' => array (
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => '/realme/acsendpoint',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ),
                // Specifies info about where and how the <Logout Response> message MUST be
                // returned to the requester, in this case our SP.
                /*'singleLogoutService' => array (
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => $this->getBaseDomain().'/realme/logout',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ),*/
                // Specifies constraints on the name identifier to be used to
                // represent the requested subject.
                // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',

                // Usually x509cert and privateKey of the SP are provided by files placed at
                // the certs folder. But we can also provide them with the following parameters
                'x509cert' => null,
                'privateKey' => null
            ),

            // Identity Provider Data that we want connect with our SP
            'idp' => array (
                // Identifier of the IdP entity  (must be a URI)
                'entityId' => 'https://mts.realme.govt.nz/saml2',
                // SSO endpoint info of the IdP. (Authentication Request protocol)
                'singleSignOnService' => array (
                    // URL Target of the IdP where the SP will send the Authentication Request Message
                    'url' => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_LoginService/Samlp/sso/login',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-POST binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ),
                // SLO endpoint info of the IdP.
                'singleLogoutService' => array (
                    // URL Location of the IdP where the SP will send the SLO Request
                    'url' => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_LoginService/Samlp/sso/login',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ),
                // Public x509 certificate of the IdP
                'x509cert' => null
                /*
                 *  Instead of use the whole x509cert you can use a fingerprint
                 *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it)
                 */
                // 'certFingerprint' => '',
            ),

            'security' => array (

                /** signatures and encryptions offered */

                // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
                // will be encrypted.
                'nameIdEncrypted' => true,

                // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
                // will be signed.              [The Metadata of the SP will offer this info]
                'authnRequestsSigned' => true,

                // Indicates whether the <samlp:logoutRequest> messages sent by this SP
                // will be signed.
                'logoutRequestSigned' => true,

                // Indicates whether the <samlp:logoutResponse> messages sent by this SP
                // will be signed.
                'logoutResponseSigned' => true,

                /* Sign the Metadata
                 False || True (use sp certs) || array (
                                                            keyFileName => 'metadata.key',
                                                            certFileName => 'metadata.crt'
                                                        )
                */

                // Algorithm that the toolkit will use on digest process. Options:
                //    'http://www.w3.org/2000/09/xmldsig#sha1'
                //    'http://www.w3.org/2001/04/xmlenc#sha256'
                //    'http://www.w3.org/2001/04/xmldsig-more#sha384'
                //    'http://www.w3.org/2001/04/xmlenc#sha512'

                /** signatures and encryptions required **/
                'signatureAlgorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',

                // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
                // <samlp:LogoutResponse> elements received by this SP to be signed.
                'wantMessagesSigned' => true,

                // Indicates a requirement for the <saml:Assertion> elements received by
                // this SP to be signed.        [The Metadata of the SP will offer this info]
                'wantAssertionsSigned' => true,

                // Indicates a requirement for the NameID received by
                // this SP to be encrypted.
                'wantNameIdEncrypted' => false,

                // Authentication context.
                // Set to false and no AuthContext will be sent in the AuthNRequest,
                // Set true or don't present thi parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
                // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
                'requestedAuthnContext' =>  true,

                // Indicates if the SP will validate all received xmls.
                // (In order to validate the xml, 'strict' and 'wantXMLValidation' must be true).
                'wantXMLValidation' => true,
            ),

            'contactPerson' => array (
                'technical' => array (
                    'givenName' => 'Dev Team',
                    'emailAddress' => 'dev@sample.com'
                ),
                'support' => array (
                    'givenName' => 'Camilo Lozano III',
                    'emailAddress' => 'me@camilord.com'
                ),
            ),

            // Organization information template, the info in en_US lang is recommended, add more if required
            'organization' => array (
                'en-US' => array(
                    'name' => 'Some Company Name',
                    'displayname' => 'LoremIpsum',
                    'url' => 'https://www.sample.com'
                ),
            ),
        );
    }

    /**
     * @param string $env
     * @param array $overrides
     * @throws \Exception
     */
    public function loadEnvSettings(string $env = 'mts', array $overrides = [])
    {
        if (!isset($overrides['sp']['entityId']) || is_null($overrides['sp']['entityId']) || strlen($overrides['sp']['entityId']) <= 0) {
            throw new \Exception('Error! You did not set your "entityId"! Please read: https://developers.realme.govt.nz/how-realme-works/metadata-requirements/');
        }
        if (!isset($overrides['idp']['privateKey']) || is_null($overrides['idp']['privateKey']) || strlen($overrides['idp']['privateKey']) <= 0) {
            throw new \Exception('Error! You did not set your "privateKey"! Please read: https://developers.realme.govt.nz/how-realme-works/saml-signing-and-encryption/');
        }
        if (
            $env !== RealMeConstants::ENV_MTS &&
            (!isset($overrides['idp']['x509cert']) || is_null($overrides['idp']['x509cert']) || strlen($overrides['idp']['x509cert']) <= 0)
        ) {
            throw new \Exception('Error! For non-MTS environment, you are required to have x509 certificate.');
        }


        $this->settings['idp']['entityId'] = RealMeConstants::get_idp_entity_id($env);
        $this->settings['idp']['singleSignOnService']['url'] = RealMeConstants::get_idp_sso_service_url($env);
        $this->settings['idp']['singleLogoutService']['url'] = RealMeConstants::get_idp_sso_service_url($env);

        // process settings override
        $this->settings = $this->processOverrides($this->settings, $overrides);
    }

    /**
     * @param $settings
     * @param array $overrides
     * @return mixed
     */
    private function processOverrides($settings, array $overrides) {
        foreach($overrides as $cfg_name => $cfg_value) {
            if (is_array($cfg_value)) {
                $settings[$cfg_name] = $this->processOverrides($settings[$cfg_name], $cfg_value);
            } else {
                $settings[$cfg_name] = $cfg_value;
            }
        }

        return $settings;
    }
}