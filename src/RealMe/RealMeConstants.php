<?php


namespace camilord\nzrealme\RealMe;

/**
 * Class RealMeConstants
 * @package camilord\nzrealme\RealMe
 */
class RealMeConstants
{
    /**
     * Current RealMe supported environments.
     */
    const ENV_MTS = 'mts';
    const ENV_ITE = 'ite';
    const ENV_PROD = 'prod';

    /**
     * SAML binding types
     */
    const TYPE_LOGIN = 'login';
    const TYPE_ASSERT = 'assert';

    /**
     * the valid AuthN context values for each supported RealMe environment.
     */
    const AUTHN_LOW_STRENGTH = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength';
    const AUTHN_MOD_STRENTH = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength';
    const AUTHN_MOD_MOBILE_SMS = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength::OTP:Mobile:SMS';
    const AUTHN_MOD_TOKEN_SID = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength::OTP:Token:SID';

    /**
     * Realme SAML2 error status constants
     */
    const ERR_TIMEOUT                = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:status:Timeout';
    const ERR_INTERNAL_ERROR         = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:status:InternalError';

    /**
     * SAML2 Error constants used for business logic and switching error messages
     */
    const ERR_AUTHN_FAILED           = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
    const ERR_UNKNOWN_PRINCIPAL      = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';
    const ERR_NO_AVAILABLE_IDP       = 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP';
    const ERR_NO_PASSIVE             = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';
    const ERR_NO_AUTHN_CONTEXT       = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext';
    const ERR_REQUEST_UNSUPPORTED    = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';
    const ERR_REQUEST_DENIED         = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';
    const ERR_UNSUPPORTED_BINDING    = 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding';

    /**
     * @param string $env
     * @return string[][]
     */
    public static function get_idp_entity_ids(string $env = self::ENV_MTS) {
        return [
            self::ENV_MTS => [
                self::TYPE_LOGIN  => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_MTSLoginService',
                self::TYPE_ASSERT => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_MTSAssertionService'
            ],

            self::ENV_ITE => [
                self::TYPE_LOGIN  => 'https://ite.login.realme.govt.nz/12c36372-4b2d-4865-b1d1-9599b0d37348/B2C_1A_DIA_RealMe_LoginService',
                self::TYPE_ASSERT => 'https://ite.login.realme.govt.nz/12c36372-4b2d-4865-b1d1-9599b0d37348/B2C_1A_DIA_RealMe_AssertionService'
            ],

            self::ENV_PROD => [
                self::TYPE_LOGIN  => 'https://www.logon.realme.govt.nz/saml2',
                self::TYPE_ASSERT => 'https://www.account.realme.govt.nz/saml2/assertion',
            ]
        ];
    }

    /**
     * @param string $env
     * @return string[][]
     */
    public static function get_idp_sso_service_urls(string $env = self::ENV_MTS) {
        return [
            self::ENV_MTS => array(
                self::TYPE_LOGIN  => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_MTSLoginService/samlp/sso/login',
                self::TYPE_ASSERT => 'https://mts.login.realme.govt.nz/4af8e0e0-497b-4f52-805c-00fa09b50c16/B2C_1A_DIA_RealMe_MTSAssertionService/samlp/sso/login'
            ),

            self::ENV_ITE => array(
                self::TYPE_LOGIN  => 'https://ite.login.realme.govt.nz/12c36372-4b2d-4865-b1d1-9599b0d37348/B2C_1A_DIA_RealMe_LoginService/samlp/sso/login',
                self::TYPE_ASSERT => 'https://ite.login.realme.govt.nz/12c36372-4b2d-4865-b1d1-9599b0d37348/B2C_1A_DIA_RealMe_AssertionService/samlp/sso/login'
            ),

            self::ENV_PROD => array(
                self::TYPE_LOGIN  => 'https://www.logon.realme.govt.nz/sso/logon/metaAlias/logon/logonidp',
                self::TYPE_ASSERT => 'https://www.assert.realme.govt.nz/sso/SSORedirect/metaAlias/assertion/realmeidp'
            )
        ];
    }


    /**
     * @param string $env
     * @return string[][]
     */
    public static function get_idp_x509_cert_filenames(string $env = self::ENV_MTS) {
        return [
            self::ENV_MTS => array(
                self::TYPE_LOGIN  => 'mts_login_saml_idp.cer',
                self::TYPE_ASSERT => 'mts_assert_saml_idp.cer'
            ),

            // As of the 2021 Azure re-platforming, ITE certificates are the same - a single cert for both logon and assert
            self::ENV_ITE => array(
                self::TYPE_LOGIN  => 'ite.signing.logon.realme.govt.nz.cer',
                self::TYPE_ASSERT => 'ite.signing.logon.realme.govt.nz.cer'
            ),

            self::ENV_PROD => array(
                self::TYPE_LOGIN  => 'signing.logon.realme.govt.nz.cer',
                self::TYPE_ASSERT => 'signing.account.realme.govt.nz.cer'
            )
        ];
    }

}