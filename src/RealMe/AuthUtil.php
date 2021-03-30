<?php


namespace camilord\nzrealme\RealMe;

include __DIR__.'/Libraries/xmlseclibs/xmlseclibs.php';

/**
 * Class AuthUtil
 * @package camilord\nzrealme\RealMe
 */
class AuthUtil
{
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    /**
     * Returns deflated, base64 encoded, unsigned AuthnRequest.
     *
     * @param string $authRequest
     * @return string
     */
    public static function encodeAuthRequest(string $authRequest): string
    {
        $deflatedRequest = gzdeflate($authRequest);
        return base64_encode($deflatedRequest);
    }

    /**
     * @param string $samlRequest encoded AuthRequest
     * @param string $relayState - relay url
     * @param string $SPkey - SP Key or Private Key
     * @return string
     * @throws \Exception
     */
    public static function buildRequestSignature(string $samlRequest, string $relayState, string $SPkey): string
    {
        $objKey = new \XMLSecurityKey(\XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $objKey->loadKey($SPkey, false);

        $msg = 'SAMLRequest='.urlencode($samlRequest);
        $msg .= '&RelayState='.urlencode($relayState);
        $msg .= '&SigAlg=' . urlencode(\XMLSecurityKey::RSA_SHA1);
        $signature = $objKey->signData($msg);

        return base64_encode($signature);
    }
}