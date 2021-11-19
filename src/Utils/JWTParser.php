<?php declare(strict_types=1);

namespace Hanaboso\HbPFAppStore\Utils;

use DateTimeZone;
use Hanaboso\Utils\File\File;
use Hanaboso\Utils\String\Json;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use LogicException;

/**
 * Class JWTParser
 *
 * @package Hanaboso\HbPFAppStore\Utils
 */
final class JWTParser
{

    private const ORCHESTY_LICENSE = 'ORCHESTY_LICENSE';
    private const DEFAULT_JWT      = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsaWNlbnNlIjoie1widmVyc2lvblwiOjEsXCJ1c2Vyc1wiOjEsXCJhcHBsaWNhdGlvbnNcIjozLFwidHlwZVwiOlwiZnJlZVwiLFwiZW1haWxcIjpcInB1YmxpY0BvcmNoZXN0eS5pb1wiLFwibmFtZVwiOlwiRnJlZSBhY2NvdW50XCIsXCJudW1iZXJcIjpcIjFcIn0iLCJpYXQiOjE2MzczMzg5ODQuNzUxMjUyLCJpc3MiOiJIYW5hYm9zbyBzLnIuby4iLCJuYmYiOjE2MzczMzg5ODQuNzUxMjUyLCJleHAiOjE3MDA0MTA5ODQuNzUxMjUyfQ.I9Tp_TMOEgje8SWYPlB9zB4RLaNUIRHaHkywE8sm7PSCey35Z8m4oLYw3MoAZzIyasUBeavxFuvbbNt9X2PPxDvrI6xkaEJSSQyGQThK7IO6nSEszMYRfaUpISmFEgJiVCWbXx-Cb9dwIUinRzjFMuoPvzUAyTSof2rfSe0gC2ry8cr6UpZIBcs4EEkJU4VAtwJglFswW8JLrkphPl7DSeoYYaT7uUW1-3r4KpQEGYO2L9zH0_xqHmfyWInIWp8M49mb-zOroM67SYxgX7HZxMZLOQOVJyclnPe_yqhosBBZ4ym_AGyKhd261b_egQjVqGtpZ3e3VETcMkiGFeSloMzLa4U7ff7EN_3n2fCgK5QSw9P6d9IDINOcFtm6VJ_D4eVhc3IS-vUo8KmzEZFXFtF5U8fUGi_vqFG9obLK1OlGpFsFmacWHT0UvRbtSxTk_TkRdvNsUtEs0_bYP-9WEBwPNioTOHb2sG3cskWyvTxZbYIsRheAECbLtosasggTrSzI6iaRqKBE5nDTBdqh8oKIRnww4HDnvV7qHEQyyD-GpUiX_5VXuKkEj7RDFgvRrhO0qhb3ZlmQ9QTxDBnTlptj7jKBh_zJZH2H_RFTaE1882UdTAwmnuOPBwDT3BXmKfMdYO-rh1NV8WbQ3_0XX_HhZQam4w-fP4CLZszAX6Y';

    /**
     * @param string|null $rootPath
     *
     * @return mixed[]
     */
    public static function verifyAndReturn(?string $rootPath = NULL): array
    {
        return Json::decode(self::jwtVerify($rootPath)->claims()->get('license'));
    }

    /**
     * @param string|null $rootPath
     *
     * @return string
     */
    public static function getJwtLicense(?string $rootPath = NULL): string
    {
        return self::jwtVerify($rootPath)->toString();
    }

    /**
     * @param string|null $rootPath
     *
     * @return UnencryptedToken
     */
    private static function jwtVerify(?string $rootPath = NULL): UnencryptedToken
    {
        $jwt           = self::DEFAULT_JWT;
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::file(sprintf('%s%s', __DIR__, '/jwt.pem')),
            InMemory::base64Encoded('ZjlqU2VncVl3dmRsSTRDOXN0bFc='),
        );
        $configuration->setValidationConstraints(
            new StrictValidAt(new SystemClock(new DateTimeZone('UTC'))),
        );

        if (getenv(self::ORCHESTY_LICENSE)) {
            $jwt = getenv(self::ORCHESTY_LICENSE);
        } else if ($rootPath) {
            $jwt = trim(File::getContent(sprintf('%s/license/license', $rootPath)));
        }

        /** @var UnencryptedToken $token */
        $token       = $configuration->parser()->parse($jwt);
        $constraints = $configuration->validationConstraints();
        if (!$configuration->validator()->validate($token, ...$constraints)) {
            throw new LogicException('Jwt is not valid');
        }

        return $token;
    }

}
