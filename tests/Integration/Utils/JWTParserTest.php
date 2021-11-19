<?php declare(strict_types=1);

namespace HbPFAppStoreTests\Integration\Utils;

use DateTimeImmutable;
use Hanaboso\HbPFAppStore\Utils\JWTParser;
use Hanaboso\Utils\File\File;
use HbPFAppStoreTests\DatabaseTestCaseAbstract;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use LogicException;

/**
 * Class JWTParserTest
 *
 * @package HbPFAppStoreTests\Integration\Utils
 */
final class JWTParserTest extends DatabaseTestCaseAbstract
{

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::verifyAndReturn
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testVerifyAndReturn(): void
    {
        self::assertTrue(count(JWTParser::verifyAndReturn()) > 0);
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::verifyAndReturn
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testVerifyAndReturnEnv(): void
    {
        /** @phpstan-ignore-next-line */
        putenv(sprintf('%s=%s', 'ORCHESTY_LICENSE', $this->createJwtToken()));
        self::assertTrue(count(JWTParser::verifyAndReturn()) > 0);
        /** @phpstan-ignore-next-line */
        putenv('ORCHESTY_LICENSE');
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::verifyAndReturn
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testVerifyAndReturnRootPath(): void
    {
        File::putContent('tests/Integration/Utils/data/license/license', $this->createJwtToken());
        self::assertTrue(count(JWTParser::verifyAndReturn('tests/Integration/Utils/data/')) > 0);
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::verifyAndReturn
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testVerifyAndReturnNotValid(): void
    {
        File::putContent('tests/Integration/Utils/data/license/license', $this->createJwtToken('-1 minute'));
        self::expectException(LogicException::class);
        JWTParser::verifyAndReturn('tests/Integration/Utils/data/');
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::getJwtLicense
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testGetJwtLicense(): void
    {
        self::assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsaWNlbnNlIjoie1widmVyc2lvblwiOjEsXCJ1c2Vyc1wiOjEsXCJhcHBsaWNhdGlvbnNcIjozLFwidHlwZVwiOlwiZnJlZVwiLFwiZW1haWxcIjpcInB1YmxpY0BvcmNoZXN0eS5pb1wiLFwibmFtZVwiOlwiRnJlZSBhY2NvdW50XCIsXCJudW1iZXJcIjpcIjFcIn0iLCJpYXQiOjE2MzczMzg5ODQuNzUxMjUyLCJpc3MiOiJIYW5hYm9zbyBzLnIuby4iLCJuYmYiOjE2MzczMzg5ODQuNzUxMjUyLCJleHAiOjE3MDA0MTA5ODQuNzUxMjUyfQ.I9Tp_TMOEgje8SWYPlB9zB4RLaNUIRHaHkywE8sm7PSCey35Z8m4oLYw3MoAZzIyasUBeavxFuvbbNt9X2PPxDvrI6xkaEJSSQyGQThK7IO6nSEszMYRfaUpISmFEgJiVCWbXx-Cb9dwIUinRzjFMuoPvzUAyTSof2rfSe0gC2ry8cr6UpZIBcs4EEkJU4VAtwJglFswW8JLrkphPl7DSeoYYaT7uUW1-3r4KpQEGYO2L9zH0_xqHmfyWInIWp8M49mb-zOroM67SYxgX7HZxMZLOQOVJyclnPe_yqhosBBZ4ym_AGyKhd261b_egQjVqGtpZ3e3VETcMkiGFeSloMzLa4U7ff7EN_3n2fCgK5QSw9P6d9IDINOcFtm6VJ_D4eVhc3IS-vUo8KmzEZFXFtF5U8fUGi_vqFG9obLK1OlGpFsFmacWHT0UvRbtSxTk_TkRdvNsUtEs0_bYP-9WEBwPNioTOHb2sG3cskWyvTxZbYIsRheAECbLtosasggTrSzI6iaRqKBE5nDTBdqh8oKIRnww4HDnvV7qHEQyyD-GpUiX_5VXuKkEj7RDFgvRrhO0qhb3ZlmQ9QTxDBnTlptj7jKBh_zJZH2H_RFTaE1882UdTAwmnuOPBwDT3BXmKfMdYO-rh1NV8WbQ3_0XX_HhZQam4w-fP4CLZszAX6Y',
            JWTParser::getJwtLicense(),
        );
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::getJwtLicense
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testGetJwtLicenseEnv(): void
    {
        $token = $this->createJwtToken();
        /** @phpstan-ignore-next-line */
        putenv(sprintf('%s=%s', 'ORCHESTY_LICENSE', $token));
        self::assertEquals($token, JWTParser::getJwtLicense());
        /** @phpstan-ignore-next-line */
        putenv('ORCHESTY_LICENSE');
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::getJwtLicense
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testGetJwtLicensePath(): void
    {
        $token = $this->createJwtToken('+2 year');
        File::putContent('tests/Integration/Utils/data/license/license', $token);
        self::assertEquals($token, JWTParser::getJwtLicense('tests/Integration/Utils/data/'));
    }

    /**
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::getJwtLicense
     * @covers \Hanaboso\HbPFAppStore\Utils\JWTParser::jwtVerify
     */
    public function testGetJwtLicenseNotValid(): void
    {
        File::putContent('tests/Integration/Utils/data/license/license', $this->createJwtToken('-1 minute'));
        self::expectException(LogicException::class);
        JWTParser::getJwtLicense('tests/Integration/Utils/data/');
    }

    /**
     * @param string $timeModify
     *
     * @return string
     */
    private function createJwtToken(string $timeModify = '+1 minute'): string
    {
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::file(sprintf('%s%s', __DIR__, '/jwt.pem')),
            InMemory::base64Encoded('ZjlqU2VncVl3dmRsSTRDOXN0bFc='),
        );

        $now        = new DateTimeImmutable();
        $validToken = $configuration->builder()
            ->withClaim('license', '{"test":"test"}')
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify($timeModify))
            ->getToken($configuration->signer(), $configuration->signingKey());

        return $validToken->toString();
    }

}
