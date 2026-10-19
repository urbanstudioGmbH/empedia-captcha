<?php
declare(strict_types=1);

namespace Empedia\Captcha;

/** Ergebnis von Client::verify(). `unreachable` = der Dienst war nicht erreichbar (Entscheidung über `failOpen`). */
final class VerifyResult
{
    public bool $success;
    /** @var string[] */
    public array $errorCodes;
    public array $raw;
    public bool $unreachable;

    public function __construct(bool $success, array $errorCodes = [], array $raw = [], bool $unreachable = false)
    {
        $this->success = $success;
        $this->errorCodes = array_values(array_map('strval', $errorCodes));
        $this->raw = $raw;
        $this->unreachable = $unreachable;
    }
}
