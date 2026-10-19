<?php
declare(strict_types=1);

namespace Empedia\Captcha;

/** Ergebnis von Client::check(): verdict = allow | review | block, risk 0–100, reasons = Gründe (Codes). */
final class CheckResult
{
    public string $verdict;
    public int $risk;
    /** @var string[] */
    public array $reasons;
    public bool $unreachable;
    public array $raw;

    public function __construct(string $verdict, int $risk = 0, array $reasons = [], bool $unreachable = false, array $raw = [])
    {
        $this->verdict = $verdict;
        $this->risk = $risk;
        $this->reasons = array_values(array_map('strval', $reasons));
        $this->unreachable = $unreachable;
        $this->raw = $raw;
    }

    public function isBlocked(): bool { return $this->verdict === 'block'; }
    public function needsReview(): bool { return $this->verdict === 'review'; }
}
