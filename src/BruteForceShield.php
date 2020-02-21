<?php

namespace Ali1\BruteForceShield;

use InvalidArgumentException;

class BruteForceShield {

	/**
	 * @var bool
	 */
	private $validated = false;

	/**
	 * /**
	 *
	 * @param array|null $userHistory
	 * @param array $inputData an array of data, can use $this->request->getData()
	 * @param \Ali1\BruteForceShield\Configuration|null $configuration
	 *
	 * @return array|null
	 */
	public function validate(?array $userHistory, array $inputData, ?Configuration $configuration = null): ?array {
		$configuration = $configuration ?? new Configuration();
		$this->validated = false;

		foreach (array_keys($inputData) as $key) {
			if (is_int($key)) {
				throw new InvalidArgumentException('Keys for data cannot be integers');
				// i.e. $data parameter cannot be array($password). Must be array('password' => $password)
			}
		}

		$newChallenge = new Challenge();

		$isEmptyChallenge = true;
		foreach ($inputData as $keyName => $datum) {
			if (!is_string($datum) && !is_int($datum)) {
				throw new InvalidArgumentException('Non-string data found for Bruteforce input "' . $keyName . '"');
			}

			if (empty($datum)) {
				$datum = '';
			} else {
				$isEmptyChallenge = false;
			}

			$newChallenge->addData(
				$keyName,
				(string)$datum,
				$datum && $this->isKeyEncrypted($keyName, $configuration->unecryptedKeyNames)
			);
		}
		unset($inputData);

		if ($isEmptyChallenge) {
			$this->validated = true;
			return $userHistory; // no need for protection to be applied for empty challenges (challenge not counted towards limit)
		}

		if (empty($userHistory)) {
			$userHistory = ['attempts' => []]; // first login attempt - initialize data for cache
		}
		// remove old attempts based on configured time window
		$userHistory['attempts'] = array_filter($userHistory['attempts'], static function ($attempt) use ($configuration) {
			return $attempt['time'] > (time() - $configuration->timeWindow);
		});

		// analyse history of this user
		$totalAttempts = count($userHistory['attempts']);
		$firstKeyAttempts = 0;

		foreach ($userHistory['attempts'] as $attempt) {
			/** @var \Ali1\BruteForceShield\Challenge $oldChallenge */
			$oldChallenge = unserialize($attempt['challenge'], ['allowed_classes' => [Challenge::class]]);
			// no need to applyProtection and count this challenge if it is identical to a previous challenge attempt
			if ($newChallenge->matchesAnOldChallenge($oldChallenge)) {
				$this->validated = true;
				return $userHistory; // if reached here, that means exactly same attempt previously - do not count
			}

			if ($configuration->stricterLimitKey
				&& $newChallenge->matchesAnOldChallenge($oldChallenge, $configuration->stricterLimitKey)
			) {
				$firstKeyAttempts++;
			}
		}

		if (
			$totalAttempts <= $configuration->totalAttemptsLimit
			&& !($configuration->getStricterLimitKey() && $firstKeyAttempts > $configuration->getStricterLimitAttempts())
		) {
			$this->validated = true;
		}

		// record this new attempt only if attempted validated (otherwise assume will be getting blocked)
		if ($this->isValidated()) {
			$userHistory['attempts'][] = [
				'challenge' => serialize($newChallenge),
				'time' => time(),
			];
		}

		return $userHistory;
	}

	/**
	 * @param string $keyName
	 * @param array $unencryptedKeyNames
	 *
	 * @return bool
	 */
	private function isKeyEncrypted(string $keyName, array $unencryptedKeyNames): bool {
		return !in_array($keyName, $unencryptedKeyNames, true);
	}

	/**
	 * @return bool
	 */
	public function isValidated(): bool {
		return $this->validated;
	}

}
