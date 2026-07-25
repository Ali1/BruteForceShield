<?php

namespace Ali1\BruteForceShield;

use InvalidArgumentException;

class Configuration {

	/**
	 * @var int
	 */
	private $timeWindow = 300;

	/**
	 * @var int
	 */
	private $totalAttemptsLimit = 8;

	/**
	 * @var string|null
	 */
	private $stricterLimitKey;

	/**
	 * @var int|null
	 */
	private $stricterLimitAttempts;

	/**
	 * @return int|null
	 */
	public function getStricterLimitAttempts(): ?int {
		return $this->stricterLimitAttempts;
	}

	/**
	 * @return string|null
	 */
	public function getStricterLimitKey(): ?string {
		return $this->stricterLimitKey;
	}

	/**
	 * @var array
	 */
	public $unencryptedKeyNames = [];

	/**
	 * @return int
	 */
	public function getTimeWindow(): int {
		return $this->timeWindow;
	}

	/**
	 * @param int $timeWindow
	 * @return $this
	 */
	public function setTimeWindow(int $timeWindow) {
		if ($timeWindow < 1) {
			throw new InvalidArgumentException('timeWindow must be greater than 0');
		}
		$this->timeWindow = $timeWindow;

		return $this;
	}

	/**
	 * @return int
	 */
	public function getTotalAttemptsLimit(): int {
		return $this->totalAttemptsLimit;
	}

	/**
	 * @param int $totalAttemptsLimit
	 * @return $this
	 */
	public function setTotalAttemptsLimit(int $totalAttemptsLimit) {
		if ($this->stricterLimitAttempts && $totalAttemptsLimit <= $this->stricterLimitAttempts) {
			throw new InvalidArgumentException('If a stricter limit on a key is set, total totalAttemptsLimit must be greater');
		}
		$this->totalAttemptsLimit = $totalAttemptsLimit;

		return $this;
	}

	/**
	 * @return array
	 */
	public function getUnencryptedKeyNames(): array {
		return $this->unencryptedKeyNames;
	}

	/**
	 * @param string $unencryptedKeyName
	 *
	 * @return $this
	 */
	public function addUnencryptedKey(string $unencryptedKeyName) {
		$this->unencryptedKeyNames[] = $unencryptedKeyName;

		return $this;
	}

	/**
	 * @param string $unencryptedKeyName
	 *
	 * @return $this
	 */
	public function removeUnencryptedKey(string $unencryptedKeyName) {
		$key = array_search($unencryptedKeyName, $this->unencryptedKeyNames, true);
		if ($key !== false) {
			unset($this->unencryptedKeyNames[$key]);
		}

		return $this;
	}

	/**
	 * @return $this
	 */
	public function removeAllUnencryptedKeys() {
		$this->unencryptedKeyNames = [];

		return $this;
	}

	/**
	 * @param string $key
	 * @param int $attempts
	 * @return $this
	 */
	public function setStricterLimitOnKey(string $key, int $attempts) {
		if ($attempts >= $this->totalAttemptsLimit) {
			throw new InvalidArgumentException('If a stricter limit is set on a key, the limit must be fewer than totalAttemptsLimit');
		}
		$this->stricterLimitKey = $key;
		$this->stricterLimitAttempts = $attempts;

		return $this;
	}

	/**
	 * @return $this
	 */
	public function removeStricterLimit() {
		$this->stricterLimitAttempts = null;
		$this->stricterLimitKey = null;

		return $this;
	}

	/**
	 * @param string $keyName
	 *
	 * @return bool
	 */
	public function isKeyEncrypted(string $keyName): bool {
		return !in_array($keyName, $this->unencryptedKeyNames, true);
	}

}
