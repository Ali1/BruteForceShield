<?php

namespace Ali1\BruteForceShield;

use InvalidArgumentException;

class Configuration {

	/**
	 * @var int
	 */
	public $timeWindow = 300;

	/**
	 * @var int
	 */
	public $totalAttemptsLimit = 8;

	/**
	 * @var string|null
	 */
	public $stricterLimitKey = null;

	/**
	 * @var int|null
	 */
	public $stricterLimitAttempts = null;

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
	public $unecryptedKeyNames = [];

	/**
	 * @return int
	 */
	public function getTimeWindow() {
		return $this->timeWindow;
	}

	/**
	 * @param int $timeWindow
	 * @return void
	 */
	public function setTimeWindow(int $timeWindow) {
		if ($timeWindow < 1) {
			throw new InvalidArgumentException('timeWindow must be greater than 0');
		}
		$this->timeWindow = $timeWindow;
	}

	/**
	 * @return int
	 */
	public function getTotalAttemptsLimit() {
		return $this->totalAttemptsLimit;
	}

	/**
	 * @param int $totalAttemptsLimit
	 * @return void
	 */
	public function setTotalAttemptsLimit(int $totalAttemptsLimit): void {
		if ($this->stricterLimitAttempts && $totalAttemptsLimit <= $this->stricterLimitAttempts) {
			throw new InvalidArgumentException(
				'If a stricter limit on a key is set, total totalAttemptsLimit must be greater'
			);
		}
		$this->totalAttemptsLimit = $totalAttemptsLimit;
	}

	/**
	 * @return array
	 */
	public function getUnecryptedKeyNames() {
		return $this->unecryptedKeyNames;
	}

	/**
	 * @param string $unencryptedKeyName
	 * @return void
	 */
	public function addUnencryptedKeyNames(string $unencryptedKeyName) {
		$this->unecryptedKeyNames[] = $unencryptedKeyName;
	}

	/**
	 * @param string $unencryptedKeyName
	 * @return void
	 */
	public function removeUnencryptedKeyNames(string $unencryptedKeyName): void {
		$key = array_search($unencryptedKeyName, $this->unecryptedKeyNames, true);
		if ($key !== false) {
			unset($this->unecryptedKeyNames[$key]);
		}
	}

	/**
	 * @return void
	 */
	public function removeAllUnencryptedKeyNames() {
		$this->unecryptedKeyNames = [];
	}

	/**
	 * @param string $key
	 * @param int $attempts
	 * @return void
	 */
	public function setStricterLimitOnKey(string $key, int $attempts): void {
		if ($attempts >= $this->totalAttemptsLimit) {
			throw new InvalidArgumentException(
				'If a stricter limit is set on a key, the limit must be fewer than totalAttemptsLimit'
			);
		}
		$this->stricterLimitKey = $key;
		$this->stricterLimitAttempts = $attempts;
	}

	/**
	 * @return void
	 */
	public function removeStricterLimit(): void {
		$this->stricterLimitAttempts = null;
		$this->stricterLimitKey = null;
	}

}
