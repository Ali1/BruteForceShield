<?php

namespace Ali1\BruteForceShield;

class Challenge {

	/**
	 * @var array Key=>Data store of the challenge (data may be encrypted or unencrypted depending on config)
	 */
	public $data = [];

	/**
	 * @var array Key=>Data store of the challenge fully unencrypted. Will be destroyed before serialize into Cache or Log
	 */
	public $unencryptedData = [];

	/**
	 * @var array a list of keys in that are encrypted
	 */
	public $encryptedKeyNames = [];

	/**
	 * @param string $keyName
	 * @param string $data
	 * @param bool $hashed
	 *
	 * @return void
	 */
	public function addData(string $keyName, string $data, bool $hashed): void {
		$this->unencryptedData[$keyName] = $data;
		$this->data[$keyName] = $hashed ? password_hash($data, PASSWORD_DEFAULT) : $data;
		if ($hashed) {
			$this->encryptedKeyNames[] = $keyName;
		}
	}

	/**
	 * @param \Ali1\BruteForceShield\Challenge $oldChallenge
	 * @param string|null $onlyTestKey
	 *
	 * @return bool
	 */
	public function matchesAnOldChallenge(Challenge $oldChallenge, ?string $onlyTestKey = null): bool {
		if (!$this->data && !$oldChallenge->data) {
			return true;
		}

		if (!$this->data || !$oldChallenge->data) {
			return false;
		}

		if ($onlyTestKey && !isset($this->unencryptedData[$onlyTestKey], $oldChallenge->data[$onlyTestKey])) {
			return false;
		}

		if (!$onlyTestKey && array_keys($this->data) !== array_keys($oldChallenge->data)) { // check all keys match
			return false; // some key doesn't match
		}

		foreach ($this->unencryptedData as $keyName => $datum) {
		    if ($onlyTestKey && $keyName !== $onlyTestKey) {
		        continue;
			}

			if ($oldChallenge->isKeyEncrypted($keyName)) {
				if (!password_verify($datum, $oldChallenge->data[$keyName])) {
					return false;
				}
			} else {
				if ($datum !== $oldChallenge->data[$keyName]) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * @param string $keyName
	 *
	 * @return bool
	 */
	private function isKeyEncrypted(string $keyName): bool {
		return in_array($keyName, $this->encryptedKeyNames, true);
	}

	/**
	 * Return an array contain property names that you want included in object serialization
	 *
	 * @return array
	 */
	public function __sleep() {
		return ['data', 'encryptedKeyNames'];
	}

}
