<?php

namespace Ali1\BruteForceShield\Tests;

use Ali1\BruteForceShield\BruteForceShield;
use Ali1\BruteForceShield\Configuration;
use PHPUnit\Framework\TestCase;

class BruteForceShieldTest extends TestCase {

	/**
	 * @return void
	 */
	public function testUserAuthRecommended(): void {
		$bruteConfig = new Configuration();
		$bruteConfig->setTotalAttemptsLimit(6)
            ->setStricterLimitOnKey('username', 5)
            ->addUnencryptedKey('username');
		$this->commonUserAuthTests($bruteConfig);
	}

	/**
	 * @return void
	 */
	public function testUserAuthFullyUnencrypted(): void {
		$bruteConfig = new Configuration();
		$bruteConfig->setTotalAttemptsLimit(6)
            ->setStricterLimitOnKey('username', 5)
            ->addUnencryptedKey('username')
            ->addUnencryptedKey('password');
		$this->commonUserAuthTests($bruteConfig);
	}

	/**
	 * @return void
	 */
	public function testUserAuthFullyEncrypted(): void {
		$bruteConfig = new Configuration();
		$bruteConfig->setTotalAttemptsLimit(6)
            ->setStricterLimitOnKey('username', 5);
		$this->commonUserAuthTests($bruteConfig);
	}

	/**
	 * @param \Ali1\BruteForceShield\Configuration $bruteConfig
	 * @param array $extraInput
	 *
	 * @return void
	 */
	private function commonUserAuthTests(Configuration $bruteConfig, $extraInput = []): void {
		$inputData = array_merge(['password' => 'start', 'username' => 'admin'], $extraInput);
		$userHistory = null;

		// allow 5 attempts
		$allowsAttempts = true;
		$protector = new BruteForceShield();
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		if (!$protector->isValidated()) {
			$allowsAttempts = false;
		} else {
			for ($i = 1; $i <= 4; $i++) {
				$protector = new BruteForceShield();
				$inputData['password'] = (string)mt_rand();
				$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
				if (!$protector->isValidated()) {
					$allowsAttempts = false;
				}
			}
		}
		$this->assertTrue($allowsAttempts);

		// disallow more than 5 tries
		$protector = new BruteForceShield();
		$inputData['password'] = (string)mt_rand();
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertFalse($protector->isValidated());

		// allow more attempts with different username
		$protector = new BruteForceShield();
		$inputData['username'] = 'admin2';

		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertTrue($protector->isValidated());

		// dont allow any more attempts even new usernames
		$protector = new BruteForceShield();
		$inputData['username'] = 'admin3';
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertFalse($protector->isValidated());

		// allow repeat tries of same challenge
		$protector = new BruteForceShield();
		$inputData['username'] = 'admin';
		$inputData['password'] = 'start'; // used before
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertTrue($protector->isValidated());
	}

	/**
	 * @return void
	 */
	public function testSingleKeyAndTimeWindow(): void {
		$bruteConfig = new Configuration();
		$bruteConfig->setTotalAttemptsLimit(5)
            ->setTimeWindow(7);
		$inputData = ['hash' => 'start'];
		$userHistory = null;

		// allow 5 attempts
		$allowsAttempts = true;
		$protector = new BruteForceShield();
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		if (!$protector->isValidated()) {
			$allowsAttempts = false;
		} else {
			for ($i = 1; $i <= 4; $i++) {
				$protector = new BruteForceShield();
				$inputData['hash'] = (string)mt_rand();
				$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
				if (!$protector->isValidated()) {
					$allowsAttempts = false;
				}
			}
		}
		$this->assertTrue($allowsAttempts);

		// disallow more than 5 tries
		$protector = new BruteForceShield();
		$inputData['hash'] = (string)mt_rand();
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertFalse($protector->isValidated());

		// allow repeat tries of same challenge
		$protector = new BruteForceShield();
		$inputData['hash'] = 'start'; // used before
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertTrue($protector->isValidated());

		// allow after short time windows
		sleep(8);
		$protector = new BruteForceShield();
		$inputData['hash'] = (string)mt_rand();
		$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
		$this->assertTrue($protector->isValidated());
	}

	/**
	 * @return void
	 */
	public function testEmptyChallenge(): void {
		$bruteConfig = new Configuration();
		$bruteConfig->setTotalAttemptsLimit(5)
            ->setTimeWindow(7);
		$userHistory = null;
		$inputData = [];

		// allow unlimited attempts
		$allowsAttempts = true;
		for ($i = 1; $i <= 15; $i++) {
			$protector = new BruteForceShield();
			$userHistory = $protector->validate($userHistory, $inputData, $bruteConfig);
			if (!$protector->isValidated()) {
				$allowsAttempts = false;
			}
		}
		$this->assertTrue($allowsAttempts);
	}

}
