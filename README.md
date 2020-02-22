# Brute Force Shield

### Features
* Use for IP address-based protection but can be used with other unique identifiers
* Does not count re-attempts with same challenge details (e.g. if a user tries the same username/password combination a few times)
* Designed to use with any data store (file, mysql, cache library) and any framework
* Can block multiple attempts at the same username earlier than the normal limit (to give users a chance to enter the correct username if they have been trying with the wrong one)

### Requirements

* Composer
* PHP 7.2 or higher
* Any data store to persist the User History data between requests 

### Installation

```
composer require ali1/brute-force-shield
```

### Configuration

When applying protection, a Ali1\BruteForceShield\Configuration object can be provided.

```php
    $configuration = new Configuration();
    $configuration->setTimeWindow(600);
    $configuration->setTotalAttemptsLimit(10);
```

|Configuration method|Details|
|---|---|
|`setTimeWindow(int $timeWindow)`|Time in seconds until Brute Force Protection resets (default: 300)|
|`setTotalAttemptsLimit(int $totalAttempts)`|Number of attempts before blocking further challenges (default: 8)|
|`addUnencryptedKey(string $keyName)`|By default, all entered user data is irreversibly hashed when prepared for storage. Use `addUnencryptedKey` for each key for which you want the data to be stored plaintext to aid debugging or security logging (i.e. usernames)|
|`setStricterLimitOnKey(string $keyName, int $limitAttempts)`|This optional method is useful in id/password type scenarios. You can configure the shield to further limit the number of attempts if using the same id/username repeatedly (i.e. use `setStricterLimitOnKey('username', 7)` and `setTotalAttemptsLimit(10)` to allow 7 attempts for a user, and then another 3 if user tries a different username)|

### Usage

As you will need your own architecture to store data and log blocked events, it is recommended to create a method, function, component or middleware to use this library.

For example a reusable method for your application could be:

```php
	/**
	 *
	 * @param string $name a unique string to store the data under (different $name for different uses of Brute
	 *                          force protection within the same application.
	 * @param array $data an array of input data, safe to use $_POST
	 * @param \Ali1\BruteForceShield\Configuration|null $bruteConfig (optional)
	 * @param string $cache (default: 'default')
	 *
	 * @return bool
	 */
	public function validateBruteForce(string $name, array $data, ?Configuration $bruteConfig = null, $cache = 'default'): bool {
		$cacheKey = 'BruteforceData.' . str_replace(':', '.', $_SERVER['REMOTE_ADDR']) . '.' . $name;
		$shield = new BruteForceShield();
		$userDataRaw = Cache::read($cacheKey, $cache);
		$userData = $userDataRaw ? json_decode($userDataRaw, true) : null;
		$userData = $shield->validate($userData, $data, $bruteConfig);
		Cache::write($cacheKey, json_encode($userData), $cache);
		if (!$shield->isValidated()) {
			Log::alert(
				"Bruteforce blocked\nIP: {$this->getController()->getRequest()->getEnv('REMOTE_ADDR')}\n",
				json_encode($userData)
			);

			throw new TooManyAttemptsException();
		}
		return $shield->isValidated();
    }
```

And then when you want to apply Protection to a method, use:

```php

    public function login()
    {
        // prior to actually verifying data
        $bruteConfig = new Configuration();
        $bruteConfig->setTotalAttemptsLimit(10);
        $bruteConfig->setStricterLimitOnKey('username', 7);
        $bruteConfig->addUnencryptedKey('username');

        $this->validateBruteForce(
            'login', // unique name for this BruteForce action
            ['username' => $this->requst->getData('username'), 'password' => $this->requst->getData('password')],
            $bruteConfig
        );

        // login code after 
    }
```