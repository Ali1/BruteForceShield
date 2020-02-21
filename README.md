# Brute Force Shield

### Features
* IP address-based protection
* Uses the Cache class to store attempts so no database installation necessary
* Logs blocked attempts (uses CakePHP Logs)
* Does not count re-attempts with same challenge details (e.g. if a user tries the same username/password combination a few times)
* Can block multiple attempts at the same username earlier than the normal limit (to give users a chance to enter the correct username if they have been trying with the wrong one)
* Can be applied in AppController::initialize for simpler set up when authentication plugins are used
* Throws catchable exception which can optionally be caught

### Requirements

* Composer

### Installation

```
composer require ali1/brute-force-shield
```
