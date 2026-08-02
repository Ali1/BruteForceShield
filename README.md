# Brute Force Shield (archived)

This storage-agnostic engine is archived and is no longer the implementation used by production CakePHP applications.
It remains available only for existing non-CakePHP users and historical reference.

For CakePHP 5 applications, use
[`ali1/cakephp-bruteforce`](https://github.com/Ali1/cakephp-bruteforce). That package now contains the complete limiter,
CakePHP cache integration, locking, safe logging, proxy-bypass backstop, and current PHP/CakePHP support.

No new security fixes should be added here and then assumed to protect CakePHP consumers; make them in the CakePHP
plugin instead.

## Legacy requirements

- PHP 7.2+
- A caller-supplied persistent store

## Legacy tests

```sh
composer test
```
