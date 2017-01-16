#!/usr/bin/env bash

cd $(dirname $BASH_SOURCE)
php -dzend_extension=xdebug.so -dmbstring.func_overload=2 vendor/bin/phpunit --configuration=phpunit.xml --coverage-text tests/
