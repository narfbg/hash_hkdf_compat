<?php
/**
 * ISC License (ISC)
 *
 * Copyright (c) 2014, Andrey Andreev <narf@devilix.net>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * hash_hkdf() compat package
 *
 * A userland implementation of hash_hkdf() for PHP versions prior to 7.1.2.
 *
 * @package	hash_hkdf_compat
 * @author	Andrey Andreev <narf@devilix.net>
 * @copyright	Copyright (c) 2017, Andrey Andreev <narf@devilix.net>
 * @license	http://opensource.org/licenses/ISC ISC License (ISC)
 * @link	https://github.com/narfbg/hash_hkdf_compat
 */
if ( ! function_exists('hkdf'))
{
	/**
	 * hash_hkdf()
	 *
	 * An RFC5869-compliant HMAC Key Derivation Function implementation.
	 *
	 * @link	https://secure.php.net/hash_hkdf
	 * @link	https://tools.ietf.org/rfc/rfc5869.txt
	 *
	 * @param	string	$algo   Hashing algorithm
	 * @param	string  $ikm	Input keying material
	 * @param	int	$length	Desired output length
	 * @param	string	$info	Context/application-specific info
	 * @param	string	$salt	Salt
	 * @return	string
	 */
	function hash_hkdf($algo = null, $ikm = null, $length = 0, $info = '', $salt = '')
	{
		// To match PHP's behavior as closely as possible (unusual
		// inputs and error messages included), we'll have to do
		// some weird stuff here ...
		if (func_num_args() < 2)
		{
			trigger_error(
				sprintf("hash_hkdf() expects at least 2 parameters, %d given", func_num_args()),
				E_USER_WARNING
			);
			return null;
		}
		elseif (func_num_args() > 5)
		{
			trigger_error(
				sprintf("hash_hkdf() expects at most 5 parameters, %d given", func_num_args()),
				E_USER_WARNING
			);
			return null;
		}

		foreach (array(1 => 'algo', 2 => 'ikm', 4 => 'info', 5 => 'salt') as $paramNumber => $paramName)
		{
			switch ($paramType = gettype($$paramName))
			{
				case 'string': break;
				case 'integer':
				case 'double':
				case 'NULL':
					$$paramName = (string) $$paramName;
					break;
				case 'boolean':
					// Strangely, every scalar value BUT bool(true)
					// can be safely casted ...
					$$paramName = ($$paramName === true) ? '1' : '';
					break;
				case 'object':
					if (is_callable(array($$paramName, '__toString')))
					{
						$$paramName = (string) $$paramName;
						break;
					}
				default:
					trigger_error(
						sprintf("hash_hkdf() expects parameter %d to be string, %s given", $paramNumber, $paramType),
						E_USER_WARNING
					);
					return null;
			}
		}

		static $sizes;
		if ( ! isset($sizes))
		{
			// Non-cryptographic hash functions are blacklisted,
			// so we might as well flip that to a whitelist and
			// include all the digest sizes here instead of
			// doing strlen(hash($algo, '')) on the fly ...
			//
			// Find the interesection of what's available on
			// PHP 7.1 and whatever version we're using.
			$sizes = array_intersect_key(
				array(
					'md2'         => 16, 'md4'         => 16, 'md5'         => 16,
					'sha1'        => 20,
					'sha224'      => 28, 'sha256'      => 32, 'sha384'      => 48,
					'sha512/224'  => 28, 'sha512/256'  => 32, 'sha512'      => 64,
					'sha3-224'    => 28, 'sha3-256'    => 32, 'sha3-384'    => 48, 'sha3-512'    => 64,
					'ripemd128'   => 16, 'ripemd160'   => 20, 'ripemd256'   => 32, 'ripemd320'   => 40,
					'whirlpool'   => 64,
					'tiger128,3'  => 16, 'tiger160,3'  => 20, 'tiger192,3'  => 24,
					'tiger128,4'  => 16, 'tiger160,4'  => 20, 'tiger192,4'  => 24,
					'snefru'      => 32, 'snefru256'   => 32,
					'gost'        => 32, 'gost-crypto' => 32,
					'haval128,3'  => 16, 'haval160,3'  => 20, 'haval192,3'  => 24, 'haval224,3'  => 28, 'haval256,3'  => 32,
					'haval128,4'  => 16, 'haval160,4'  => 20, 'haval192,4'  => 24, 'haval224,4'  => 28, 'haval256,4'  => 32,
					'haval128,5'  => 16, 'haval160,5'  => 20, 'haval192,5'  => 24, 'haval224,5'  => 28, 'haval256,5'  => 32,
				),
				array_flip(hash_algos())
			);

			// PHP pre-5.4.0's output for Tiger hashes is in little-endian byte order - blacklist
			if ( ! defined('PHP_VERSION_ID') || PHP_VERSION_ID < 50400)
			{
				unset(
					$sizes['tiger128,3'], $sizes['tiger160,3'], $sizes['tiger192,3'],
					$sizes['tiger128,4'], $sizes['tiger160,4'], $sizes['tiger192,4']
				);
			}
		}

		if ( ! isset($sizes[$algo]))
		{
			// Edge case ...
			// PHP does case-insensitive lookups and 'Md5', 'sHa1', etc. are accepted.
			// Still, we want to preserve the original input for the error message.
			if ( ! isset($sizes[strtolower($algo)]))
			{
				if (in_array(strtolower($algo), hash_algos(), true) && strncasecmp($algo, 'tiger1', 6) !== 0)
				{
					trigger_error("hash_hkdf(): Non-cryptographic hashing algorithm: {$algo}", E_USER_WARNING);
					return false;
				}

				trigger_error("hash_hkdf(): Unknown hashing algorithm: {$algo}", E_USER_WARNING);
				return false;
			}

			$algo = strtolower($algo);
		}

		if ( ! isset($ikm[0]))
		{
			trigger_error("hash_hkdf(): Input keying material cannot be empty", E_USER_WARNING);
			return false;
		}

		if ( ! is_int($length))
		{
			// Integer casting rules so bizzare that we can't even cover all of them.
			// We'll try for just the simpler cases ...
			if (is_string($length) && isset($length[0]) && strspn($length, "0123456789", $length[0] === '-' ? 1 : 0))
			{
				$length = (int) $length;
			}
			// For some reason, this next line executes without being marked as covered
			elseif (is_float($length)) // @codeCoverageIgnore
			{
				$length = (int) ($length < 0 ? ceil($length) : floor($length));
			}
			elseif ( ! isset($length) || is_bool($length))
			{
				$length = (int) $length;
			}
			else
			{
				trigger_error(
					sprintf("hash_hkdf() expects parameter 3 to be integer, %s given", gettype($length)),
					E_USER_WARNING
				);
				return null;
			}
		}

		if ($length < 0)
		{
			trigger_error("hash_hkdf(): Length must be greater than or equal to 0: {$length}", E_USER_WARNING);
			return false;
		}
		elseif ($length > (255 * $sizes[$algo]))
		{
			trigger_error(
				sprintf("hash_hkdf(): Length must be less than or equal to %d: %d", 255 * $sizes[$algo], $length),
				E_USER_WARNING
			);
			return false;
		}
		elseif ($length === 0)
		{
			$length = $sizes[$algo];
		}

		isset($salt[0]) || $salt = str_repeat("\x0", $sizes[$algo]);
		$prk = hash_hmac($algo, $ikm, $salt, true);
		$okm = '';
		for ($keyBlock = '', $blockIndex = 1; ! isset($okm[$length - 1]); $blockIndex++)
		{
			$keyBlock = hash_hmac($algo, $keyBlock.$info.chr($blockIndex), $prk, true);
			$okm .= $keyBlock;
		}

		// Byte-safety ...
		return defined('MB_OVERLOAD_STRING')
			? mb_substr($okm, 0, $length, '8bit')
			: substr($okm, 0, $length);
	}
}
