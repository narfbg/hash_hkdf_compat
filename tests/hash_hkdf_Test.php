<?php
class hash_hkdf_Test extends PHPUnit_Framework_TestCase {

	private static $availableAlgos;

	/**
	 * Checks whether a hash algorithm is available in the environment
	 *
	 * For some reason, even setUpBeforeClass() runs AFTER dataProvider methods ...
	 */
	private function algoIsAvailable($algo)
	{
		if ( ! isset(self::$availableAlgos))
		{
			self::$availableAlgos = array();
			// array_flip(hash_algos()) was more convenient, but
			// we had to blacklist tiger on PHP pre-5.4.0
			foreach (hash_algos() as $algo)
			{
				if (strncasecmp('tiger1', $algo, 6) !== 0)
				{
					self::$availableAlgos[$algo] = $algo;
				}
			}
		}

		return isset(self::$availableAlgos[$algo]);
	}

	/**
	 * Skips test if we're running PHP >= 7.1.2 as it already has this function
	 */
	private function skipTestIfNecessary()
	{
		version_compare(PHP_VERSION, '7.1.2', '>=') && $this->markTestSkipped("PHP versions >= 7.1.2 already have this function and don't need this package");
	}

	/**
	 * Tests matching ext/hash/tests/hash_hkdf_basic.phpt from php-src
	 *
	 * @dataProvider	createBasic
	 */
	public function testBasic($algo, $ikm, $okm)
	{
		$this->skipTestIfNecessary();
		$this->assertSame($okm, bin2hex(hash_hkdf($algo, $ikm)));
	}

	public function createBasic()
	{
		$ikm = 'input key material';
		$map = array(
			'md2'        => '87779851d2377dab25da16fd7aadfdf5',
			'md4'        => '422c6bd8dd2a6baae8abadef618c3ede',
			'md5'        => '98b16391063ecee006a3ca8ee5776b1e',
			'sha1'       => 'a71863230e3782240265126a53e137af6667e988',
			'sha224'     => '51678ceb17e803505187b2cf6451c30fbc572fda165bb69bbd117c7a',
			'sha256'     => 'd8f0bede4b652933c32a92eccf7723f7eeb4701744c81325dc3f0fa9fda24499',
			'sha384'     => 'f600680e677bb417a7a22a4da8b167c0d91823a7a5d56a49aeb1838bb2320c05068d15d6d980824fee542a279d310c3a',
			'sha512'     => 'fb1b86549e941b81821a89ac6ba7c4f93465077b3f2af94352ebf1d041efcd3c5694469c1ae31bb10db4c1d2ab84f07e4518ba33a3eadd4a149425750285c640',
			'ripemd128'  => 'cb6418fc0dc9efaeb7e9654390fa7f14',
			'ripemd160'  => 'ba42dbb34f08e9337ace15295f218754a41d6c39',
			'ripemd256'  => 'f2e96b292935e2395b59833ed89d928ac1197ff62c8031ebc06a3f5bad19513f',
			'ripemd320'  => 'a13a682072525ceb4c4a5fef59096e682096e1096e6e7e238c7bd48a6f6c6a9ba3d7d9fbee6b68c4',
			'whirlpool'  => '497c717e04d896c3d582742c614435b7d0963b39de12dcf532540d39164b3b85214014620dfdff4a089a06b06aff43c39a3b4d9b806913cf6309de58ff1151f5',
			'tiger128,3' => 'e13c2e7262892c6bd8dfc24121e7cb34',
			'tiger160,3' => '48cc5a9f5e5d7029eb0544662222c0ba13822b7b',
			'tiger192,3' => '5a665d23b6cbb405668160e58b01aebef74eba979f4bc70b',
			'tiger128,4' => '8acf517ecf58cccbd65c1186d71e4116',
			'tiger160,4' => 'cc0e33ee26700a2eb9a994bbb0e6cef29b429441',
			'tiger192,4' => '97fa02d42331321fdc05c7f8dbc756d751ca36ce1aee69b0',
			'haval128,3' => '2accab8029d42fb15fdbe9d3e2a470ca',
			'haval160,3' => '496fd29e7fc8351d2971b96a3733a7b3de000064',
			'haval192,3' => '238a731801439b1f195e1a1568ce75251e1dd719d904a8a2',
			'haval224,3' => 'd863e596ff6b2bdba1ed7b313df1c3d177176312e81b47e9290f7566',
			'haval256,3' => '96f555fe41255c34fe57b275f1ae40bbb8f07c6a2a6d68c849748fbb393ff443',
			'haval128,4' => '9822af229cc59527a72e231a690fad3b',
			'haval160,4' => '1bbbc4d632daaf94d5ba167efaa70af5b753effe',
			'haval192,4' => 'dd12a8f8919cbf5632497f0918b30236371dd1b55f71e824',
			'haval224,4' => '8af449fb4eb627eb8887507c1279a116ac4325b5806dd22e2f2af410',
			'haval256,4' => 'bd74a6d5fa1ec23a92ce1fd76c36bc8be36f5eddbea821545a91810e1f8d6fc5',
			'haval128,5' => '84564f3450a6ccf6041162207dc8acba',
			'haval160,5' => 'b55cd1b3c514457b9e61c51ad22f302f6ec7cca1',
			'haval192,5' => 'd1db7a8e69b327455d530d1ac60f774023b8b4bdd6bbbf92',
			'haval224,5' => 'c5a2576511f1143c6e29f63d82d6e0be8f67d0bea448e27238be5000',
			'haval256,5' => '9dbab73d13f1fd3a1b41398fe90ba1f298329681d861b023373c33f1051bd4d3',
			'snefru'     => '798eac954e5ece38e9acb63b50c1c2ecb799d34356358cec5a80eeeea91c8de9',
			'snefru256'  => '798eac954e5ece38e9acb63b50c1c2ecb799d34356358cec5a80eeeea91c8de9',
			'gost'       => '64edd584b87a2dfdd1f2b44ed2db8bd27af8386aafe751c2aebaed32dfa3852e'
		);

		foreach ($map as $algo => $okm)
		{
			if ( ! $this->algoIsAvailable($algo))
			{
				unset($map[$algo]);
				continue;
			}

			$map[$algo] = array($algo, $ikm, $okm);
		}

		return $map;
	}

	/**
	 * Tests the official vectors from IETF RFC 5869 (https://tools.ietf.org/html/rfc5869)
	 *
	 * @dataProvider	createRFC5869
	 */
	public function testRFC5869($params, $okm)
	{
		$this->skipTestIfNecessary();
		$this->assertSame($okm, bin2hex(call_user_func_array('hash_hkdf', $params)));
	}

	public function createRFC5869()
	{
		return array(
			'Test case 1 (SHA-256)' => array(
				array(
					'sha256',
					"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
					42,
					"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
					"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
				),
				'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
			),
			'Test case 2 (SHA-256 with longer inputs/outputs)' => array(
				array(
					'sha256',
					"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
					82,
					"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
					"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
				),
				'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'
			),
			'Test case 3 (SHA-256 with zero-length salt, info)' => array(
				array(
					'sha256',
					"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
					42,
					'',
					''
				),
				'8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
			),
			'Test case 4 (SHA-1)' => array(
				array(
					'sha1',
					"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
					42,
					"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
					"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
				),
				'085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896'
			),
			'Test case 5 (SHA-1 with longer inputs/outputs)' => array(
				array(
					'sha1',
					"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
					82,
					"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
					"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
				),
				'0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4'
			),
			'Test case 6 (SHA-1 with zero-length salt, info)' => array(
				array(
					'sha1',
					"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
					42,
					'',
					''
				),
				'0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918'
			),
			'Test case 7 (SHA-1 with zero-length info, salt not provided)' => array(
				array(
					'sha1',
					"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
					42,
					''
				),
				'2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48'
			)
		);
	}

	/**
	 * @dataProvider	createErrors
	 */
	public function testErrors($params, $outputs)
	{
		$this->skipTestIfNecessary();
		$this->assertSame($outputs['returnValue'], @call_user_func_array('hash_hkdf', $params));
		$this->setExpectedException('PHPUnit_Framework_Error_Warning', $outputs['errorMessage']);
		call_user_func_array('hash_hkdf', $params);
	}

	public function createErrors()
	{
		$ikm  = 'input key material';
		$data = array(
			'0 params' => array(
				array(),
				array('returnValue' => null,  'errorMessage' => 'hash_hkdf() expects at least 2 parameters, 0 given')
			),
			'1 param' => array(
				array('sha1'),
				array('returnValue' => null,  'errorMessage' => 'hash_hkdf() expects at least 2 parameters, 1 given')
			),
			'6 params' => array(
				array('sha1', $ikm, 20, '', '', 'extra parameter'),
				array('returnValue' => null,  'errorMessage' => 'hash_hkdf() expects at most 5 parameters, 6 given')
			),
			'Unknown algo' => array(
				array('foo', $ikm),
				array('returnValue' => false, 'errorMessage' => 'hash_hkdf(): Unknown hashing algorithm: foo')
			),
			'Empty IKM' => array(
				array('sha1', ''),
				array('returnValue' => false, 'errorMessage' => 'hash_hkdf(): Input keying material cannot be empty')
			),
			'Negative length' => array(
				array('sha1', $ikm, -1),
				array('returnValue' => false, 'errorMessage' => 'hash_hkdf(): Length must be greater than or equal to 0: -1')
			),
			'Excessive length' => array(
				array('sha1', $ikm, 20 * 255 +1),
				array('returnValue' => false, 'errorMessage' => 'hash_hkdf(): Length must be less than or equal to 5100: 5101'),
			)
		);

		if (version_compare(PHP_VERSION, '5.4', '<'))
		{
			foreach (array('tiger128,3', 'tiger160,3', 'tiger192,3', 'tiger128,4', 'tiger160,4', 'tiger192,4') as $algo)
			{
				$data["Unknown: {$algo}"] = array(
					array($algo, $ikm),
					array('returnValue' => false, 'errorMessage' => "hash_hkdf(): Unknown hashing algorithm: {$algo}")
				);
			}
		}

		foreach (array('adler32', 'crc32', 'crc32b', 'fnv132', 'fnv1a32', 'fnv164', 'fnv1a64', 'joaat') as $algo)
		{
			$this->algoIsAvailable($algo) && $data["Blacklisted: {$algo}"] = array(
				array($algo, $ikm),
				array('returnValue' => false, 'errorMessage' => "hash_hkdf(): Non-cryptographic hashing algorithm: {$algo}")
			);
		}

		return $data;
	}

	/**
	 * Test edge cases
	 *
	 * These are implementation specific; i.e. to cover common programming
	 * mistakes specific to the LANGUAGE.
	 *
	 * For example, empty() is a very common check to do in PHP, but if
	 * used directly on any of hash_hkdf()'s input params, it WILL result
	 * in a bug - 0 and null are different things for this function.
	 * Another example is missing __toString() checks for objects.
	 *
	 * Thus, some of these may match php-src's ext/hash/tests/hash_hkdf_edges.phpt,
	 * but the C ones irrelevant to PHP will be excluded, and most will
	 * target our own implementation.
	 *
	 * @dataProvider	createEdges
	 */
	public function testEdges($params, $output, $errorMessage)
	{
		$this->skipTestIfNecessary();

		if (is_string($output))
		{
			$this->assertSame($output, bin2hex(call_user_func_array('hash_hkdf', $params)));
		}
		else
		{
			$this->assertSame($output, @call_user_func_array('hash_hkdf', $params));
			$this->setExpectedException('PHPUnit_Framework_Error_Warning', $errorMessage);
			call_user_func_array('hash_hkdf', $params);
		}
	}

	public function createEdges()
	{
		$ikm = 'input key material';
		$data = array(
			// Matches php-src:ext/hash/tests/hash_hkdf_edges.phpt
			'Valid algo case-sensitivity' => array(
				array('Md5', $ikm, 7),
				'98b16391063ece',
				null
			),
			// php-src:ext/hash/tests/hash_hkdf_edges.phpt uses 'jOaAt' here,
			// but that's not available in older PHP versions while CRC32 is
			'Non-crypto algo case-sensitivity' => array(
				array('cRC32', $ikm),
				false,
				'hash_hkdf(): Non-cryptographic hashing algorithm: cRC32'
			),
			'Algo: integer' => array(
				array(1, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: 1'
			),
			'Algo: float' => array(
				array(1.9, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: 1.9'
			),
			'Algo: null' => array(
				array(null, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: '
			),
			'Algo: false' => array(
				array(false, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: '
			),
			'Algo: true' => array(
				array(true, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: 1'
			),
			'Algo: Zero' => array(
				array(0, $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: 0'
			),
			'Algo: Zero __toString()' => array(
				array(new toStringZero(), $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: 0'
			),
			'Algo: Valid __toString()' => array(
				array(new toStringAlgoValid(), $ikm),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Algo: Invalid __toString()' => array(
				array(new toStringAlgoUnknown(), $ikm),
				false,
				'hash_hkdf(): Unknown hashing algorithm: Unknown'
			),
			'Algo: Non-crypto __toString()' => array(
				array(new toStringAlgoNonCrypto(), $ikm),
				false,
				'hash_hkdf(): Non-cryptographic hashing algorithm: CRC32'
			),
			'Algo: No __toString()' => array(
				array(new stdClass(), $ikm),
				null,
				'hash_hkdf() expects parameter 1 to be string, object given'
			),
			'Algo: Other non-scalar' => array(
				array(array('md5'), $ikm),
				null,
				'hash_hkdf() expects parameter 1 to be string, array given'
			),
			'IKM: Integer' => array(
				array('md5', 1),
				'cf5a3dcc04a6455fee2602fe24099aba',
				null
			),
			'IKM: float(1.0)' => array(
				array('md5', 1.0),
				'cf5a3dcc04a6455fee2602fe24099aba',
				null
			),
			'IKM: float(1.9)' => array(
				array('md5', 1.9),
				'956dcbe0bb8b23aaf500d8063c1ed417',
				null
			),
			'IKM: true' => array(
				array('md5', true),
				'cf5a3dcc04a6455fee2602fe24099aba',
				null
			),
			'IKM: false' => array(
				array('md5', false),
				false,
				'hash_hkdf(): Input keying material cannot be empty'
			),
			'IKM: null' => array(
				array('md5', null),
				false,
				'hash_hkdf(): Input keying material cannot be empty'
			),
			'IKM: Zero' => array(
				array('md5', 0),
				'115ebf51d7d3a488b4cc8a25d9b0cf12',
				null
			),
			'IKM: Zero __toString()' => array(
				array('md5', new toStringZero()),
				'115ebf51d7d3a488b4cc8a25d9b0cf12',
				null
			),
			'IKM: Empty __toString()' => array(
				array('md5', new toStringEmpty()),
				false,
				'hash_hkdf(): Input keying material cannot be empty'
			),
			'IKM: Non-empty __toString()' => array(
				array('md5', new toStringAlgoValid()),
				'ea683be38029b634069f30de615efbe6',
				null
			),
			'IKM: No __toString()' => array(
				array('md5', new stdClass()),
				null,
				'hash_hkdf() expects parameter 2 to be string, object given'
			),
			'IKM: Other non-scalar' => array(
				array('md5', array($ikm)),
				null,
				'hash_hkdf() expects parameter 2 to be string, array given'
			),
			'Info: Integer' => array(
				array('md5', $ikm, 0, 1),
				'bc4b94fd8b78028ee145d32526d6942d',
				null
			),
			'Info: float(1.0)' => array(
				array('md5', $ikm, 0, 1.0),
				'bc4b94fd8b78028ee145d32526d6942d',
				null
			),
			'Info: float(1.9)' => array(
				array('md5', $ikm, 0, 1.9),
				'4ffac83bd3ee27c8be7703cfeec43781',
				null
			),
			'Info: true' => array(
				array('md5', $ikm, 0, true),
				'bc4b94fd8b78028ee145d32526d6942d',
				null
			),
			'Info: false' => array(
				array('md5', $ikm, 0, false),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Info: null' => array(
				array('md5', $ikm, 0, null),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Info: Zero' => array(
				array('md5', $ikm, 0, 0),
				'a81136d380d80bdfa68f449de9f6019f',
				null
			),
			'Info: Zero __toString()' => array(
				array('md5', $ikm, 0, new toStringZero()),
				'a81136d380d80bdfa68f449de9f6019f',
				null
			),
			'Info: Empty __toString()' => array(
				array('md5', $ikm, 0, new toStringEmpty()),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Info: Non-empty __toString()' => array(
				array('md5', $ikm, 0, new toStringAlgoValid()),
				'3e57a2bd3b8200a115351e34d6f6ae15',
				null
			),
			'Info: No __toString()' => array(
				array('md5', $ikm, 0, new stdClass()),
				null,
				'hash_hkdf() expects parameter 4 to be string, object given'
			),
			'Info: Other non-scalar' => array(
				array('md5', $ikm, 0, array('')),
				null,
				'hash_hkdf() expects parameter 4 to be string, array given'
			),
			'Salt: Integer' => array(
				array('md5', $ikm, 0, '', 1),
				'0d8b2c78ad8b7d7602b3c260c68a5b6c',
				null
			),
			'Salt: float(1.0)' => array(
				array('md5', $ikm, 0, '', 1.0),
				'0d8b2c78ad8b7d7602b3c260c68a5b6c',
				null
			),
			'Salt: float(1.9)' => array(
				array('md5', $ikm, 0, '', 1.9),
				'dcc713f1fb69efe8abb404705885c4c6',
				null
			),
			'Salt: true' => array(
				array('md5', $ikm, 0, '', true),
				'0d8b2c78ad8b7d7602b3c260c68a5b6c',
				null
			),
			'Salt: false' => array(
				array('md5', $ikm, 0, '', false),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Salt: null' => array(
				array('md5', $ikm, 0, '', null),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Salt: Zero' => array(
				array('md5', $ikm, 0, '', 0),
				'5ba98625d3d5040cd215d6b5922e092f',
				null
			),
			'Salt: Zero __toString()' => array(
				array('md5', $ikm, 0, '', new toStringZero()),
				'5ba98625d3d5040cd215d6b5922e092f',
				null
			),
			'Salt: Empty __toString()' => array(
				array('md5', $ikm, 0, '', new toStringEmpty()),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Salt: Non-empty __toString()' => array(
				array('md5', $ikm, 0, '', new toStringAlgoValid()),
				'556214294479f336d79b85d988c1f560',
				null
			),
			'Salt: No __toString()' => array(
				array('md5', $ikm, 0, '', new stdClass()),
				null,
				'hash_hkdf() expects parameter 5 to be string, object given'
			),
			'Salt: Other non-scalar' => array(
				array('md5', $ikm, 0, '', array('')),
				null,
				'hash_hkdf() expects parameter 5 to be string, array given'
			),
			'Length: String starts with a positive number' => array(
				array('md5', $ikm, '4x9'),
				'98b16391',
				null
			),
			'Length: String start with a negative number' => array(
				array('md5', $ikm, '-8x3'),
				false,
				'hash_hkdf(): Length must be greater than or equal to 0: -8'
			),
			'Length: String starts with non-number' => array(
				array('md5', $ikm, 'ff66'),
				null,
				'hash_hkdf() expects parameter 3 to be integer, string given'
			),
			'Length: Empty string' => array(
				array('md5', $ikm, ''),
				null,
				'hash_hkdf() expects parameter 3 to be integer, string given'
			),
			'Length: Positive float >= 1' => array(
				array('md5', $ikm, 1.9),
				'98',
				null
			),
			'Length: Positive float < 1' => array(
				array('md5', $ikm, 0.9),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Length: Negative float > -1' => array(
				array('md5', $ikm, -0.9),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Length: Negative float <= -1' => array(
				array('md5', $ikm, -1.9),
				false,
				'hash_hkdf(): Length must be greater than or equal to 0: -1'
			),
			'Length: true' => array(
				array('md5', $ikm, true),
				'98',
				null
			),
			'Length: false' => array(
				array('md5', $ikm, false),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Length: null' => array(
				array('md5', $ikm, null),
				'98b16391063ecee006a3ca8ee5776b1e',
				null
			),
			'Length: Zero(digit) __toString()' => array(
				array('md5', $ikm, new toStringZero()),
				null,
				'hash_hkdf() expects parameter 3 to be integer, object given'
			),
			'Length: No __toString()' => array(
				array('md5', $ikm, new stdClass()),
				null,
				'hash_hkdf() expects parameter 3 to be integer, object given'
			),
			'Length: Other non-scalar' => array(
				array('md5', $ikm, array(1)),
				null,
				'hash_hkdf() expects parameter 3 to be integer, array given'
			)
		);

		return $data;
	}

	/**
	 * Tests byte-safety
	 *
	 * Unfortunately, we can't test with mbstring.func_overload enabled
	 * only for this test case, so the entire test suite will have to be
	 * run with -dmbstring.func_overload=2
	 *
	 * @requires	extension	mbstring
	 */
	public function testByteSafety()
	{
		$this->skipTestIfNecessary();

		if ( ! defined('MB_OVERLOAD_STRING') || ((int) ini_get('mbstring.func_overload') & 2) == 0)
		{
			$this->markTestSkipped("ext/mbstring not available or mbstring.func_overload is not enabled for string functions");
		}

		/**
	 	 * The test relies on \xC5\xA2 being a valid UTF-8 character
		 * that the output for hash_kdf('haval224, 'input key material')
		 * starts with ... we'll only test if that sequence is treated
		 * as a single character (wrong) or if it gets split.
		 *
		 * @link	http://www.fileformat.info/info/unicode/char/0162/index.htm
		 */
		@ini_set('mbstring.internal_encoding', 'UTF-8');
		$this->assertEquals('c5', bin2hex(hash_hkdf('haval224,5', 'input key material', 1)));
	}
}

class toStringAlgoValid     { public function __toString() { return 'MD5'; } }
class toStringAlgoUnknown   { public function __toString() { return 'Unknown'; } }
class toStringAlgoNonCrypto { public function __toString() { return 'CRC32'; } }
class toStringEmpty         { public function __toString() { return ''; } }
class toStringZero          { public function __toString() { return '0'; } }
