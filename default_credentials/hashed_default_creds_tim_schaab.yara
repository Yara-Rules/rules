/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="73005d28babc7a958a1362a2201686de"
    $a1="b91cd1a54781790beaa2baf741fa6789"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b77eb819278979b8524abdddc9cec90f76c61268"
    $a1="07313f0e320f22cbfa35cfc220508eb3ff457c7e"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="52aae9ef3de689f47d9ad60e13b8f52849e53baca96c495efdd6dca4abc7d3feebf571e2f1da7becb2c1348362a91407"
    $a1="667332fb92cbc368815b6668d52f2261b3ff4d7d0f9e52a0fbabb37f261c13c1a3985abba04d322580c7d48060f7400b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ba3e163ca6a7bc217d2796d3478130257aac7a0d1cb6d1a068ba44e3"
    $a1="097f8a9d50be832dc296c89ab5400939a21ab5592c9790cacde423ff"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7681d198af9976f4b4b73ceb3bc7cdb4b5b7ae1da6803056916a5551514ad951382959fa57d7df3d8672fe8252853cc62809b338900bb3167b8501fd48a67f89"
    $a1="10c1a3be7b993eee6463dd03e83987f5c160af6552107bc53623426f3eb07e128b3cdd4865df74c506338e9fbd2de141857cc72b2cabb4eb315b3fb3d7d35af1"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="992345f21b57d68f497b9c5dbf837e060eaf2d8a4894f3f98c0b64de2b13006d"
    $a1="00810cf8b94d6fcb9c5de484d3bec4187620b3e2876e59aab90d852fe0f18fb6"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bba0b9d3314db0322e75ebfc8cfab750be0a3907637bb6b96539ae716733e36e928383b789da7734f5057f5233c22c6ef75275311e5abe08ad4fb5355081ea19"
    $a1="ae48ad7b8a408c58a6eb311c2c65e4a2b3579078e4e7cb33918b6b0a11dad34a898cf91211ba7718ed483f90c043a19aaaba8d9ca9f3610bad28b63691c9a1f8"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f6bddb051aec6d01742704121def4365dcff3684356da6781edc4468cfed7e90"
    $a1="efaf787dae80c58d0676abbda9990f95819db87e62549104485872f23f8ab5d2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc51e79a1c1bcf77dcafe187a816f41696607b1cc7d0229539f6e387"
    $a1="796a752e3ba6302e6e5bf7c2e217de4782cad48b23373c1439064aa7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e527ee31f3db0c0dd623164db1faa602ed6fb418a1e1938883bd315c1bbeae0"
    $a1="043a4b3192fa16dced3d44a0421d1071430738d7b6a109d1a661887f611523ea"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="959a5b5f7865fce20f855926b93cce02afa1a00369cb293f8fdce3f3a8fc978336dbd1b31f5407ca50da05936af042d6"
    $a1="6298254a634a568a9aa432814c5563e3ae408330cfa0370fca364cc36ccbd6b0d96cf4ae41179a3526fc4e099651a024"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c80072a6101b7360095ab0828fd92fb2e96d544ed09f855f32445c96709245d14687246cfc889d2446fd43ff4aaecd49f9b6ba23ef6060c65638b08a6fa28fc3"
    $a1="3d7bc8ff047df30b118d405435e5c94bd038dbc77040b55a2fb2cdd2f2bb6f4656d2f6cd76c6d432e303264e65a0b802c9b21f15fbf254c3b2449a803ab0e490"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tim_schaab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tim_schaab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dGhlbWFu"
    $a1="Y2hhbmdlaXQ="
condition:
    ($a0 and $a1)
}

