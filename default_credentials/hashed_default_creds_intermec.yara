/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="14307f768d621b4f2120caeb5c425faf"
    $a2="14307f768d621b4f2120caeb5c425faf"
    $a3="14307f768d621b4f2120caeb5c425faf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="108b09192633643de9870cc86e690237d10c5144"
    $a2="108b09192633643de9870cc86e690237d10c5144"
    $a3="108b09192633643de9870cc86e690237d10c5144"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
    $a2="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
    $a3="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
    $a2="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
    $a3="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
    $a2="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
    $a3="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
    $a2="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
    $a3="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
    $a2="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
    $a3="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="25a9e5c6b8fb76bfc981f3a6c5365593eae0db790174b82740d2535241d15815"
    $a2="25a9e5c6b8fb76bfc981f3a6c5365593eae0db790174b82740d2535241d15815"
    $a3="25a9e5c6b8fb76bfc981f3a6c5365593eae0db790174b82740d2535241d15815"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
    $a2="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
    $a3="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="e32c206e6c2e4740252a8e171814953fd7014384073a91eb75853cc18a47f3dd"
    $a2="e32c206e6c2e4740252a8e171814953fd7014384073a91eb75853cc18a47f3dd"
    $a3="e32c206e6c2e4740252a8e171814953fd7014384073a91eb75853cc18a47f3dd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
    $a2="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
    $a3="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
    $a2="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
    $a3="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_intermec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for intermec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="aW50ZXJtZWM="
    $a2="aW50ZXJtZWM="
    $a3="aW50ZXJtZWM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

