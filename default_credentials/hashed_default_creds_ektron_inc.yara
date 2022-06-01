/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="388d33adeb7f579156ee4a0c86777760"
    $a1="388d33adeb7f579156ee4a0c86777760"
    $a2="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a3="1ba1910b5b36c57ca5a6bf1134186f00"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="748a336cc88c03ccb07ed5f5073d18624731b8b5"
    $a1="748a336cc88c03ccb07ed5f5073d18624731b8b5"
    $a2="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a3="54f39b2b097190c7f817d09b71899db1c9febf5d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7276f879d844283681889a5c5f580f30d8bc469263f47dae6e240a99a4a7efd1507da0624d3d85475da900fc361e47f5"
    $a1="7276f879d844283681889a5c5f580f30d8bc469263f47dae6e240a99a4a7efd1507da0624d3d85475da900fc361e47f5"
    $a2="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a3="abccce632c2244a5968143be6a181ae13815db6f70562b3314e5d34a02bf77218ab60bc032bb2cc8ef0734aa1e65ba09"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e8098cf453e9885e01134bf0895ff089cb19962a0430d6db6ac0ca73"
    $a1="e8098cf453e9885e01134bf0895ff089cb19962a0430d6db6ac0ca73"
    $a2="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a3="af7f9611506b70ba8393c035b0be590fb4b50d723d80e41e7590e70f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="76a447de1f4d7c97c4650376d6f7f805bf1f730a60cd67166bcfe7254a4ee3010c0e4b7dc25e1d3e6c948af107874b4b3214b22bd638d22cfaa3bdc2c7ffb05a"
    $a1="76a447de1f4d7c97c4650376d6f7f805bf1f730a60cd67166bcfe7254a4ee3010c0e4b7dc25e1d3e6c948af107874b4b3214b22bd638d22cfaa3bdc2c7ffb05a"
    $a2="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a3="4aa4754c637fa58fd50afcae0a73d211b27cde13a3adc04c419689f51d13c2ddac1a9bb3af992f7f998ddab9f6930de99f8ee9ef7778da33c924df367519b48d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f0177192e8bdee58fd3d5e4479c148d52b55d3f0205f5d9b17973aa261277c2"
    $a1="2f0177192e8bdee58fd3d5e4479c148d52b55d3f0205f5d9b17973aa261277c2"
    $a2="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a3="8dfeea858fb7a73674d0ed862861599283e6c839d214060b9d8291e9086cad52"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="34b4bc9a5c5fcef6ebc3cb008eb6e4412ecc131079455ba2ff9d56ff783273a65d2a6001be70bc7cd2d86b3b6c678ec61451fab5021231c7a82d9ff48585bb05"
    $a1="34b4bc9a5c5fcef6ebc3cb008eb6e4412ecc131079455ba2ff9d56ff783273a65d2a6001be70bc7cd2d86b3b6c678ec61451fab5021231c7a82d9ff48585bb05"
    $a2="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a3="7d3d4d7e93c044f4a810f47b1d7eb740210d2144b5265d3b37998dc93a8b9d0cdb6ffc154e4cdfd2c36e834533a8739c1a7066f0ad75f598cd178324fcd36e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c988c5a4e5d5f03f9b08121efdb5e0fa3862320a09d41cd45294125bede1eba"
    $a1="8c988c5a4e5d5f03f9b08121efdb5e0fa3862320a09d41cd45294125bede1eba"
    $a2="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a3="b894b8ed1a098f68cf79d8e28e51fcd25cf47626db584ec94bb349db66565e20"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1c153368c77b8f057bcd8b7ebda5bb4db727bf2ba5b6f8511c36eb87"
    $a1="1c153368c77b8f057bcd8b7ebda5bb4db727bf2ba5b6f8511c36eb87"
    $a2="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a3="7c2b4a789151c004478b2a0b16d1ab7eb0ae9fbbc17bbddeac04d6b0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="18a921ceac023823379c712d7bc6077f3a8ec5e68b026170f6b6d6c44f2e494a"
    $a1="18a921ceac023823379c712d7bc6077f3a8ec5e68b026170f6b6d6c44f2e494a"
    $a2="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a3="bb883024addc15febe771f444d0b700bbca27b607c17fcef146d8212ad0c5e6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bf45272818041e47979f7b30b6e4b88161efa400807adc045f15f262bb94956fd31208ce50ab332735c7edd1c006d7fa"
    $a1="bf45272818041e47979f7b30b6e4b88161efa400807adc045f15f262bb94956fd31208ce50ab332735c7edd1c006d7fa"
    $a2="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a3="43a121eba75b3bc0e26ab1dc8069251ae7257b535727b73a89a039192151787ca848a529679cac9eb69b7589f32343cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4f53bad004878396e755bea0549c17c8853efe0da2b2cd8dc2a3313906dec8c596a73f7eeb8873af8795ef17df303a862cea7330b5ec823246437ae314796156"
    $a1="4f53bad004878396e755bea0549c17c8853efe0da2b2cd8dc2a3313906dec8c596a73f7eeb8873af8795ef17df303a862cea7330b5ec823246437ae314796156"
    $a2="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a3="c8aeaaaf3ba4cf140fb8abeaa7743374d338ab00fd4bacf642ee324baf75db6eb5d9ec0ce0dd5e4d6b9ef030fadf5f4dce6b8597d1e350c4cd766a98cf37546d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_ektron_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ektron_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YnVpbHRpbg=="
    $a1="YnVpbHRpbg=="
    $a2="c2E="
    $a3="RWt0cm9u"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

