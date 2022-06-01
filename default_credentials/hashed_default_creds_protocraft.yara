/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a53560609ddcb913d8fdc1f094f6aca"
    $a1="5449f5ad3be9fe3f70cb25d7ad66546a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="26861b599d63208d29db6616f1d66df8afdc4785"
    $a1="78e4ac2d505bca71d3b9a2aac66fc6ef5b164cf7"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c8f4e06ab3c3cf212c77ff2a380eeb0d0d24a89bd4f9388640ca0cf95291e9411c48fada50de313c0558e68120ffb3c3"
    $a1="0fbfe8051b611ad8250979ffa4bc5494e4c2b2ea696eaabe4de50da1b366c26d29cc46cd158588b566e1473aa39ee1c0"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="18250460059f5cf002f219bdf70d720b8d7eaa2f250a8aaa56dadea9"
    $a1="90e84fbcb14492c42d87ebfc5dfef28b25f536fccecf4f3b21e34b56"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="45fe64d53670a60a32fd45fbeb8e22c2505278209fce59c97212e22c309fb047632305ab94e13afca1e7ddb44da2869c6f5d01ef9010604b74ef24e5921edbc9"
    $a1="90ec751aed32c48103c8c2ed50af702ed50e53976b771bc854e25e2bf3fd4f15991c61fcbbdb96c32b8b39df0cf88eb0e3586f076981c88aa74d1121d343b7a0"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="16d1b91e6218e62c6d0a5abae61abf83a55581c92e6d9da0087a21fcd615c3a6"
    $a1="eec809683aa6744a99b65e585360ce97cc79490311df1618f7dc53ace2645c77"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="33509b6581c62b1ae48efcab4188327c4946fe143cfb141765f6657c1c63dea5b9cd715aab8be2955febf9037b63e23888e523454161ed0ad24277ba80ae54eb"
    $a1="34ba8044050ef19e8ebf58ffb60690b73f6c4f3be1b8b9509a8a438d55e073a12da31c5ed7ed64006f008d480fd7cb0ca1d27ef95ee332cf10beae4068d75899"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ebe94dc8983771d3bed8ff7fe832471b332b07f1fe43ecd316fb5de0283b962e"
    $a1="340553627a618d7946b63b7e3897b99e9da9a983b9b586bf897a792d3bd219d0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e610c66661efb5363535db0f09e02ed10ed3db0468a1807e4593587"
    $a1="6377fbde69a9d931186770db0a50bef81dfc1f01418644c2e5727f13"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e1e429a92357a8522f6e8d63a1ec3f7f20b63399063eb7d24f2e8b5ada5d0a56"
    $a1="1069b8293cb8f385a0b9d947ad7f4a6d397d0dbfa8741a411b7aba28c949b5b0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="26b96a280c54b03133b7821eaa1c34b289d8cf6ae0081fb4b694d030016249f159acba3c64ffc8eb8ac10c63bbe37236"
    $a1="558e7f45f3376ca68425d5aa7fd12375bf91559821f87af5c2f87e81498915e0c6380d301ce0df54aa72ed4bb1ea0997"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5b987007670291ebcc757270fa96b43976e24441a7b385fb408b5d072a9a5179555d3fe602526f3340bbf13c7ed322e457e3c2fb73739cbdbcba51b4ab8c379"
    $a1="e643c37f043f1f907ef0513a829ebc83892e5e06882a9a900be7a297087abae97581df5cae44b0510b8704ca2f5fb85746925446fc75790718a0de93858679c4"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_protocraft
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for protocraft. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bXVzaTE5MjE="
    $a1="TXVzaSUxOTIx"
condition:
    ($a0 and $a1)
}

