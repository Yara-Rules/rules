/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1c6d6ca22cc31cb79e6e1f5277ef06e0"
    $a1="1c6d6ca22cc31cb79e6e1f5277ef06e0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1280b208e59e5b339bfaec67511509c713f2e04a"
    $a1="1280b208e59e5b339bfaec67511509c713f2e04a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0511dcaaace99058e8117a400a08d0efb0c63b2e97f2c82e5682fd078b1ee082e08a5172564ca4155b9d13fef75ecafb"
    $a1="0511dcaaace99058e8117a400a08d0efb0c63b2e97f2c82e5682fd078b1ee082e08a5172564ca4155b9d13fef75ecafb"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24125cff46775475979b5b92b88fe60bcd25bc66f109264e126573cc"
    $a1="24125cff46775475979b5b92b88fe60bcd25bc66f109264e126573cc"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e259fd13956f0821b5d08dd6f15b42f21f5513f74a7118139a4e06d9708511652735ad1dd834b9228c6063247bae86d85044d5e92f7a88d5ac0dbba5cdfa76f"
    $a1="3e259fd13956f0821b5d08dd6f15b42f21f5513f74a7118139a4e06d9708511652735ad1dd834b9228c6063247bae86d85044d5e92f7a88d5ac0dbba5cdfa76f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f1b55b860590406f84f9394f4e73356902dad022a8cd6f43221086d3c70699e"
    $a1="7f1b55b860590406f84f9394f4e73356902dad022a8cd6f43221086d3c70699e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="16fd829eb094822e947c000452f7d785ecff3a5b59a5c535a4ee75c1c5c34d4e1666e4c878ce716b9d0218ee46f2181dc774d7f4b82091f5bd93d94c4abcc66b"
    $a1="16fd829eb094822e947c000452f7d785ecff3a5b59a5c535a4ee75c1c5c34d4e1666e4c878ce716b9d0218ee46f2181dc774d7f4b82091f5bd93d94c4abcc66b"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="10a3023ac59111ab169ba02e0c0481a7660e43d8dde4d6787dd8c1411673120d"
    $a1="10a3023ac59111ab169ba02e0c0481a7660e43d8dde4d6787dd8c1411673120d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9dddc625701f46379155d00c6e5d24c6ebeadd2247d07ffb7b76eb50"
    $a1="9dddc625701f46379155d00c6e5d24c6ebeadd2247d07ffb7b76eb50"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0283e5dde1443ba70e8623b7de43aff1ee2b4f7a2c48e58690d2ae5c586b57a1"
    $a1="0283e5dde1443ba70e8623b7de43aff1ee2b4f7a2c48e58690d2ae5c586b57a1"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25fa5a9a5899389d961c6c0976641a1a48b6300fc68c63c92175afa1ffc57ac4a5d598991571ca11b183c27390640525"
    $a1="25fa5a9a5899389d961c6c0976641a1a48b6300fc68c63c92175afa1ffc57ac4a5d598991571ca11b183c27390640525"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="674e108fad0b50c3c50da6665568c00a3a740302f0eb5a64e86583b9d22567fd3d0420d8bbfa9d394382518192f2b9575f66fc949936439347e48ebad257d9a6"
    $a1="674e108fad0b50c3c50da6665568c00a3a740302f0eb5a64e86583b9d22567fd3d0420d8bbfa9d394382518192f2b9575f66fc949936439347e48ebad257d9a6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ldap_account_managerlam
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ldap_account_managerlam. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bGFt"
    $a1="bGFt"
condition:
    ($a0 and $a1)
}

