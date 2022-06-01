/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8fe4c11451281c094a6578e6ddbf5eed"
    $a1="8fe4c11451281c094a6578e6ddbf5eed"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1a91d62f7ca67399625a4368a6ab5d4a3baa6073"
    $a1="1a91d62f7ca67399625a4368a6ab5d4a3baa6073"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e75984af4914e9531b359fa63ba8abf6b781d6fcbd8698b84d7c3136c5c47e2be33119ed13d064151405cdfeff51ee43"
    $a1="e75984af4914e9531b359fa63ba8abf6b781d6fcbd8698b84d7c3136c5c47e2be33119ed13d064151405cdfeff51ee43"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd"
    $a1="bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="be196838736ddfd0007dd8b2e8f46f22d440d4c5959925cb49135abc9cdb01e84961aa43dd0ddb6ee59975eb649280d9f44088840af37451828a6412b9b574fc"
    $a1="be196838736ddfd0007dd8b2e8f46f22d440d4c5959925cb49135abc9cdb01e84961aa43dd0ddb6ee59975eb649280d9f44088840af37451828a6412b9b574fc"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30c952fab122c3f9759f02a6d95c3758b246b4fee239957b2d4fee46e26170c4"
    $a1="30c952fab122c3f9759f02a6d95c3758b246b4fee239957b2d4fee46e26170c4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6bddc3a7e69780937eb8b5fc52a605ec0a498c218c97588494ed74df7d5e4240f3c666b50d3c019c2fa76f3973935e64e17ccb321e4285f142b7b0cd44dca643"
    $a1="6bddc3a7e69780937eb8b5fc52a605ec0a498c218c97588494ed74df7d5e4240f3c666b50d3c019c2fa76f3973935e64e17ccb321e4285f142b7b0cd44dca643"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="96955f842a8eee22926294313610041a03fae3c8566247a742d6a76e18eaf1a5"
    $a1="96955f842a8eee22926294313610041a03fae3c8566247a742d6a76e18eaf1a5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="708ef04755d85fb4a2340edc89f78a21574248bc4dbb568eb907c3a2"
    $a1="708ef04755d85fb4a2340edc89f78a21574248bc4dbb568eb907c3a2"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd5a71a5fecae3102bf192afa6e4c07566bd8f41fbc6934cc20fd12e5595e121"
    $a1="fd5a71a5fecae3102bf192afa6e4c07566bd8f41fbc6934cc20fd12e5595e121"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a44b8e3acfe7b0bab875a6775a80d564c959a7904a10e7ffe08e37e209eba708ab48e5303d271b34ae9e3bef82082d40"
    $a1="a44b8e3acfe7b0bab875a6775a80d564c959a7904a10e7ffe08e37e209eba708ab48e5303d271b34ae9e3bef82082d40"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bc01cefc69c54c31f13d86a416a68211e9e02efb0ac3db1318dd5ea768de73209a7e30ee92d942ea31086fcbdb62a42d2ea7336913628d29e89aea5cf74dd526"
    $a1="bc01cefc69c54c31f13d86a416a68211e9e02efb0ac3db1318dd5ea768de73209a7e30ee92d942ea31086fcbdb62a42d2ea7336913628d29e89aea5cf74dd526"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_voicegenie_technologies
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for voicegenie_technologies. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cHc="
    $a1="cHc="
condition:
    ($a0 and $a1)
}

