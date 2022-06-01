/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e60bc642fefc11b43792e8745df6c1d"
    $a1="7e60bc642fefc11b43792e8745df6c1d"
    $a2="913f9c49dcb544e2087cee284f4a00b7"
    $a3="7e60bc642fefc11b43792e8745df6c1d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9017347a610d1436c1aaf52764e6578e8fc1a083"
    $a1="9017347a610d1436c1aaf52764e6578e8fc1a083"
    $a2="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a3="9017347a610d1436c1aaf52764e6578e8fc1a083"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
    $a1="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
    $a2="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a3="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
    $a1="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
    $a2="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a3="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
    $a1="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
    $a2="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a3="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
    $a1="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
    $a2="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a3="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
    $a1="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
    $a2="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a3="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
    $a1="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
    $a2="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a3="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
    $a1="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
    $a2="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a3="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
    $a1="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
    $a2="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a3="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
    $a1="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
    $a2="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a3="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
    $a1="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
    $a2="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a3="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_cyberpower
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cyberpower. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y3liZXI="
    $a1="Y3liZXI="
    $a2="ZGV2aWNl"
    $a3="Y3liZXI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

