/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4811df2c83bee7ee3a883640cc4d80af"
    $a1="abe6db4c9f5484fae8d79f2e868a673c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="325b32ac6cdc607502c4532300fadd4d3a0cdc1c"
    $a1="ab4154a7c451f56e9b7ff1537758ddd0c619f8be"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="253553fe01d9d5666fbd3cadacd95189085b9d922b25aa01fae15858a56db818e75f5afe1216b0bbffcc23bb3e28dc54"
    $a1="8dedd9fbb2b8711a25753f2faddfd4c7478f584e8f9ee89328f3fdfab770ee19abcc7fbae828335f73500137ee4091b9"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8b13d1565c9e9c0b74899415243e152d8caadf0f714b1f1f630fca2f"
    $a1="0a5fcaa8156df5fc8f006e239b44d01fd54862cee3056ef9ece150db"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="baefcd6c04eb788b2119ba9a1b6ee55bd9e0f872d2deb8eeef9723810f789774b2bf20e1d0d05d094e4b62a7b1062cc9e5c646128359ffecdd7b912eb1c38bdb"
    $a1="d5f92dcae90ec87247840df8a76a195aa1cd0f7fe996b1d79eb6f9da2294338a556b46cfd64e0fe3a00b71952e17a72880b01540485924150fbb5448098e6853"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d42c104a926912d66fc148da987606648ae8e4ff88b21c810e51f8c47b3b7064"
    $a1="48c5a1d217fe85082464d2ca1e90a16d15464fabe20f8610d79b63aa58797b9b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21121986da4c2c50df04d001ee5caab03158348b7874d5ab1743b423996756598585b35c5f127a8f6d7cd9414ee5a72d91d09bb0926ed81a82de548dd3e424a9"
    $a1="95634d08635b26a78df2c5dc103556cc1a15ca5858c8bda7e04b16f9e68a8644eff5d2508be346a0c3ce742f064aa9abcc65e60302b589ecf88178ebcf9bd9ab"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2c7e219e70e3709ea4da62059a7626ef9b1d375724dfd9edf713c3ae3107d225"
    $a1="1afd6171483ae4dd7a2baf511850ebc9900b1adc9d8c37823a7a0650461a2c72"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3eb683ffe6602c2cc920568281c655d9ea6f2b790d2633cf643f90f4"
    $a1="65a8b6efd24734f6e40cbfddad07491caab5ef3ec7f783df05aa1f7c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4bb99770fa21751eed6dd7496b1e3e1fc6e62b41ad403d90ca47f4feef023ffa"
    $a1="479c8cc5b15e63edffa494719fb284525dcd351436ef9be5c6761eaead136c82"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5f14ad767216390bbea72abcc67d8bbb0005715e5993bc3ad6a15eef8fd93689fa551a434ee899fdc08ac3b6f7850083"
    $a1="3b0be128d62f2800d7c12e8c90d361257b3df6638ab81a873d6c095a6357922cb910e3fb506739c6b812a564b49810da"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e3ba9708644b3076b80bd3d7a687d3dae422148efb4a02aa7e577bdcba9bb28aaae2332ea3967a43f533ebc13b34062a11aa22eb17ac90e276f1a0a5dbddb17"
    $a1="bae826dd03f7c866258d7b93bde4be7ffe42d0039032436fa517abbe03da5babd149068e8a7f3f913a474a5c587ece5b7c005f7ad888b2c68e8651a7d40e518f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_firebird_project
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for firebird_project. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="U1lTREJB"
    $a1="bWFzdGVya2V5"
condition:
    ($a0 and $a1)
}

