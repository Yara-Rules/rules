/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a74ad8dfacd4f985eb3977517615ce25"
    $a1="a1c2d5a7bd746b3e13281664926267e5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="94a0426e8d3203da5468ccf0c624f93cb37601e2"
    $a1="782f13253a81998119936f9905c990d688978c23"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6f8434e44ee71b6d9db1c351541b950a657e32948cce61625f3964a0e20112de8a5e5ecb7d0325283a3753f0fa66fa6"
    $a1="5a9cabf2d5c387228affb7e0da802d44f309dac06b33abb130ec3412b0d9b2a8b2fe8b5c65b040e65b493039a63b6994"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="643fc30d6d77ee255aaa29b84211b518a49e85b3d30e458ca812e361"
    $a1="51aa380f70edeeecc838bd278ae78ea707653f2ab7a79d944b8b548d"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="de91078a5b1eb16864d1db7baffa09ab367e6ac301fa61a484dfd7095def57de8bedfa2ba415f59d7e76753c807d0fc5b0e8963d1fd1992b6936ba9383c4975e"
    $a1="b276d2d9f7ec787739c9b13dcaa2bdd79faca1166914854333c76609350a5005d413666dfe67427d7d345c070ad93e367bb670f2056aaa025114b9f29444bb81"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0d45f5fd462b8c70bffb10021ac1bcff3f58f29b1faf7568595095427d42812c"
    $a1="7672dd2edb47af6dbf8a18e6ec217b17edcb9531acde1028d248a7ce5a744ddd"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e89533ae07f2b649d869018b12e53af8c5da84a479e5899bf9536654cc94d91c7bd731e6f28cddab2c58e8e6279c2b4feb14bb5aba26358d946ccb2496fcc4a"
    $a1="f67991b83f5325d369868d4e770764605cabbd69bb6ef7ff5aa310fa83dbcb99f3013e024e0f1e6d14e687d96b64ae3bf38f528cdb29b0b848154b01c022b4f1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b4bfd4da344d6eaf12d3727c604aa5198977d089851e9700a148955e04dcee85"
    $a1="601c482cd4b2fb7b9b5646b9e0f007b28523b59d1bb569b270cc218f3daf8dcc"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="653f2b3fa3f9763ad936ede2df5a2e13e61349870c0a86ae8ca85f25"
    $a1="af727eb2ab5c39aaa570d1c506b3ba3baa72e9f99cb2433584a08e03"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="57760688d1f824db5d9c6bd4024622bda7c9550529d99c42cc890e881a285ac7"
    $a1="5813046cb52ca23bdb05915e6e5e7929f9af4fc2c1ab4ee466ecd20b1eda7d33"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4516ab200f5ed7ddb33b6e53a9f8a3d8c028955e0d1f99cab427e4d309dcdbe258a445ed54be33e2d0ba7b247496654"
    $a1="3993a490b023d2df8561c7f088190fb36f5e767cf7100aa3a33b52d3beb91101003672583c7079b9771633cc5e28e334"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7d82e8deff52c99abe279678f98e50cd2c70edf53bd4c847f324c380cee7ade9f036315b79fac6c1c17c6b05827894ade1a422e46a4325269eb9bbd06a48e6a7"
    $a1="baf9cd37fc5c34e635729b68f94e26a6a95d44fc97aded2731fb514dd05c53266f88ce4dffcf31f07aaa9b6551ae8447f3dd4b6e67dcc7de6d93be9e7fa80aa7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_phpreactor
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for phpreactor. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y29yZQ=="
    $a1="cGhwcmVhY3Rvcg=="
condition:
    ($a0 and $a1)
}

