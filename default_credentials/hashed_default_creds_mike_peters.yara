/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3760a58c148fe40959c3f5350e8a5162"
    $a1="9eb7eaabde1f146ae5184b96e727a623"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e4ff855d91951b344f2fc06d73c9c22110ff68d"
    $a1="2b924de2e59b07d41e1d0f0734d6f0a61e8563fd"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="36606b2a05ac1bf5ec5da128d378fcabf2198e34914fe1f6e14e2238add9dec270cedd11ec57cd75d2f53c14666596b6"
    $a1="8d03678115cd5643b076a0615aa216daa526aaff50953402c0c5d137a3789d55fa5dba8cfcdb76ced557ce0e376b8c31"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3e62cb8e84184f8179fd31cb560077376b5c44e88fcd311b20c1c8cc"
    $a1="dcb80a936deca9704d30462d2ceb96e56af8d9a00cf7863bdfa91558"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="084464abfce48360589ea66600f6e515095aa719bd2df7bc15782d75c92b3084d150044fce39d114e3bebffc2a675d54dd1babf1e90a6e4fe1af5308aaf117ec"
    $a1="67dacd5a4aa9d821189e70849feaf8f7e86b1f1bb6374025f34d0b7218c86b3bc065d8a14e0896f2d727f638d51494c56b85fb8596336610800773b59c81b50b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6c4a79d37cf5e5b57e277e8c4a67da06258e63f001edb9709b6bb17571cde506"
    $a1="286b5dc354fa294d0e5530deb9c788031eb4b66a8a0348b607afca948435f692"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf707e79308f5867c85a95aacf508aff835039724a38cff3deda189d4a7026fbcee2b666fbcdfe1fb0d7b7e3b76710a2ecaf5daa97e027d9a1bd63d4b1fd3107"
    $a1="4037a63ec412209574e54ff977cf321414520e39e89a75e11a0aaadd732f5fb591bfb968a7564e1d172ef5d51ca932f5838f4be0cfadf45e61d439b31b49bc4b"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8d0037ed26039b236e037bef7c04d48ec9fe239900658c972984b9602dafa929"
    $a1="441608a66f64cc8e031d7812d5297e271076e9e32d2b401a1643e31d05081ee5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="050f75e33d345994b527ca026748f9cf61c5271356f19c3ddd113a65"
    $a1="57d89390c51a6bc26e0f7c5eb281112436450df3083eaa04e05e4cba"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b608192b14a7149c2466283c6a56b0029887698240ca43c8afcdf807942f4dd5"
    $a1="9714558db29e3fcd29c75f873b615f093399010b9d3898f4264946ae8801ac93"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0b5fe5ddf86d2ba1753ceb31abeb735cc93b8deaf9244eb68f11fce42c21c56e082ab87d78f9cd8c4e73b708696a8c0f"
    $a1="e974aa87cd12edc23db032a6482a8db971d800beb2ddc1233fe77d68efbf7f7ccc31f9d28929390956c04ed79caa97a7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0851d1eb63a96ad11fcc22d278b7183321d7817c0ed56e9b13b417a17bd4db4aa93f54d3949db257b07c74a664d165920d50b37cac4edcd31607f8c5fe38b4d8"
    $a1="ed311dffbb1ef20e418c9e91f48d6125ab4fa57e35c0ee20168bb4840a3c7d883793d626bc95511d6e7be5f3fd2d5a9b00243aabb0fd6cf3f8cf38fda8ac2e0f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_mike_peters
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mike_peters. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YnN4dXNlcg=="
    $a1="YnN4cGFzcw=="
condition:
    ($a0 and $a1)
}

