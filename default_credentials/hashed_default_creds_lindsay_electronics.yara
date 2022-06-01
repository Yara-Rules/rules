/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99fedb09f0f5da90e577784e5f9fdc23"
    $a1="e6e9f5d5d8fb4be11d981eba8db34c14"
    $a2="e6e9f5d5d8fb4be11d981eba8db34c14"
    $a3="e6e9f5d5d8fb4be11d981eba8db34c14"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a1="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
    $a2="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
    $a3="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a1="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
    $a2="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
    $a3="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a1="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
    $a2="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
    $a3="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a1="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
    $a2="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
    $a3="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a1="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
    $a2="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
    $a3="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a1="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
    $a2="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
    $a3="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a1="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
    $a2="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
    $a3="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a1="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
    $a2="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
    $a3="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a1="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
    $a2="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
    $a3="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a1="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
    $a2="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
    $a3="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a1="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
    $a2="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
    $a3="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_lindsay_electronics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lindsay_electronics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QURNSU5JU1RSQVRPUg=="
    $a1="U0VOVElORUw="
    $a2="U0VOVElORUw="
    $a3="U0VOVElORUw="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

