/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="73ff5555e52fde5a83a48310c57826cb"
    $a1="73ff5555e52fde5a83a48310c57826cb"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1468cebdd51acdbeebffc0d182ee7dbc0bcf0211"
    $a1="1468cebdd51acdbeebffc0d182ee7dbc0bcf0211"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4c19698a6ef429e1018159ecd7bba601844763279bf0886f7ee60b3ba67405a31ee2f1e25b129f2b3a94f6a78ed573a4"
    $a1="4c19698a6ef429e1018159ecd7bba601844763279bf0886f7ee60b3ba67405a31ee2f1e25b129f2b3a94f6a78ed573a4"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d4212591fa279f0de307778beb6cfed79d6726e0290637a22755eef5"
    $a1="d4212591fa279f0de307778beb6cfed79d6726e0290637a22755eef5"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5bb77f3869a5bfd11a256691717ffdccdbbbc8e83caa2ae4be1322fd82e649820f034ea4aa7583bbeef31aaf65948a3dc331375eca4da2dc13fbc7cdb7cb7256"
    $a1="5bb77f3869a5bfd11a256691717ffdccdbbbc8e83caa2ae4be1322fd82e649820f034ea4aa7583bbeef31aaf65948a3dc331375eca4da2dc13fbc7cdb7cb7256"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7e3acd1d0553393aaf82d4a893422ced3cee013fded53491a1763c898d37682"
    $a1="a7e3acd1d0553393aaf82d4a893422ced3cee013fded53491a1763c898d37682"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f93a4c85c3999beda5e4b05abf0970252ad29921867adb306099a30ded03e923b98a1701271488ddcfced6ac809d77f173f1003734de5fd06276f58b5dfb31c"
    $a1="7f93a4c85c3999beda5e4b05abf0970252ad29921867adb306099a30ded03e923b98a1701271488ddcfced6ac809d77f173f1003734de5fd06276f58b5dfb31c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed4c5e03b178cd31b036affe0027841e69f9f3465ddac75a53a9077840a4c055"
    $a1="ed4c5e03b178cd31b036affe0027841e69f9f3465ddac75a53a9077840a4c055"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f79279d15d397afcb90b35c2d0359e4b5c0f1da9ebb01645c37aa850"
    $a1="f79279d15d397afcb90b35c2d0359e4b5c0f1da9ebb01645c37aa850"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7caf41ae779b5fc1e6457ea777e4845bfeb3b5098045bea509a9a86a3eab16d0"
    $a1="7caf41ae779b5fc1e6457ea777e4845bfeb3b5098045bea509a9a86a3eab16d0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e75988d6eee6fd1e529c86165650f0edc92fb78a61427cab228cbe043ecc993a1f0e56ae9929a737831bb797677b224"
    $a1="0e75988d6eee6fd1e529c86165650f0edc92fb78a61427cab228cbe043ecc993a1f0e56ae9929a737831bb797677b224"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a82b24ed65f151463b8d698075e4d8d23f524fae1285d60e38ee6a41c2641699ed49d486c13cba47e402f2812df03f58baafe08506f82fbe490430d476e27b61"
    $a1="a82b24ed65f151463b8d698075e4d8d23f524fae1285d60e38ee6a41c2641699ed49d486c13cba47e402f2812df03f58baafe08506f82fbe490430d476e27b61"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_prtg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for prtg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cHJ0Z2FkbWlu"
    $a1="cHJ0Z2FkbWlu"
condition:
    ($a0 and $a1)
}

