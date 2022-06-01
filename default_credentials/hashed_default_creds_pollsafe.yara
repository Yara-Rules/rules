/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ca39be1d5df0b6913c20f05ea1ac59b8"
    $a1="371b09d93ca01e09a42fbd5a2a423f8e"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0f04837e5b1587480bd5dd2565daf753c4dc111f"
    $a1="3c1c6889a3ee92b50e066ab90996ea34f7f8189b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="00a996752c972e54a87c53b4427c0d714ed6dab7d232d9c62a679dfe92bbe69a3e3eaf593e1a78813da750aafba2a61b"
    $a1="50aa1cd8d34b822285163a3c43124ba44a2ef47c10ce090fb42dc1aa556d861e75ddf343a13f0b630b6de4e78dc8ea07"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0f23cb5454988be5a11c868d63c28415f3406865c7e537fbcb5900bb"
    $a1="6b8dff8ad3499917f23fa2ccd73bd2dc2bc23684150f64e30df2996f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a61ef940744863cce48f228bbe836f0689fdd32615064befbf7f70fb42464f5ad7a5f2121159ada672875d3199c3d02874399986a5d4d24527193a0684de372"
    $a1="6e67f8dbbbe2b9b302250b570cb2099e0f937f7139544800e84719e545fc6bb3b6f21d1eba6ee7fc6737535b500a0bf3752c12015b4e80454ceeaf4ba08897f1"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20bd5a6217e1d0b1a819794f3ff85c5f5d7380b6c6e734799e1be5d42b6b7cac"
    $a1="8f0ad38086075b37a535d141659ca0d0c98cee5987db82a325d3772e4dee2ee1"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bc06ca99fc895f454b021a1413c304f0b81f0b0a53285cc185f23d2eef4d6b31cf50b64fe8eceac3c5cfe729b7b1d1f0e6eef0ee08cff30788317adada1362f0"
    $a1="d147bb827edf0b78c11b39f69d871a5025db05a5ccf97d86fd967842068ade17f4b84c3b0a7740216c077675e73b54784bf9f421d3213fedf2d470a10d8ba6f5"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e362c8c3cdff8ae96a6cab56544ca0692349dc9c88a54855f042df1fc9190b4"
    $a1="ecb70a7762ae4de51ade8691dbd617e30da39e05a2a739ff3a48aeeb524eed25"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4d3bd2f9b51c02b58bd735ce9668d87f7959bd1ed4d9cd068ecefce9"
    $a1="0ba629e1a8af632e9ff3f4fbc8b08b4fed373d45c212205070baa62f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a01a25d4573adb2a60d5252e428f508fe5f23657d33c53a6800865b0c3cccbb9"
    $a1="6dd7ef0fc7657da7b51d4aab5ff3850733c621ee52f6c81a92d554cc3f12cd2a"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="259ef1392fbe43c5db3ee66e3762eb8dc6bd22fe098d270bca99b047c3a46239d3333b8125349b82897d25d587cd2360"
    $a1="a680be5b6406fe4cd964087f34e5858cd7e892d859118f84e27c4f88321f20e2700e666aa4359b61f74090fa998bfeea"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0f4637af3ed6d5e286930d703f36e5b2ed9f729ddfb02c2bcb8fd09f475689ec6d473a04ae6958f1440f323bc627a0447504505207d1cf81c2ef276f05b63d1e"
    $a1="4bc96e21751e17f915f76453074300345275b86a1ed9eb7d6f06a8f2a07596c0f35445b0bc90e5d52e6aac1635653d89d23b73120462822078794c226a59d07d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_pollsafe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pollsafe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="U01EUg=="
    $a1="U0VDT05EQVJZ"
condition:
    ($a0 and $a1)
}

