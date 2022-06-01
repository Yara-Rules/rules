/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="79ab945544e5bc017a2317b6146ed3aa"
    $a1="fc5364bf9dbfa34954526becad136d4b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ace893fb2c9553a38a873fb03d0e21a406b351a1"
    $a1="2aeede80be6f6dfc0aa4d1cbd6487e24e27a81be"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="52eef3bb62146d67d3d739b1d86ac74562320aecbddc38184592bdf24a61bf116e838495b0c73ff9aa57f5f9e4c3166d"
    $a1="5f6a2daec364126c664ea8906ad8845e94dacfd4e19debb92c38827b90819bb85e221221af7f7686e99e368a1885f32b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8d072777a0db94c5e8a251d43be84aacd8e5792c2c4632c5e555ada1"
    $a1="5f114c9ea6e15c49b26c228e685b93e2b0ccb2eba49cd2166bc9a189"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="338f820430095e0a1486ad94a8b0d43113a942a24646097a139da23fb58ceb1894c7b7a8e1f5f7e980960cf1c5a0bcb7e80ad901c55c8e829bff04e7626f6569"
    $a1="9c427caa8c8a2cb8b298c007210715886b6622767883d3fbbecd50a4009c06dfc72aca70e73aa1f0d90a9dabc5d5349d450c6c181c43fdec5d6f250cd5ee58e9"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2be4e33aa3e21f6ff7ad144f8fd58228a1cce3b50340b4805ff0c63480eec488"
    $a1="0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99cf80b12673ee366d20c78d4b3c4eedb12f7877e5f8a58dbe60a08ccf9e6ba3cf109751fc8de14c49e7c74487f7b3ba302c6756ca5ebf4e0c24636b573690b0"
    $a1="2815b777b7db227ba97c90a15ec8f2d9bfebe7ccb665bc6e582c4871adb9a7c91c0fe6ec775393f98b9d872cc41ef773ab2f3697bfebd82a43ae13083e695a3a"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="04339265cbd585598dff41824389171eb4cb8bb7c70e6a45975486c2d641fecf"
    $a1="8523939fc72e236fb366f328392ad8616932d5ff9c04b849532dd4d7e5f0a310"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6ca32d3ec254ccc030a275f34dbc98c5c4b80ba402dcfdb7fa32be5f"
    $a1="bcb990d7e2300a10dd151103bc92f4a2ed4ef48e7d0e033504da8cff"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8fa9de94db19eb76b80daa866c54b3ac0221c54fd805dfd9f1bc2fd3e88d1a0d"
    $a1="a06da966ec71d8a337a9ec0d9e8b5cda4a93583524d1a07ab959393712e3dce3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dfbe9d0c6a889ad4c9b8e7c8fad1fe8e4d8d5e162f464c7b06d2ec4cd50774146ceac15015a03d5280fdf53a78c08992"
    $a1="f826e80c0522c109724f73d0ef8856721045b61bb47f08c01a03cfd313517b4f67cbcc8ace91fe414e99bec5b7cddf48"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69b0409c73653ae5f6fcfad7c83e978afb19749488a9333a2c42a90ebe80d823db1d2c9f73c5b37517257b9263d9d3e068f818e18a56379066b1db0a04eb2d32"
    $a1="2137bfab95ff98094e876560af3f171f06c4aac4473943764babf91f7797b37a269e36867c1b9116f9f7c01a0d8f91fd1df82b6093ef827341e1c24217f95fab"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_johnson_controls
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for johnson_controls. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="am9obnNvbg=="
    $a1="Y29udHJvbA=="
condition:
    ($a0 and $a1)
}

