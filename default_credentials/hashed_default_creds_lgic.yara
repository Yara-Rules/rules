/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0fac94723fc1210519a9ff1003238030"
    $a1="0fac94723fc1210519a9ff1003238030"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7a0d288e3bdbe71a0578ee5dbc3c381f22b0087"
    $a1="c7a0d288e3bdbe71a0578ee5dbc3c381f22b0087"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f02a6aa40a61e156fb4d174dff507f9426fd59e0059a6103d5973a3c51b372ae04f058215ba22a933e8d504efa1ba099"
    $a1="f02a6aa40a61e156fb4d174dff507f9426fd59e0059a6103d5973a3c51b372ae04f058215ba22a933e8d504efa1ba099"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="839f9f9fb767e4b37067b4a6da6b95fc85cf8a1d9f3b61eb66e31e55"
    $a1="839f9f9fb767e4b37067b4a6da6b95fc85cf8a1d9f3b61eb66e31e55"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b5a201d6e6a4afbf195ce69e50de17ea6e231c94283972964de52500e8492c622e010fdea2111494ff13b44d957a5b5789556826135b29c88e4c910713fe65bd"
    $a1="b5a201d6e6a4afbf195ce69e50de17ea6e231c94283972964de52500e8492c622e010fdea2111494ff13b44d957a5b5789556826135b29c88e4c910713fe65bd"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9c9fcc48e1ad8f060ac2d5cccf61a40ac77cad046e80fd6f1e629a394409cacc"
    $a1="9c9fcc48e1ad8f060ac2d5cccf61a40ac77cad046e80fd6f1e629a394409cacc"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="80cb914358dfb5866c37c3ebc7ec62d34900e4a3ca85222c0cb6dc5ddf345b64e030fa55a15ebed6a2cea3c76fe16d7599fbd892a03c102afe373601382f9957"
    $a1="80cb914358dfb5866c37c3ebc7ec62d34900e4a3ca85222c0cb6dc5ddf345b64e030fa55a15ebed6a2cea3c76fe16d7599fbd892a03c102afe373601382f9957"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bb494051d48e5fa640b097433e30f36fccb745a1b41ca16e4d40b76ee88df222"
    $a1="bb494051d48e5fa640b097433e30f36fccb745a1b41ca16e4d40b76ee88df222"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21fad657b40e26646485684ae64179996ef5da7694eb4576aaba5ecf"
    $a1="21fad657b40e26646485684ae64179996ef5da7694eb4576aaba5ecf"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6d8de4a53ba7351cd6029e9aab427b36c1f72af123384912dd76802e7bd60b38"
    $a1="6d8de4a53ba7351cd6029e9aab427b36c1f72af123384912dd76802e7bd60b38"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1967cae834f6765af958ee9270e42c8adb97d49eb7896bece0b143313ddd0ea1e1e07f8b139166e32bc807e0f48c5ede"
    $a1="1967cae834f6765af958ee9270e42c8adb97d49eb7896bece0b143313ddd0ea1e1e07f8b139166e32bc807e0f48c5ede"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="63fac862d7b18721e6de9e64b9b24ad54d4c84b4c7f5f42b75ae1aa005404b8df546e6344d984303bc8d6ce15cb2f8bd4662cc0a496e1ddd4e439c08085e6930"
    $a1="63fac862d7b18721e6de9e64b9b24ad54d4c84b4c7f5f42b75ae1aa005404b8df546e6344d984303bc8d6ce15cb2f8bd4662cc0a496e1ddd4e439c08085e6930"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_lgic
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lgic. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TFItSVNETg=="
    $a1="TFItSVNETg=="
condition:
    ($a0 and $a1)
}

