/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aba2895c13bc1098f75cf2f3c85659a6"
    $a1="aba2895c13bc1098f75cf2f3c85659a6"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70fbbe4a8f84094c4ac0bb719995019639ccd0c0"
    $a1="70fbbe4a8f84094c4ac0bb719995019639ccd0c0"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b500949cca23b9b05a05ebacdbc7a6db4f2557ab1772ced1e77f0a2dadcc9c673ff608dd6e40c69d9eae8dd19e864437"
    $a1="b500949cca23b9b05a05ebacdbc7a6db4f2557ab1772ced1e77f0a2dadcc9c673ff608dd6e40c69d9eae8dd19e864437"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e77421e10a7f364bf641a661edf505d1f6827ceb20d3763a0b85234e"
    $a1="e77421e10a7f364bf641a661edf505d1f6827ceb20d3763a0b85234e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d822c18a499b2734d43f6af8173cb9045e294b2b822d6e1ba10672684b20bf1cf47944c9039021ad7315d10d3dc0aaddff0ed456c0f610c75b1c2f19aabb76c1"
    $a1="d822c18a499b2734d43f6af8173cb9045e294b2b822d6e1ba10672684b20bf1cf47944c9039021ad7315d10d3dc0aaddff0ed456c0f610c75b1c2f19aabb76c1"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9d84719abfe8d1df26ea8413cadbc63c412dd369d94a952f4ce92156a5321cc3"
    $a1="9d84719abfe8d1df26ea8413cadbc63c412dd369d94a952f4ce92156a5321cc3"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8951a61be180c445fc4ee4216cddf3590aa1876d0d9a11337db0f6fcd988ab84b2c603bf1712418830791e0fdd80cee8bd7b97d9cbf511f334c96b0188f63b83"
    $a1="8951a61be180c445fc4ee4216cddf3590aa1876d0d9a11337db0f6fcd988ab84b2c603bf1712418830791e0fdd80cee8bd7b97d9cbf511f334c96b0188f63b83"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83e663743e5126ad075a6418a7a8ea21b39c43f051b8d2348001263ce97d0b7a"
    $a1="83e663743e5126ad075a6418a7a8ea21b39c43f051b8d2348001263ce97d0b7a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e7fec6d7d7bd32542ddecccd474e492642ccb012e34ec136a0cb40d"
    $a1="0e7fec6d7d7bd32542ddecccd474e492642ccb012e34ec136a0cb40d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7ca72859d6fea775126c5b8581ffabfbfb8e8ca0da26bd8da9650ffde5d01d64"
    $a1="7ca72859d6fea775126c5b8581ffabfbfb8e8ca0da26bd8da9650ffde5d01d64"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d55779c15b5623e93f0d37c57f90073b2ee7610531d0a3f56a02909e5297cf2928af2030a78c40ac74cd6329869fc476"
    $a1="d55779c15b5623e93f0d37c57f90073b2ee7610531d0a3f56a02909e5297cf2928af2030a78c40ac74cd6329869fc476"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b726245d7aa6db40f13b117520c88ba2ef50297772e4166c67d92f9f9ad80eef5bb77d85932fcc5c5ca98da4ef0e1bd3cc6fa52594630b9ef0b39c4d4f1fe92b"
    $a1="b726245d7aa6db40f13b117520c88ba2ef50297772e4166c67d92f9f9ad80eef5bb77d85932fcc5c5ca98da4ef0e1bd3cc6fa52594630b9ef0b39c4d4f1fe92b"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ca_process_automation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_process_automation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cGFtYWRtaW4="
    $a1="cGFtYWRtaW4="
condition:
    ($a0 and $a1)
}

