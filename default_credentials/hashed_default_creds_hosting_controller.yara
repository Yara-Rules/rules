/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9916af00ceb9627cef3943f1eab5a6c"
    $a1="514081b0540f9665b2120443ebb4b0fa"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="94a119d167d2857be8b6d86034f2a6e5c14ebf07"
    $a1="d4ebb71fe3932c3955c81052fcfe5022d1c73657"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="495488b92978b8119a98ba215bbcb528d0ca4c017bb4c04a37c31cc21827053c01a5423ab672554445fb8152398090e6"
    $a1="6ed08b0f0a551a0a8cacd730b9f333baa3524b7ecf31b71daeb0d05ff0aea763fb088eaff3a3249fd96398b6f87af989"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62d28bd2046b7858bc01ea09f58aaaff3ca26b8267d7ee6146178a03"
    $a1="a7b9da03f8ca12bcb6129a94229e247dc9b45ffc2ad8553514890cc9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a6a48168431dd674ec59d95e173a01f1be81b1d49f2a286362d738b5464a207ed2f3d00ba7fde401d20a17de6c9707d0eb57c9cf1c157d7dcad141a5bfeeae4a"
    $a1="87df9fc25ad8616fc92a0b8c06f645604e8841db3ee66a9a39a553e5c04755fca9c92207d5182da77f7da4b63169475b1ced857a73af51914f2c7fb4740c3755"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b006a8bff111aa0eb05b4ea80e4148942cbf509ddc4f33598d8d9e4768089b4"
    $a1="9b71dca5b458fd1cc846601ff89e64600a67332a3119787c5299ad26769f9831"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40d6c4ff78e09c19b8e4fe831eae0a8c4ebe0adacf1846b6e2794b74cc91b3215fc57f3339e203e1d5598b9dbe7adad1a25a1642197c832cc737bb086dad6030"
    $a1="999da54e7b8f6c5182d5170beb2b0c0be1bd816ef9e7acd04319d1fa2ec1808c39221fa1ad57aeb6a353f061cbb2aeade6a6acd77fbc1cb010dbbcb63a41b3a0"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1447e741b0280674269b5cb6e87ae612dadab6b692eeb59478189d1a69ae11eb"
    $a1="e1db1db123ea8a818ebfe2496e66bf792cb19243f7e61939a909b3d2379c4875"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59fa82720971619f9f9eb76416c90310263023602d5de4b51c889d6b"
    $a1="5239af35516c3086607068821f44ae464d36935f32f878d7f87ced1a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cf0e6a4583e94fa3479fad7aefd3ef63684423006fa29bd458636b94ee95247"
    $a1="54216db276e2b24855d598ee1bebd7fc545ea567fa393cfe74c5a1f860e18039"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d61c638a0091dea10873164acaa9a2d8efd3efe7fb340bcb73a2a17efa72843fdd44018e27f07e7302be4134f28ded53"
    $a1="1c17b444da39eb31fa36dbcfc23d38d1ac776dc59e042d99be888b766242ff4b79dce5552772f3782529446e4dae45a2"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a24743085ac5bf0875dcf01ad9b6852d98eb41174d490b2ecea4e8e32aa9230e4c9d9ff44440d598b3dfa043c416c0d2c5462c11cb2c39420e9b1c11afd8fc18"
    $a1="0344e65c48c200f3196aa2bbaae313b56b8ed87b1e7de68b08278b82ab5e4ce2e8a8bcfd1f34ffa8255334ef812a5e578ff04a930c9f82af5b6618409724bd02"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_hosting_controller
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for hosting_controller. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWR2V2ViYWRtaW4="
    $a1="YWR2Y29tbTUwMDM0OQ=="
condition:
    ($a0 and $a1)
}

