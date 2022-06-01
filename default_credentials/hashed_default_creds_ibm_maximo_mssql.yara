/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cfc38813ee2f95d252773707d75466f8"
    $a1="cfc38813ee2f95d252773707d75466f8"
    $a2="bf090d435d40fdda5140c4ec65670344"
    $a3="bf090d435d40fdda5140c4ec65670344"
    $a4="951ac5658efd8732a33c6e2fc568856a"
    $a5="951ac5658efd8732a33c6e2fc568856a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6ea52614215568407593a2ebfbffe7609323f537"
    $a1="6ea52614215568407593a2ebfbffe7609323f537"
    $a2="3e86a541edbac4c26942b2432d02afdd590895e1"
    $a3="3e86a541edbac4c26942b2432d02afdd590895e1"
    $a4="c023aa5bf8e4e57631de80dd3f3748ce6ddaf97f"
    $a5="c023aa5bf8e4e57631de80dd3f3748ce6ddaf97f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dabe7e42cb76b9ce673f2830d09dae787a250d6e7d48a32d82e9784271f44f62c3e780cdd2c703959c9abc276afeaaeb"
    $a1="dabe7e42cb76b9ce673f2830d09dae787a250d6e7d48a32d82e9784271f44f62c3e780cdd2c703959c9abc276afeaaeb"
    $a2="483b7c82acf22a47e5ced3d4cdeed9083e3aee2ca5b8432f5aa46f434ec6c376bebb4a1dddcb97dd93d75d1bf001651e"
    $a3="483b7c82acf22a47e5ced3d4cdeed9083e3aee2ca5b8432f5aa46f434ec6c376bebb4a1dddcb97dd93d75d1bf001651e"
    $a4="24bd64f280f3a90a64d2f41964a086dab5ffd0f536a8028c7c6d143abf3f8a5774099de9b7fc318b31ae1e7547d04b4b"
    $a5="24bd64f280f3a90a64d2f41964a086dab5ffd0f536a8028c7c6d143abf3f8a5774099de9b7fc318b31ae1e7547d04b4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="348b2cddbab7d2c685cd8a9c0f33984b8cde2508bc04538712dc3a27"
    $a1="348b2cddbab7d2c685cd8a9c0f33984b8cde2508bc04538712dc3a27"
    $a2="c9974882c14290bd2d91be2c5aa9b8114e4c952066bd143274305ba7"
    $a3="c9974882c14290bd2d91be2c5aa9b8114e4c952066bd143274305ba7"
    $a4="be9304d5db0672df72ff3615a2e7dc97125d9615ff1236cc888c0997"
    $a5="be9304d5db0672df72ff3615a2e7dc97125d9615ff1236cc888c0997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9db4397def3c048dcf39880258c8cfa459470a21d910dcf83000db47e0b21f263e6a2f3c3b655d01540d4667db3ec3a189166890bb1a3d5d0a3fe174b89dbc5c"
    $a1="9db4397def3c048dcf39880258c8cfa459470a21d910dcf83000db47e0b21f263e6a2f3c3b655d01540d4667db3ec3a189166890bb1a3d5d0a3fe174b89dbc5c"
    $a2="62884f1502a3ab60eb54dec90857eb9d6eeece3fe1367808eb884809786975b497c1c761f410beb09aaea0431ee8b8399c787395bf22211aa8cdfb21ad7f142c"
    $a3="62884f1502a3ab60eb54dec90857eb9d6eeece3fe1367808eb884809786975b497c1c761f410beb09aaea0431ee8b8399c787395bf22211aa8cdfb21ad7f142c"
    $a4="f29e81adee90f4c99afd29094593164a88f122f6f20ec58d06ad1c18a9c4a97410b267cf77a418da968c45c1283d77111af43a3b53884ff60edeb9bc1ca2cef8"
    $a5="f29e81adee90f4c99afd29094593164a88f122f6f20ec58d06ad1c18a9c4a97410b267cf77a418da968c45c1283d77111af43a3b53884ff60edeb9bc1ca2cef8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a11bf1f3c7c86c71f1b756db5d660aa162636bec4bbd9225e7d47dcf8929d7f7"
    $a1="a11bf1f3c7c86c71f1b756db5d660aa162636bec4bbd9225e7d47dcf8929d7f7"
    $a2="9ad40ad5ebbb4ee39a4fcc4ca4814346072a42210529f279a7f8458aac6d51ed"
    $a3="9ad40ad5ebbb4ee39a4fcc4ca4814346072a42210529f279a7f8458aac6d51ed"
    $a4="bf352bf9f21cefd23afea884311d92a7f1c3d33039615f58e90e273937f31c8a"
    $a5="bf352bf9f21cefd23afea884311d92a7f1c3d33039615f58e90e273937f31c8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ab91910ec29db734d2fee5a2a71abb82abde4395aaa0ba8255169deb665f520f93b069c06fe983dafb922c87dab694d8075de324c1d8a53414965e6753b716a8"
    $a1="ab91910ec29db734d2fee5a2a71abb82abde4395aaa0ba8255169deb665f520f93b069c06fe983dafb922c87dab694d8075de324c1d8a53414965e6753b716a8"
    $a2="50ba0a14118047cc3d2e4693cb1f1c7737d0b0bd0015fdd0c514c7c07d5b5169905034ffa5856161281e9a2f4ac81728d1c402f7e38f995714ad42e9d06c9fac"
    $a3="50ba0a14118047cc3d2e4693cb1f1c7737d0b0bd0015fdd0c514c7c07d5b5169905034ffa5856161281e9a2f4ac81728d1c402f7e38f995714ad42e9d06c9fac"
    $a4="3be298bf52d69efabc23e925acbd63425fa77812b7accb18349b6d9c2ada00e3afa5473c6e396ed682293c7ae5fb750f87603bc03226c2a16944d91e7c0d2715"
    $a5="3be298bf52d69efabc23e925acbd63425fa77812b7accb18349b6d9c2ada00e3afa5473c6e396ed682293c7ae5fb750f87603bc03226c2a16944d91e7c0d2715"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1cb355815059e81b5e3964ade8c91f169bd502f642b8644c25cce562600735ab"
    $a1="1cb355815059e81b5e3964ade8c91f169bd502f642b8644c25cce562600735ab"
    $a2="cb9a3a73a21b1978685a4d332d9ed43042d373b90d961afe5ec5ad7967b1d81e"
    $a3="cb9a3a73a21b1978685a4d332d9ed43042d373b90d961afe5ec5ad7967b1d81e"
    $a4="f64891e4a7b949d2cb83ea124d0a77622a9a134b433204cef38addfb777b43ff"
    $a5="f64891e4a7b949d2cb83ea124d0a77622a9a134b433204cef38addfb777b43ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8f18c1b3d6556353ebccf1e5177d2e27850e33fd5a9d946b2caa36d3"
    $a1="8f18c1b3d6556353ebccf1e5177d2e27850e33fd5a9d946b2caa36d3"
    $a2="65fdede991ebecdd0b1dc7ebd9fe0314aaef26dcc5dd992b87560208"
    $a3="65fdede991ebecdd0b1dc7ebd9fe0314aaef26dcc5dd992b87560208"
    $a4="afb0ac8f76af5f0b4524aa517b4c76825927e4c0cc5f664522bc2c1c"
    $a5="afb0ac8f76af5f0b4524aa517b4c76825927e4c0cc5f664522bc2c1c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a468ba8adb0a12b9d9c6edfa7351c2d25f7878641950049ba9c98d7e36744ac3"
    $a1="a468ba8adb0a12b9d9c6edfa7351c2d25f7878641950049ba9c98d7e36744ac3"
    $a2="bf45215dac25fcfa0b851a363c3021abd7362a3ce668ca26484c0133e260f35d"
    $a3="bf45215dac25fcfa0b851a363c3021abd7362a3ce668ca26484c0133e260f35d"
    $a4="139731e7de41debe77d701e52a9ef57b0af0144dbf91d3b8c96cc0dc81df3cab"
    $a5="139731e7de41debe77d701e52a9ef57b0af0144dbf91d3b8c96cc0dc81df3cab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9b1c08f26b202b22c4a215f4d7d719f4419e9b15d443c6d8274d06d2ee632e3316c359bf76db225bd67ae12c70ab781e"
    $a1="9b1c08f26b202b22c4a215f4d7d719f4419e9b15d443c6d8274d06d2ee632e3316c359bf76db225bd67ae12c70ab781e"
    $a2="95ac6d9519cedfc9029373e4edf21d87ff8a9dd2e9fe2741d67773919c380f67d65b662bd6edb751e6f35c622e77cd22"
    $a3="95ac6d9519cedfc9029373e4edf21d87ff8a9dd2e9fe2741d67773919c380f67d65b662bd6edb751e6f35c622e77cd22"
    $a4="ebe28e7a50c5089dc2af3a534e26fbf428428d6a7de0ee81693c7db657968a1d323f0761636874d8e079802b4ee33614"
    $a5="ebe28e7a50c5089dc2af3a534e26fbf428428d6a7de0ee81693c7db657968a1d323f0761636874d8e079802b4ee33614"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a1b35a7ed55dea5324acd219a7d97910ea2b3b34312010a9f1f000a213794a1ba2f869bf31d62614442bbbda43c98044396c721445042e587e825c423157198"
    $a1="4a1b35a7ed55dea5324acd219a7d97910ea2b3b34312010a9f1f000a213794a1ba2f869bf31d62614442bbbda43c98044396c721445042e587e825c423157198"
    $a2="2daf88c1bd1aea257668ad4c52c471e6787153cfeed5a78a5e5d9b300c66b016db42da1ea3c69d55a1a02c9089ecd492d249974c70c9051997f47e506613848f"
    $a3="2daf88c1bd1aea257668ad4c52c471e6787153cfeed5a78a5e5d9b300c66b016db42da1ea3c69d55a1a02c9089ecd492d249974c70c9051997f47e506613848f"
    $a4="da7f823046c1dde0ccaf03ee946c36519cf188f764fc0ee8f5fd688791c5ed3474018ed06105f31ff50a265daa71d3bc49bc5ce50afd8c60cb811d13313160d1"
    $a5="da7f823046c1dde0ccaf03ee946c36519cf188f764fc0ee8f5fd688791c5ed3474018ed06105f31ff50a265daa71d3bc49bc5ce50afd8c60cb811d13313160d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_ibm_maximo_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ibm_maximo_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWF4YWRtaW4="
    $a1="bWF4YWRtaW4="
    $a2="bWF4cmVn"
    $a3="bWF4cmVn"
    $a4="bXhpbnRhZG0="
    $a5="bXhpbnRhZG0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

