/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule FUDCrypter
{
    meta:
        description = "Detects unmodified FUDCrypt samples"
        reference = "https://github.com/gigajew/FudCrypt/"
        author = "https://github.com/hwvs"
        last_modified = "2019-11-21"

    strings:
        $ = "OcYjzPUtJkNbLOABqYvNbvhZf" wide ascii
        $ = "gwiXxyIDDtoYzgMSRGMckRbJi" wide ascii
        $ = "BclWgISTcaGjnwrzSCIuKruKm" wide ascii
        $ = "CJyUSiUNrIVbgksjxpAMUkAJJ" wide ascii
        $ = "fAMVdoPUEyHEWdxQIEJPRYbEN" wide ascii
        $ = "CIGQUctdcUPqUjoucmcoffECY" wide ascii
        $ = "wcZfHOgetgAExzSoWFJFQdAyO" wide ascii
        $ = "DqYKDnIoLeZDWYlQWoxZnpfPR" wide ascii
        $ = "MkhMoOHCbGUMqtnRDJKnBYnOj" wide ascii
        $ = "sHEqLMGglkBAOIUfcSAgMvZfs" wide ascii
        $ = "JtZApJhbFAIFxzHLjjyEQvtgd" wide ascii
        $ = "IIQrSWZEMmoQIKGuxxwoTwXka" wide ascii

    condition:
        1 of them
}
