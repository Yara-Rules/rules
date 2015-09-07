# Project

This project covers the need of a group of IT Security Researches to have a single repository where different Yara signatures are compiled, classified and kept as up to date as possible, and begin as an open source community for collecting Yara rules. Our Yara ruleset is under the GNU-GPLv2 license and open to any user or organization, as long as you use it under this license.

Yara is being increasingly used, but knowledge about the tool and its usage is dispersed in many different places. Yara Rules project aims to be the meeting point for Yara users, gathering together a ruleset as complete as possible thus providing users a quick way to get Yara ready for usage.

We hope this project is useful for the Security Community and all Yara Users, and are looking forward to your feedback. Join this community by subscribing to our mailing list.

# Contribute

If you’re interested in sharing your Yara rules with us and the Security Community, you can join our mailing list, send a message to our Twitter account or send a pull request here.

Twitter account: https://twitter.com/yararules

Mail list : http://list.yararules.com/mailman/listinfo/yararules.com.signatures

# Requirements

Yara **version 3.0** or higher is required for most of the rules to work. This is mainly due to the use of the "pe" module introduced in that version.

You can check your installed version with `yara -v`

The available packages in Ubuntu 14.04 LTS default repositories are too old.  You can install from source or use the packages available in the [Remnux repository](https://launchpad.net/~remnux/+archive/ubuntu/stable).

# Categories

## malware 

In this section you will find Yara rules specialised on the indentification of well-known malware.

## mobile

In this section you will find Yara rules specialised on the indentification of well-known mobile malware.

Many rules in this section use Androguard module developed by people at https://koodous.com/. 

You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara

## hackingtools

In this section you will find Yara rules specialised on the identification of
well-known hackingtools like DuBrute, Wineggdrop Portscanner, etc.

## rulesets

the rulesets directory contains the following rulesets:

### Antidebug/AntiVM

In this section you will find Yara Rules aimed to detect anti debug and anti virtualization techniques used by malware to evade automated analyisis.

### Crypto

In this section you will find Yara rules aimed to detect the existence of cryptographic algoritms.

### Malicious Documents

In this section you will find Yara Rules to be used with documents to find if they have been crafted to leverage malicious code.

### Packers

In this section you will find Yara Rules aimed to detect well-known sofware packers, that can be used by malware to hide itself.

# ToDo

* sorting malware [ELF/Windows/OS X/MIPS/...]
* adding more categories [Possible unwanted Application (PUA)/..]

# Contact 

Webpage: http://yararules.com

Twitter account: https://twitter.com/yararules

Mail list : http://list.yararules.com/mailman/listinfo/yararules.com.signatures
