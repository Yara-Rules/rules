/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

rule extortion_email
{
  meta:
    author = "milann shrestha <Twitter - @x0verhaul>"
		description = "Detects the possible extortion scam on the basis of subjects and keywords"
		data = "12th May 2020"

	strings:
	  $eml1="From:"
    $eml2="To:"
    $eml3="Subject:"
		
		// Common Subjects scammer keep for luring the targets 
    $sub1 = "Hackers know password from your account."
    $sub2 = "Security Alert. Your accounts were hacked by a criminal group."
    $sub3 = "Your account was under attack! Change your credentials!"
    $sub4 = "The decision to suspend your account. Waiting for payment"
    $sub5 = "Fraudsters know your old passwords. Access data must be changed."
    $sub6 = "Your account has been hacked! You need to unlock it."
    $sub7 = "Be sure to read this message! Your personal data is threatened!"
    $sub8 = "Password must be changed now."

		// Keywords used for extortion
    $key1 = "BTC" nocase
    $key2 = "Wallet" nocase
    $key3 = "Bitcoin" nocase
    $key4 = "hours" nocase
    $key5 = "payment" nocase
    $key6 = "malware" nocase
    $key = "bitcoin address" nocase
    $key7 = "access" nocase
    $key8 = "virus" nocase

	condition: 
    all of ($eml*) and
    any of ($sub*) and
    any of ($key*)
}		
