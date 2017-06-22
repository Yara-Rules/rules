rule Fake_it_maintenance_bulletin : mail
{
  meta:
		Author = "Tyler Linne <@InfoSecTyler>"
		Description ="Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange"
  strings:
    $eml_1="From:"
    $eml_2="To:"
    $eml_3="Subject:"
    $subject1={49 54 20 53 45 52 56 49 43 45 20 4d 61 69 6e 74 65 6e 61 6e 63 65 20 42 75 6c 6c 65 74 69 6e [1-20]} //Range is for varying date of "notification"
    $subject2={44 45 53 43 52 49 50 54 49 4f 4e 3a 20 53 65 72 76 65 72 20 55 70 67 72 61 64 65 20 4d 61 69 6e 74 65 6e 61 6e 63 65 [1-20]} //Range is for server name varriation 
    $body1="Message prompted from IT Helpdesk Support" nocase
    $body2="We are currently undergoing server maintenance upgrade" nocase
    $body3="Upgrade is to improve our security and new mail experience" nocase
    $body4="As an active Outlook user, you are kindly instructed  to upgrade your mail account by Logging-in the below link" nocase
    $body5="Sign in to Access Upgrade" nocase
    $body6="Our goal is to provide excellent customer service" nocase
    $body7="Thanks,/n OWA - IT Helpdesk Service" nocase

  condition:
    All of ($eml_*)and
    1 of ($subject*) and
    4 of ($body*) 
}
