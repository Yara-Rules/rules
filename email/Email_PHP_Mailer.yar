/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/
rule Email_Generic_PHP_Mailer_Script
{
    meta:
        Description ="Generic rule to identify potential emails sent from hacktool mailer scripts"
        Author = "Xylitol <xylitol@temari.fr>"
        date = "2020-05-11"
        // Attempt at getting live urls of HackTool.PHP.SpyMail (kav), 
        // Script.Trojan.PHPMailer (gdata), Trojan.PHP.Mailar (Ikarus)
        // This Yara rule is meant to be run against .eml files
        // May only the challenge guide you
    strings:
 
        // Files, part of php package who can trigger the rules
        // we don't want that if we scan a mixed batch of files.
        $donotwant1 = { FE ED FA CE } // Mach-O binary (32-bit)
        $donotwant2 = { FE ED FA CF } // Mach-O binary (64-bit)
        $donotwant3 = { CE FA ED FE } // Mach-O binary (reverse byte ordering scheme, 32-bit)
        $donotwant4 = { CE FA ED FE } // Mach-O binary (reverse byte ordering scheme, 64-bit)
        $donotwant5 = { 4D 5A 50 00 02 } // Win32 Dynamic Link Library - Borland C/C++
        $donotwant6 = { 53 75 62 6A 65 63 74 3A 20 25 73 } // "Subject: %s"
       
        // Adjust to your need the list of legitimate. You may miss web sent
        // spam through this filter, but we don't need stuff we can't access
        // publicly like cpanel, Roundcube, etc...
        $legit1 = "(https://github.com/PHPMailer/PHPMailer)" // PHPMailer
        $legit2 = "(phpmailer.sourceforge.net)" // PHPMailer
        $legit3 = "X-Mailer: PHPMailer" // PHPMailer
        $legit4 = "SimpleMailInvoker.php" // Swiftmailer
        $legit5 = "X-Mailer: SMF" // Simple Machines Forum
        $legit6 = "X-Mailer: phpBB3" // phpBB3
        $legit7 = "X-Mailer: PHP/Xooit" // Xooit forum
        $legit8 = "X-Mailer: vBulletin" // vBulletin
        $legit9 = "X-Mailer: MediaWiki mailer" // MediaWiki
        $legit10 = "X-Mailer: Drupal" // Drupal
        $legit11 = "X-Mailer: osCommerce Mailer" // osCommerce
        $legit12 = "abuse@mailjet.com" // Message sent by Mailjet
        $legit13 = "class.foxycart.transaction.php" // Foxy Ecommerce
        $legit14 = "User-Agent: Roundcube Webmail" // Roundcube
        $legit15 = "User-Agent: SquirrelMail" // SquirrelMail
        $legit16 = "X-Source: /opt/cpanel/" // mail send from cpanel
        $legit17 = { 58 2D 50 48 50 2D 4F 72 69 67 69 6E 61 74 69 6E 67 2D 53 63 72 69 70 74 3A 20 [1-6] 3A 70 6F 73 74 2E 70 68 70 28 [1-6] 29 } // "X-PHP-Originating-Script: ?:post.php(?)" Might be related to cpanel.
        $legit18 = { 58 2D 50 48 50 2D 53 63 72 69 70 74 3A 20 [3-30] 2F 70 6F 73 74 2E 70 68 70 20 66 6F 72 20 } // "X-PHP-Script: ????/post.php for " Might be related to cpanel.
 
        $eml1 = "From:"
        $eml2 = "To:"
        $eml3 = "Subject:"
   
        $mailer1 = /X-PHP-Originating-Script: ([\w\.]+(.*\.php))?/
        $mailer2 = /X-PHP-Script: ([\w\.\/]+\/(.*\.php))?/
        $mailer3 = /X-PHP-Filename: (\/[\w]+\/(.*\.php))?/
        // $mailer4 = /X-Source-Args: (\/[\w]+\/(.*\.php))?/  // may lead to false positive and unwanted, up to you.
 
    condition:
        not  any of ($donotwant*) and not any of ($legit*)
        and all of ($eml*) and 2 of ($mailer*)
}
