import "androguard"

rule bankbot_polish_banks : banker
{
    meta:
        author = "Eternal"
        hash0 = "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
        description = "BankBot/Mazain attacking polish banks"
        reference = "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/"
    strings:
        $bank1 = "com.comarch.mobile"
        $bank2 = "eu.eleader.mobilebanking.pekao"
        $bank3 = "eu.eleader.mobilebanking.raiffeisen"
        $bank4 = "pl.fmbank.smart"
        $bank5 = "pl.mbank"
        $bank6 = "wit.android.bcpBankingApp.millenniumPL"
        $bank7 = "pl.pkobp.iko"
        $bank8 = "pl.plus.plusonline"
        $bank9 = "pl.ing.mojeing"
        $bank10 = "pl.bzwbk.bzwbk24"
        $bank11 = "com.getingroup.mobilebanking"
        $bank12 = "eu.eleader.mobilebanking.invest"
        $bank13 = "pl.bph"
        $bank14 = "com.konylabs.cbplpat"
        $bank15 = "eu.eleader.mobilebanking.pekao.firm"

        $s1 = "IMEI"
        $s2 = "/:/"
        $s3 = "p="
        $s4 = "SMS From:"

    condition:
        all of ($s*) and 1 of ($bank*) and 
        androguard.permission(/android.permission.INTERNET/) and 
        androguard.permission(/android.permission.WAKE_LOCK/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.RECEIVE_MMS/) and
        androguard.permission(/android.permission.READ_SMS/) and
        androguard.permission(/android.permission.RECEIVE_SMS/)
}
