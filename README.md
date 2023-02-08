# smartcard
basic EMV smart card reader (contact only).  
The script (main.py) selects the application, initiate its processing and reads public data.

#### dependencies
1. https://pypi.org/project/pyscard/
2. https://github.com/knovichikhin/pyemv - I've took only a single unit from it to work with TLV data objects (tlv.py). The file contains modifications and put into into the project for convenience purposes. Check pyemv fork to see the actual changes

## application selection
the script attempts to read the PSE (Payment System Environment) and, when available, reads and lists the application(s) from it. If there is just a single application available it selected automatically. When there are more that one applications present on the chip, the script prompts the user to enter the application number to proceed with.  
If there is no PSE available the script attempts to select Visa (A0000000031010) and Mastercard (A0000000041010) AIDs 
```
def ApplicationSelection()
returns 
  - content of Tag 9F38 - PODL (Processing Options Data Object List)
  - content of Tag 9F4D - LogEntry
```
## initiate application processing
the scripts checks the PDOL passed as a parameter and depending on its content constructs the GPO (Get Processing Options) command. If PDOL is empty, the GPO generated without parameters. When PDOL contains list of objects to be used in GPO, the script constructs the data object using the predefined list of parameters defined in TERMCONFIG dictionary.
```
def InitiateApplicationProcessing(pdol)
returns
  - AFL (Application File Locator)
```
### read application data
reads the data from the records defined in AFL
```
def ReadApplicationData(afl)
```


### sample output
```
['Broadcom Corp Contacted SmartCard 0']
ATR: 3B EF 00 00 81 31 FE 45 43 44 33 69 09 00 00 00 20 20 20 20 20 20 00 B0
* SELECT 1PAY.SYS.DDF01
>c-apdu: 00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31
sw 90 00
<r-apdu: 6F 20 84 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 A5 0E 88 01 01 5F 2D 04 64 65 65 6E 9F 11 01 01
=
6F File Control Information (FCI) Template
   84 Dedicated File (DF) Name
      315041592E5359532E4444463031 (1PAY.SYS.DDF01)
   A5 File Control Information (FCI) Proprietary Template
      88 Short File Identifier (SFI)
         01 
      5F2D Language Preference
         6465656E (deen)
      9F11 Issuer Code Table Index
         01 
=
PSE SFI = 1
* READ RECORD: SFI 1, record 1
>c-apdu: 00 B2 01 0C
sw 90 00
<r-apdu: 70 27 61 25 4F 07 A0 00 00 00 04 10 10 50 0A 4D 61 73 74 65 72 43 61 72 64 9F 12 0A 4D 61 73 74 65 72 63 61 72 64 87 01 01
=
70 READ RECORD Response Message Template
   61 Application Template
      4F Application Identifier (ADF Name)
         A0000000041010 
      50 Application Label
         4D617374657243617264 (MasterCard)
      9F12 Application Preferred Name
         4D617374657263617264 (Mastercard)
      87 Application Priority Indicator
         01 
=

* List of applications
AID: A0000000041010 (MasterCard), priority: 01

* SELECT A0000000041010
>c-apdu: 00 A4 04 00 07 A0 00 00 00 04 10 10
sw 90 00
<r-apdu: 6F 40 84 07 A0 00 00 00 04 10 10 A5 35 50 0A 4D 61 73 74 65 72 43 61 72 64 9F 11 01 01 9F 12 0A 4D 61 73 74 65 72 63 61 72 64 5F 2D 04 64 65 65 6E 87 01 01 9F 38 03 9F 40 05 BF 0C 05 9F 4D 02 0B 0A
=
6F File Control Information (FCI) Template
   84 Dedicated File (DF) Name
      A0000000041010 
   A5 File Control Information (FCI) Proprietary Template
      50 Application Label
         4D617374657243617264 (MasterCard)
      9F11 Issuer Code Table Index
         01 
      9F12 Application Preferred Name
         4D617374657263617264 (Mastercard)
      5F2D Language Preference
         6465656E (deen)
      87 Application Priority Indicator
         01 
      9F38 Processing Options Data Object List (PDOL)
         9F4005 
      BF0C File Control Information (FCI) Issuer Discretionary Data
         9F4D Log Entry
            0B0A 
=
PDOL: 9F4005
* GET PROCESSING OPTIONS
>c-apdu: 80 A8 00 00 07 83 05 F0 00 F0 A0 01
sw 90 00
<r-apdu: 77 0A 82 02 18 00 94 04 18 01 02 00
=
77 Response Message Template Format 2
   82 Application Interchange Profile (AIP)
      1800 
   94 Application File Locator (AFL)
      18010200 
=
AFL: 18010200
* Read application data
* READ RECORD: SFI 3, record 1
>c-apdu: 00 B2 01 1C
sw 90 00
<r-apdu: 70 81 8C 9F 42 02 09 78 5F 25 03 15 08 01 5F 24 03 18 08 31 5A 08 51 00 00 00 00 00 00 59 5F 34 01 00 9F 07 02 FF 00 8C 27 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 35 01 9F 45 02 9F 4C 08 9F 34 03 9F 21 03 9F 7C 14 8D 0C 91 0A 8A 02 95 05 9F 37 04 9F 4C 08 8E 0E 00 00 00 00 00 00 00 00 42 03 1E 03 1F 03 9F 0D 05 B0 50 9C 88 00 9F 0E 05 00 00 00 00 00 9F 0F 05 B0 70 9C 98 00 5F 28 02 02 80 9F 44 01 02
=
70 READ RECORD Response Message Template
   9F42 Currency Code, Application
      0978 
   5F25 Application Effective Date (YYMMDD)
      150801 
   5F24 Application Expiration Date (YYMMDD)
      180831 
   5A Application Primary Account Number (PAN)
      5100000000000059 
   5F34 Application Primary Account Number (PAN) Sequence Number (PSN)
      00 
   9F07 Application Usage Control (AUC)
      FF00 
   8C Card Risk Management Data Object List 1 (CDOL1)
      9F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F21039F7C14 
   8D Card Risk Management Data Object List 2 (CDOL2)
      910A8A0295059F37049F4C08 
   8E Cardholder Verification Method (CVM) List
      000000000000000042031E031F03 
   9F0D Issuer Action Code - Default
      B0509C8800 
   9F0E Issuer Action Code - Denial
      0000000000 
   9F0F Issuer Action Code - Online
      B0709C9800 
   5F28 Issuer Country Code
      0280 
   9F44 Currency Exponent, Application
      02 
=
* READ RECORD: SFI 3, record 2
>c-apdu: 00 B2 02 1C
sw 90 00
<r-apdu: 70 30 9F 08 02 00 02 5F 20 11 48 65 6C 6C 6F 20 57 6F 72 6C 64 20 20 20 20 20 20 57 10 51 00 00 00 00 00 00 59 D1 80 82 01 00 00 00 00 5F 30 02 02 01
=
70 READ RECORD Response Message Template
   9F08 Application Version Number
      0002 
   5F20 Cardholder Name
      48656C6C6F20576F726C64202020202020 (Hello World      )
   57 Track 2 Equivalent Data
      5100000000000059D180820100000000 
   5F30 Service Code
      0201 
=
* Reading Log Entry
Log entry SFI 11, number of entries 10
* Get log format
>c-apdu: 80 CA 9F 4F
sw 90 00
<r-apdu: 9F 4F 1A 9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36 02 9F 52 06 DF 3E 01 9F 21 03 9F 7C 14

* READ RECORD: SFI 11, record 1
>c-apdu: 00 B2 01 5C
sw 90 00
<r-apdu: 00 00 00 00 02 16 99 01 91 17 08 30 00 36 20 00 01 24 00 00 00 14 38 17 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 1
9F27 (Cryptogram Information Data (CID)) - 00
9F02 (Amount, Authorised (Numeric)) - 000000021699
5F2A (Transaction Currency Code) - 0191
9A (Transaction Date (YYMMDD)) - 170830
9F36 (Application Transaction Counter (ATC)) - 0036
9F52 (Card Verification Results (CVR)) - 200001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 143817
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 2
>c-apdu: 00 B2 02 5C
sw 90 00
<r-apdu: 00 00 00 00 02 16 99 01 91 17 08 30 00 35 20 00 01 24 00 00 00 14 37 51 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 2
9F27 (Cryptogram Information Data (CID)) - 00
9F02 (Amount, Authorised (Numeric)) - 000000021699
5F2A (Transaction Currency Code) - 0191
9A (Transaction Date (YYMMDD)) - 170830
9F36 (Application Transaction Counter (ATC)) - 0035
9F52 (Card Verification Results (CVR)) - 200001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 143751
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 3
>c-apdu: 00 B2 03 5C
sw 90 00
<r-apdu: 40 00 00 00 00 20 00 09 78 16 11 11 00 34 60 10 01 22 00 00 00 12 52 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 3
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000002000
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 161111
9F36 (Application Transaction Counter (ATC)) - 0034
9F52 (Card Verification Results (CVR)) - 601001220000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 125243
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 4
>c-apdu: 00 B2 04 5C
sw 90 00
<r-apdu: 40 00 00 00 00 50 00 09 78 16 11 01 00 33 60 10 01 22 00 00 00 11 09 58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 4
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000005000
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 161101
9F36 (Application Transaction Counter (ATC)) - 0033
9F52 (Card Verification Results (CVR)) - 601001220000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 110958
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 5
>c-apdu: 00 B2 05 5C
sw 90 00
<r-apdu: 40 00 00 00 00 56 50 09 78 16 06 12 00 31 60 10 01 22 00 00 00 09 23 26 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 5
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000005650
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 160612
9F36 (Application Transaction Counter (ATC)) - 0031
9F52 (Card Verification Results (CVR)) - 601001220000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 092326
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 6
>c-apdu: 00 B2 06 5C
sw 90 00
<r-apdu: 40 00 00 00 00 11 50 09 78 16 06 05 00 30 60 10 01 24 00 00 00 14 55 27 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 6
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000001150
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 160605
9F36 (Application Transaction Counter (ATC)) - 0030
9F52 (Card Verification Results (CVR)) - 601001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 145527
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 7
>c-apdu: 00 B2 07 5C
sw 90 00
<r-apdu: 40 00 00 00 00 11 50 09 78 16 06 04 00 2F 60 10 01 24 00 00 00 10 02 33 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 7
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000001150
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 160604
9F36 (Application Transaction Counter (ATC)) - 002F
9F52 (Card Verification Results (CVR)) - 601001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 100233
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 8
>c-apdu: 00 B2 08 5C
sw 90 00
<r-apdu: 40 00 00 00 02 50 00 02 03 16 05 21 00 2E 60 10 01 24 00 00 00 10 39 39 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 8
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000025000
5F2A (Transaction Currency Code) - 0203
9A (Transaction Date (YYMMDD)) - 160521
9F36 (Application Transaction Counter (ATC)) - 002E
9F52 (Card Verification Results (CVR)) - 601001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 103939
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 9
>c-apdu: 00 B2 09 5C
sw 90 00
<r-apdu: 40 00 00 00 10 00 00 06 43 16 05 12 00 2D 60 10 01 24 00 00 00 14 38 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 9
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000100000
5F2A (Transaction Currency Code) - 0643
9A (Transaction Date (YYMMDD)) - 160512
9F36 (Application Transaction Counter (ATC)) - 002D
9F52 (Card Verification Results (CVR)) - 601001240000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 143807
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

* READ RECORD: SFI 11, record 10
>c-apdu: 00 B2 0A 5C
sw 90 00
<r-apdu: 40 00 00 00 00 03 00 09 78 16 03 28 00 2C 60 10 01 22 00 00 00 12 27 27 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
* Entry 10
9F27 (Cryptogram Information Data (CID)) - 40
9F02 (Amount, Authorised (Numeric)) - 000000000300
5F2A (Transaction Currency Code) - 0978
9A (Transaction Date (YYMMDD)) - 160328
9F36 (Application Transaction Counter (ATC)) - 002C
9F52 (Card Verification Results (CVR)) - 601001220000
DF3E (Unknown) - 00
9F21 (Transaction Time) - 122727
9F7C (Customer Exclusive Data (CED)) - 0000000000000000000000000000000000000000

```
