from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toASCIIBytes, toASCIIString, toBytes

import string

import tlv
from tags import TAGS

# these are actually indices of items in byte array of APDU command
P1 = 2
P2 = 3

# APDU tempalates
SELECT = [0x00, 0xA4, 0x04, 0x00]
GET_RESPONSE = [0x00, 0xC0, 0x00, 0x00]
READ_RECORD = [0x00, 0xB2, 0x00, 0x00]   # default P1 and P2
GPO = [0x80, 0xA8, 0x00, 0x00]
GET_DATA = [0x80, 0xCA, 0x00, 0x00]   # default P1 and P2

# data for GPO
TERMCONFIG = {
    "9F40": "F000F0A001",
    "9F33": "E0F0C8",
    "9F35": "22"
}

cardservice = None

def CardConnect():
    global cardservice

    r = readers()
    print(r)

    cardtype = AnyCardType()
    cardrequest = CardRequest(timeout=2, cardType=cardtype)
    cardservice = cardrequest.waitforcard()

    print(cardservice.connection.getReader())

    cardservice.connection.connect()

    print("ATR:", toHexString(cardservice.connection.getATR()))

def SendAPDU(apdu, log = None, raw = False):
    global cardservice

    if log:
        print(f"* {log}")

    print(">c-apdu:", toHexString(apdu))

    response, sw1, sw2 = cardservice.connection.transmit(apdu + [0x00])
    print(f"sw {sw1:02X} {sw2:02X}")
    if (sw1, sw2) == (0x90, 0x00):
        print("<r-apdu:", toHexString(response))

    if sw1 == 0x61:   # Command successfully executed; ‘XX’ bytes (in SW2) of data are available and can be requested using GET RESPONSE.
        print(">c-apdu:", toHexString(GET_RESPONSE + [sw2]))
        response, sw1, sw2 = cardservice.connection.transmit(GET_RESPONSE + [sw2])
        print(f"sw {sw1:02X} {sw2:02X}")
        if sw1 == 0x90 and sw2 == 0x00:
            print("<r-apdu:", toHexString(response))

    if sw1 == 0x6c:   # Bad length value in Le; ‘xx’ (in SW2) is the correct exact Le
        print(">c-apdu:", toHexString(apdu + [sw2]))
        response, sw1, sw2 = cardservice.connection.transmit(apdu + [sw2])
        print(f"sw {sw1:02X} {sw2:02X}")
        if (sw1, sw2) == (0x90, 0x00):
            print("<r-apdu:", toHexString(response))

    if raw:
        return response, sw1, sw2
    else:
        return tlv.decode(bytes(response), convert=lambda t, v: v.hex().upper()), sw1, sw2

def ReadLogs(logentry):
    print("* Reading Log Entry")
    logsfi = int(logentry[0:2], 16)
    lognum = int(logentry[2:4], 16)
    print(f"Log entry SFI {logsfi}, number of entries {lognum}")

    apdu = GET_DATA
    GET_DATA[P1] = 0x9F
    GET_DATA[P2] = 0x4F
    logfmt, sw1, sw2 = SendAPDU(apdu, f"Get log format")
    format = tlv.decode(bytes.fromhex(logfmt["9F4F"]), dol=True)

    print()

    n = 1
    for record_number in range(1, lognum+1):
        entry, sw1, sw2 = ReadRecord(logsfi, record_number, raw=True)
        if (sw1, sw2) != (0x90, 0x00):
            print("! record not found, exiting")
            break

        entry = bytes(entry).hex().upper()

        print("* Entry", n)

        offset = 0
        for tag, length in format.items():

            data = entry[offset:offset+length*2]
            print(f"{tag} ({GetTagName(tag)}) - {data}")
            offset += length*2

        n += 1
        print()

def isprint(ch):
    if ch > 127:
        return False
    if ch < 32:
        return False
    if chr(ch) in string.printable:
        return True
    return False

def isPrintable(value):
    for ch in toBytes(value):
        if not isprint(ch):
            return False
    return True

# pretty print of TLV data
def pprint(dic, level=0):
    # print(json.dumps(dic, indent=2))
    if level == 0:
        print("=")
    for tag, value in dic.items():
        tag_name = GetTagName(tag)

        print(f"{'   '*level}{tag} {tag_name}")
        if isinstance(value, dict):
            pprint(value, level+1)
        elif isinstance(value, list):
            for i in range(0, len(value)):
                if i != 0:
                    print(f"{'   ' * level}{tag} {tag_name}")
                pprint(value[i], level+1)
        else:
            ascii_val = ""
            if isPrintable(value):
                ascii_val = f"({toASCIIString(toBytes(value))})"
            print(f"{'   '*(level+1)}{value} {ascii_val}")

    if level == 0:
        print("=")

def PrintApplicationDetails(app):
    aid = app["4F"]
    name = bytes.fromhex(app["50"]).decode()
    try:
        priority = app["87"]
    except KeyError:
        priority = "N/A"
    print(f'AID: {aid} ({name}), priority: {priority}')

def ReadRecord(sfi, record_number, raw = False):
    apdu = READ_RECORD
    apdu[P1] = record_number
    apdu[P2] = (sfi << 3) | 0x04

    return SendAPDU(apdu, f"READ RECORD: SFI {sfi}, record {record_number}", raw = raw)

def GetPDOL(fci):
    pdol = None
    try:
        pdol = fci["6F"]["A5"]["9F38"]
    except:
        pass

    return pdol

def GetTagName(tag):
    name = "Unknown"
    try:
        name = TAGS[tag]
    except:
        pass

    return name

def GetLogEntry(fci):
    log = None
    try:
        log = fci["6F"]["A5"]["BF0C"]["9F4D"]
    except:
        pass

    return log

def ReadApplicationData(afl):
    print("* Read application data")

    afl_l = list(bytes.fromhex(afl))
    splitted_afl = [afl_l[i:i + 4] for i in range(0, len(afl_l), 4)]

    for afl_entry in splitted_afl:
        sfi = afl_entry[0] >> 3
        for record_number in list(range(afl_entry[1], afl_entry[2] + 1)):
            response, sw1, sw2 = ReadRecord(sfi, record_number)
            if (sw1, sw2) == (0x90, 0x00):
                pprint(response)

def ReadAll():
    for sfi in range(1, 31+1):
        for record in range(1, 16+1):
            try:
                ReadRecord(sfi, record)
            except tlv.DecodeError as e:
                print("Unable to parse TLV")

def Select(app):
    try:
        app_l = toBytes(app)
    except TypeError:
        app_l = toASCIIBytes(app)

    apdu = SELECT + [len(app_l)] + app_l

    return SendAPDU(apdu, f"SELECT {app}")

def ApplicationSelection():
    PSE = "1PAY.SYS.DDF01"
    fci, sw1, sw2 = Select(PSE)

    if (sw1, sw2) == (0x90, 0x00):
        pprint(fci)
        sfi = int(fci["6F"]["A5"]["88"])
        print("PSE SFI =", sfi)

        response, sw1, sw2 = ReadRecord(sfi, 1)
        if (sw1, sw2) == (0x90, 0x00):
            pprint(response)
        else:
            print("! Unable to read PSE")
            exit(1)

        print()

        print("* List of applications")
        if isinstance(response["70"]["61"], list):
            # multi-application card
            n = 1
            apps_list = response["70"]["61"]
            for app in apps_list:
                print(f"{n}. ", end="")
                n += 1
                PrintApplicationDetails(app)

            while True:
                n = int(input(f'Enter the number ({1}..{len(apps_list)}) to select application: '))
                if n in range(1, len(apps_list) + 1):
                    break
                else:
                    print("Invalid input")

            fci, sw1, sw2 = Select(apps_list[n - 1]["4F"])
            if (sw1, sw2) == (0x90, 0x00):
                pprint(fci)
                return GetPDOL(fci), GetLogEntry(fci)

        else:
            # single-application card
            PrintApplicationDetails(response["70"]["61"])
            print()
            aid = response["70"]["61"]["4F"]
            fci, sw1, sw2 = Select(aid)
            if (sw1, sw2) == (0x90, 0x00):
                pprint(fci)
                return GetPDOL(fci), GetLogEntry(fci)

    elif (sw1, sw2) == (0x6A, 0x82):
        print("! PSE not found")

        candidates = [
            "A0000000031010",  # Visa
            "A0000000041010"   # Mastercard
        ]

        selected = False
        for aid in candidates:
            print("Trying AID:", aid)
            fci, sw1, sw2 = Select(aid)
            if (sw1, sw2) == (0x90, 0x00):
                pprint(fci)
                selected = True
                break

        if not selected:
            print("! No application to process")
            exit(1)

        return GetPDOL(fci), GetLogEntry(fci)

    print("! No application to process")
    exit(1)

def InitiateApplicationProcessing(pdol):
    if pdol:
        data = []
        for tag, length in tlv.decode(bytes.fromhex(pdol), dol=True).items():
            try:
                if length*2 <= len(TERMCONFIG[tag]):
                    data += toBytes(TERMCONFIG[tag][0:length*2])
                else:
                    print("# Invalid length in the PDOL object, Tag", tag)
                    exit(1)
            except KeyError:
                print("# Missing data for GPO processing, check TERMCONFIG dict")
                exit(1)

        apdu = GPO + [len(data) + 2] + [0x83, len(data)] + data

    else:
        apdu = GPO + [0x02] + [0x83, 0x00]  # no PDOL provided in application selection response

    response, sw1, sw2 = SendAPDU(apdu, f"GET PROCESSING OPTIONS")
    if (sw1, sw2) != (0x90, 0x00):
        print("! Unable to process application")
        exit(1)

    pprint(response)

    template = list(response.keys())[0]
    if template == "77":
        return response["77"]["94"]  # AFL
    elif template == "80":
        return response["80"][4:]
    else:
        return None

def GeldKarteBalance():
    app_l = toBytes("D27600002545500200")
    apdu = SELECT + [len(app_l)] + app_l
    SendAPDU(apdu, f"SELECT")

    ReadRecord(24, 1, raw=True)  # SFI 24, record 1 = Balance. First 3 bytes
"""
######## Starts here ########

pdol, logentry = ApplicationSelection()
print("PDOL:", pdol)
afl = InitiateApplicationProcessing(pdol)
print("AFL:", afl)
ReadApplicationData(afl)

if logentry:
    ReadLogs(logentry)

exit(1)




aid = [0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60]

#apdu = SELECT + [len(aid)] + list(aid)
apdu = SELECT + [len(aid)] + list(aid)

response, sw1, sw2 = SendAPDU(apdu, f"Select AID {aid}")

#logentry = response["6F"]["A5"]["BF0C"]["9F4D"]
#queryLog(logentry)

#exit(1)

apdu = GPO + [0x06] + [0x83, 0x04, 0xE0, 0xF0, 0x00, 0x00]  # no PDOL provided in application selection response
SendAPDU(apdu, f"Get Processing Options")

#exit(1)


record_number = 5
sfi = 1
apdu = list(READ_RECORD)
apdu[P1] = record_number
apdu[P2] = (sfi << 3) | 0x04

response, sw1, sw2 = SendAPDU(apdu, f"Read record {record_number}")

exit(1)

apdu = [0x80, 0xCA, 0x9F, 0x4F]
response, sw1, sw2 = SendAPDU(apdu, f"Get log format")



exit(1)


#print response
print("get data, pin try counter?")
ATC = [0x80, 0xCA, 0x9F, 0x17, 0x04]
response, sw1, sw2 = cardservice.connection.transmit( ATC, CardConnection.T0_protocol )
print('{:x} {:x}'.format(sw1, sw2))
print(toHexString(response))












print toHexString(response)
print "%02x %02x" % (sw1, sw2)
#sys.exit()
print "GET DATA"
FILE = [0x00, 0xB2, 0x02, 0x0C, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( FILE, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)

print "GET DATA"
FILE = [0x00, 0xB2, 0x01, 0x14, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( FILE, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)

print "GET DATA"
FILE = [0x00, 0xB2, 0x03, 0x14, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( FILE, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)

print "GET DATA"
FILE = [0x00, 0xB2, 0x01, 0x1C, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( FILE, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)

print "GET DATA"
FILE = [0x00, 0xB2, 0x02, 0x1C, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( FILE, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)

#INTERNAL_AUTHENTIFICATE = [0x00, 0x88, 0x00, 0x00, 0x04, 0x5a, 0xce, 0xdd, 0xfe, 0x00]
#response, sw1, sw2 = cardservice.connection.transmit( INTERNAL_AUTHENTIFICATE, CardConnection.T1_protocol )
#print "%02x %02x" % (sw1, sw2)

PIN = [0x80, 0xCA, 0xBF, 0x5B, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( PIN, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)
print "Activation: ", toHexString(response)

PIN = [0x80, 0xCA, 0x9F, 0x23, 0x00]
response, sw1, sw2 = cardservice.connection.transmit( PIN, CardConnection.T1_protocol )
print "%02x %02x" % (sw1, sw2)
print "Limit: ", toHexString(response)

sys.exit()

GAC = [0x80, 0xAE, 0x80, 0x00, 0x1d]
Amount = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
Amount_other = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
Term_cc = [0x06, 0x43]
TVR = [0x00, 0x00, 0x00, 0x00, 0x00]
Trans_cc = [0x06, 0x43]
Trans_date = [0x13, 0x06, 0x11]
Trans_type = [0x00]
Unpred = [0x60, 0x65, 0x53, 0x77]

print "GAC1"
apdu = GAC + Amount + Amount_other + Term_cc + TVR + Trans_cc + Trans_date + Trans_type + Unpred
print "APDU send:", toHexString(apdu)
response, sw1, sw2 = cardservice.connection.transmit( apdu + [0x00], CardConnection.T1_protocol )
resp = toHexString(response)
print "Resp:", resp
print "SW1 SW2: %02x %02x" % (sw1, sw2)
atc = resp[9:15]
arqc = resp[14:38]
cvr = resp[39:]
print 'ATC ', atc
print 'ARQC ', arqc
print 'CVR ', cvr

#sys.exit()
# just gen
# tohsm = '00 40 53 53 53 53 4b 57 34 32 55 38 33 43 31 43 30 36 37 30 45 46 37 46 41 35 41 37 30 44 46 39 43 32 42 41 45 34 35 34 37 30 44 05 28 08 14 00 00 14 00 '+ atc + arqc + ' 00 80 00 00 30'

# verif and gen 
#tohsm = '00 83 30 30 30 32 4b 57 33 32 55 38 33 43 31 43 30 36 37 30 45 46 37 46 41 35 41 37 30 44 46 39 43 32 42 41 45 34 35 34 37 30 44 05 28 08 14 00 00 14 00 ' + atc + '34 30 00 00 00 01 00 00 00 00 00 00 00 00 06 43 00 00 00 00 00 06 43 13 06 11 00 60 65 53 77 38 00 '+ atc + cvr + ' 80 00 00 00 00 00 00 00 3b' + arqc + ' 00 80 00 00 30'
# 4505290837770006
tohsm = '00 83 30 30 30 32 4b 57 33 32 55 38 33 43 31 43 30 36 37 30 45 46 37 46 41 35 41 37 30 44 46 39 43 32 42 41 45 34 35 34 37 30 44 05 29 08 37 77 00 06 00 ' + atc + '34 30 00 00 00 01 00 00 00 00 00 00 00 00 06 43 00 00 00 00 00 06 43 13 06 11 00 60 65 53 77 38 00 '+ atc + cvr + ' 80 00 00 00 00 00 00 00 3b' + arqc + ' 00 80 00 00 30'
print 'Command to hsm:', tohsm

hsm = toBytes(tohsm)
hsm = HexListToBinString(hsm)


HOST, PORT = '127.0.0.1', 1500
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((HOST, PORT))
sock.send(hsm)
reply = sock.recv(16384)  # limit reply to 16K
sock.close()
resp = toHexString(BinStringToHexList(reply))
print "HSM resp:", resp
arpc = resp[30:53]
print "ARPC:", arpc

#sys.exit()

print "GAC2"
GAC2 = [0x80, 0xAE, 0x40, 0x00, 0x27]
arpc_rc = [0x30, 0x30]
iad = toBytes(arpc)

apdu = GAC2 + arpc_rc+ Amount + Amount_other + Term_cc + TVR + Trans_cc + Trans_date + Trans_type + Unpred + iad

print "APDU send:", toHexString(apdu)

response, sw1, sw2 = cardservice.connection.transmit( apdu + [0x00], CardConnection.T1_protocol )

print "Resp:", toHexString(response)
print "SW1 SW2 %02x %02x" % (sw1, sw2)


'''
connection = r[0].createConnection()
connection.connect()

atr = ATR( connection.getATR() )
print atr
print 'historical bytes: ', toHexString( atr.getHistoricalBytes() )
print 'checksum: ', "0x%X" % atr.getChecksum()
print 'checksum OK: ', atr.checksumOK
print 'T0 supported: ', atr.isT0Supported()
print 'T1 supported: ', atr.isT1Supported()
print 'T15 supported: ', atr.isT15Supported()

                   
SELECT = [0x00, 0xA4, 0x04, 0x00, 0x0E]
DF_TELECOM = [0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31]
data, sw1, sw2 = connection.transmit( SELECT + DF_TELECOM )
'''
#print "%02x %02x" % (sw1, sw2)

# pin unblcok
#tohsm = '00 4d 30 30 30 35 4b 55 30 30 55 31 46 46 31 34 32 33 41 30 33 31 35 32 33 35 31 31 33 31 31 33 36 31 44 45 45 30 42 43 44 37 31 05 28 08 14 00 00 14 00 00 00 00 00 00 00 ' + atc + ' 30 30 30 46 84 24 00 00 04 ' + atc + arqc + ' 3b'

# activation
#tohsm = '00 52 30 30 30 35 4b 55 30 30 55 31 46 46 31 34 32 33 41 30 33 31 35 32 33 35 31 31 33 31 31 33 36 31 44 45 45 30 42 43 44 37 31 05 28 08 14 00 00 14 00 00 00 00 00 00 00 '+ atc + ' 30 30 31 34 04 DA BF 5B 09 ' + atc + arqc + ' DF 01 02 00 00 3b'
tohsm = '00 52 30 30 30 35 4b 55 30 30 55 31 46 46 31 34 32 33 41 30 33 31 35 32 33 35 31 31 33 31 31 33 36 31 44 45 45 30 42 43 44 37 31 05 29 08 37 77 00 06 00 00 00 00 00 00 00 '+ atc + ' 30 30 31 34 04 DA BF 5B 09 ' + atc + arqc + ' DF 01 02 00 00 3b'
#pin change
#tohsm = '00 DA 53 53 53 53 4B 55 34 30 55 31 46 46 31 34 32 33 41 30 33 31 35 32 33 35 31 31 33 31 31 33 36 31 44 45 45 30 42 43 44 37 31 05 28 08 14 00 00 14 00 00 00 00 00 00 00 '+atc+' 30 30 30 46 84 24 00 02 14 '+atc+arqc+' 3B 55 35 42 30 41 30 45 46 31 34 32 30 30 45 37 46 43 39 31 33 44 44 39 37 45 34 30 36 38 36 42 31 39 00 00 00 00 00 00 '+atc+' 30 30 30 46 30 30 30 38 AE 8B 1D 88 21 09 69 8A 3B 30 55 46 42 30 43 34 42 37 38 38 43 44 31 35 39 31 35 37 46 42 38 43 32 45 35 35 36 42 45 35 35 31 41 30 31 34 31 35 32 38 30 38 31 34 30 30 30 30 31 55 38 33 43 31 43 30 36 37 30 45 46 37 46 41 35 41 37 30 44 46 39 43 32 42 41 45 34 35 34 37 30 44'
#tohsm = '00 DA 53 53 53 53 4B 55 34 30 55 31 46 46 31 34 32 33 41 30 33 31 35 32 33 35 31 31 33 31 31 33 36 31 44 45 45 30 42 43 44 37 31 05 29 08 37 77 00 06 00 00 00 00 00 00 00 '+atc+' 30 30 30 46 84 24 00 02 14 '+atc+arqc+' 3B 55 35 42 30 41 30 45 46 31 34 32 30 30 45 37 46 43 39 31 33 44 44 39 37 45 34 30 36 38 36 42 31 39 00 00 00 00 00 00 '+atc+' 30 30 30 46 30 30 30 38 AC 5C 05 01 36 9F CF DB 3B 30 55 46 42 30 43 34 42 37 38 38 43 44 31 35 39 31 35 37 46 42 38 43 32 45 35 35 36 42 45 35 35 31 41 30 31 34 31 35 32 39 30 38 33 37 37 37 30 30 30 55 38 33 43 31 43 30 36 37 30 45 46 37 46 41 35 41 37 30 44 46 39 43 32 42 41 45 34 35 34 37 30 44'
print 'Command to hsm:', tohsm

hsm = toBytes(tohsm)
hsm = HexListToBinString(hsm)
HOST, PORT = '127.0.0.1', 1500
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((HOST, PORT))
sock.send(hsm)
reply = sock.recv(16384)  # limit reply to 16K
sock.close()
resp = toHexString(BinStringToHexList(reply))
print "HSM resp:", resp

sys.exit()

mac = resp[30:41]
print mac
#sys.exit()
#pin change
pincdata = resp[65:]
print pincdata
#sys.exit();
# pin unblcok
#apdu = '84 24 00 00 04 ' + mac

# activation
apdu = '04 DA BF 5B 09 DF 01 02 00 00 '+mac

# pin change
#apdu = '84 24 00 02 14 ' + pincdata + ' '+ mac
print toBytes(apdu)

response, sw1, sw2 = cardservice.connection.transmit( toBytes(apdu), CardConnection.T1_protocol )

print "SW1 SW2 %02x %02x" % (sw1, sw2)


"""
