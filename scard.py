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
