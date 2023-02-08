from scard import *

CardConnect()

pdol, logentry = ApplicationSelection()
print("PDOL:", pdol)
afl = InitiateApplicationProcessing(pdol)
print("AFL:", afl)
ReadApplicationData(afl)

if logentry:
    ReadLogs(logentry)
