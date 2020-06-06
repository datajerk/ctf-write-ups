# castorsCTF20

## Magic School Bus

> 366
>
> Author: hasu
>
> `nc chals20.cybercastors.com 14421`
>
> _Flag is slightly out of format. Add underscores and submit uppercase_

Tags: _crypto_


## Summary

Simple crypto where repeatedly feeding back the output into the input will reveal the flag.


## Solutions

### Code

```python
#!/usr/bin/python3

from pwn import *

p = remote('chals20.cybercastors.com',14421)

p.recvuntil('Your choice: ')
p.sendline('2')
p.recvuntil('Flag bus seating: ')
_ = p.recvline().strip()
print(_)

while True:
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil("Who's riding the bus?: ")
    p.sendline(_)
    p.recvuntil('Bus seating: ')
    _ = p.recvline().strip()
    print(_)

    if _.find(b'CASTORSCTF') != -1:
        print()
        print(_)
        break
```

Output:

```
SNESYT3AYN1CTISL7SRS31RAFSKV3C4I0SOCNTGER0COM5
3SR4GSCSVCOSY7F0RE1RKOCNNSSS0ALAIEYT33NMTI1CT5
CFCLN4SRSTC3VRNITRO1SY1SCESEIS0NAMGYK03TS7OA35
SN103L31EYACSTCASCCOSGOFTREM7RISNTNVSIK34RYS05
3COIK0COMVSSESTN41ACENYNYCRTR1AFS33SS7S0LTGRI5
CTYASISCTSR3M4YSLOSAR3GCV1C3TONNF0KEERSI0SN175
SYGNSA3A3E1CTLVF0YRSCKNTSO10SCSCNISMRTE7I43OR5
3VNSENCS0MOS30SNIG1R1S3YEYOI4AFTC7STCSRRALKCT5
CS3FRSSRITC30IECANO1OSKVMGY7LSNYTRE314CTN0SAS5
SEKNCF3173ACIAMTN3COYESSTNGR0RCVYTR0OL1SSISS45
3MSC1NCOR0SS7NTYSKACGRSE33NTI1TSVSCIY0O4FAERL5
CTSTOCSCTIR3RS3VFSSANCEM0K3SAOYES417GIYLNNR105
S3EYYT3AS71CTF0SNSRS31RTISK4NCVMELORNAG0CSCOI5
30RVGYCS4ROSSNIECE1RKOC37SSLSASTM0YT3NNITF1CA5
CICSNVSRLTC34C7MTRO1SY10RES0FSE3TIGSKS3AYNOAN5
S71E3S310SACLTRTYCCOSGOITREINRM03AN4SFKNVCYSS5
3ROMKECOI4SS0YT3V1ACENY7SCRAC1TI0N3LSNSSSTGRF5
CTYTSMSCALR3IVS0SOSAR3GR41CNTO37ISK0ECSFEYN1N5
SSG3ST3AN01CAS4IEYRSCKNTLO1SYC0R7FSIRTENMV3OC5
34N0E3CSSIOSNEL7MG1R1S3S0YOFVAITRNSACYRCTSKCT5
CL3IR0SRFAC3SM0RTNO1OSK4IGYNSS7STCEN1VCT3ESAY5
S0K7CI31NNACFTIT33COYESLANGCERR4STRSOS1Y0MSSV5
3ISR17COCSSSN3AS0KACGRS0N3NTM1TL4YCFYEOVITERS5

CASTORSCTFR3C0N4ISSANCEISK3YTOS0LV1NGMYS73R1E5
```


### Handjob

```
# nc chals20.cybercastors.com 14421

 __    __  ______  ______  __  ______       ______  ______  __  __  ______  ______  __           ______  __  __  ______
/\ "-./  \/\  __ \/\  ___\/\ \/\  ___\     /\  ___\/\  ___\/\ \_\ \/\  __ \/\  __ \/\ \         /\  == \/\ \/\ \/\  ___\
\ \ \-./\ \ \  __ \ \ \__ \ \ \ \ \____    \ \___  \ \ \___\ \  __ \ \ \/\ \ \ \/\ \ \ \____    \ \  __<\ \ \_\ \ \___  \
 \ \_\ \ \_\ \_\ \_\ \_____\ \_\ \_____\    \/\_____\ \_____\ \_\ \_\ \_____\ \_____\ \_____\    \ \_____\ \_____\/\_____\
  \/_/  \/_/\/_/\/_/\/_____/\/_/\/_____/     \/_____/\/_____/\/_/\/_/\/_____/\/_____/\/_____/     \/_____/\/_____/\/_____/


All right kids!
The Magic Flag Bus is about to leave!
Make sure to fill each row as you step in.
Wait, what! All the kids got moved around.
I *knew* I should've stayed home today!
Nevermind... Load your own bus and let's leave.

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 2

Flag bus seating: SNESYT3AYN1CTISL7SRS31RAFSKV3C4I0SOCNTGER0COM5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: SNESYT3AYN1CTISL7SRS31RAFSKV3C4I0SOCNTGER0COM5
Bus seating: 3SR4GSCSVCOSY7F0RE1RKOCNNSSS0ALAIEYT33NMTI1CT5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3SR4GSCSVCOSY7F0RE1RKOCNNSSS0ALAIEYT33NMTI1CT5
Bus seating: CFCLN4SRSTC3VRNITRO1SY1SCESEIS0NAMGYK03TS7OA35

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CFCLN4SRSTC3VRNITRO1SY1SCESEIS0NAMGYK03TS7OA35
Bus seating: SN103L31EYACSTCASCCOSGOFTREM7RISNTNVSIK34RYS05

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: SN103L31EYACSTCASCCOSGOFTREM7RISNTNVSIK34RYS05
Bus seating: 3COIK0COMVSSESTN41ACENYNYCRTR1AFS33SS7S0LTGRI5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3COIK0COMVSSESTN41ACENYNYCRTR1AFS33SS7S0LTGRI5
Bus seating: CTYASISCTSR3M4YSLOSAR3GCV1C3TONNF0KEERSI0SN175

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CTYASISCTSR3M4YSLOSAR3GCV1C3TONNF0KEERSI0SN175
Bus seating: SYGNSA3A3E1CTLVF0YRSCKNTSO10SCSCNISMRTE7I43OR5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: SYGNSA3A3E1CTLVF0YRSCKNTSO10SCSCNISMRTE7I43OR5
Bus seating: 3VNSENCS0MOS30SNIG1R1S3YEYOI4AFTC7STCSRRALKCT5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3VNSENCS0MOS30SNIG1R1S3YEYOI4AFTC7STCSRRALKCT5
Bus seating: CS3FRSSRITC30IECANO1OSKVMGY7LSNYTRE314CTN0SAS5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CS3FRSSRITC30IECANO1OSKVMGY7LSNYTRE314CTN0SAS5
Bus seating: SEKNCF3173ACIAMTN3COYESSTNGR0RCVYTR0OL1SSISS45

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: SEKNCF3173ACIAMTN3COYESSTNGR0RCVYTR0OL1SSISS45
Bus seating: 3MSC1NCOR0SS7NTYSKACGRSE33NTI1TSVSCIY0O4FAERL5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3MSC1NCOR0SS7NTYSKACGRSE33NTI1TSVSCIY0O4FAERL5
Bus seating: CTSTOCSCTIR3RS3VFSSANCEM0K3SAOYES417GIYLNNR105

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CTSTOCSCTIR3RS3VFSSANCEM0K3SAOYES417GIYLNNR105
Bus seating: S3EYYT3AS71CTF0SNSRS31RTISK4NCVMELORNAG0CSCOI5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: S3EYYT3AS71CTF0SNSRS31RTISK4NCVMELORNAG0CSCOI5
Bus seating: 30RVGYCS4ROSSNIECE1RKOC37SSLSASTM0YT3NNITF1CA5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 30RVGYCS4ROSSNIECE1RKOC37SSLSASTM0YT3NNITF1CA5
Bus seating: CICSNVSRLTC34C7MTRO1SY10RES0FSE3TIGSKS3AYNOAN5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CICSNVSRLTC34C7MTRO1SY10RES0FSE3TIGSKS3AYNOAN5
Bus seating: S71E3S310SACLTRTYCCOSGOITREINRM03AN4SFKNVCYSS5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: S71E3S310SACLTRTYCCOSGOITREINRM03AN4SFKNVCYSS5
Bus seating: 3ROMKECOI4SS0YT3V1ACENY7SCRAC1TI0N3LSNSSSTGRF5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3ROMKECOI4SS0YT3V1ACENY7SCRAC1TI0N3LSNSSSTGRF5
Bus seating: CTYTSMSCALR3IVS0SOSAR3GR41CNTO37ISK0ECSFEYN1N5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CTYTSMSCALR3IVS0SOSAR3GR41CNTO37ISK0ECSFEYN1N5
Bus seating: SSG3ST3AN01CAS4IEYRSCKNTLO1SYC0R7FSIRTENMV3OC5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: SSG3ST3AN01CAS4IEYRSCKNTLO1SYC0R7FSIRTENMV3OC5
Bus seating: 34N0E3CSSIOSNEL7MG1R1S3S0YOFVAITRNSACYRCTSKCT5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 34N0E3CSSIOSNEL7MG1R1S3S0YOFVAITRNSACYRCTSKCT5
Bus seating: CL3IR0SRFAC3SM0RTNO1OSK4IGYNSS7STCEN1VCT3ESAY5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: CL3IR0SRFAC3SM0RTNO1OSK4IGYNSS7STCEN1VCT3ESAY5
Bus seating: S0K7CI31NNACFTIT33COYESLANGCERR4STRSOS1Y0MSSV5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: S0K7CI31NNACFTIT33COYESLANGCERR4STRSOS1Y0MSSV5
Bus seating: 3ISR17COCSSSN3AS0KACGRS0N3NTM1TL4YCFYEOVITERS5

Select:
    1) Load magic school bus
    2) View magic flag bus
Your choice: 1

Who's riding the bus?: 3ISR17COCSSSN3AS0KACGRS0N3NTM1TL4YCFYEOVITERS5
Bus seating: CASTORSCTFR3C0N4ISSANCEISK3YTOS0LV1NGMYS73R1E5
```

### Flag

```
CASTORSCTF{R3C0N4ISSANCE_IS_K3Y_TO_S0LV1NG_MYS73R1E5}
```
