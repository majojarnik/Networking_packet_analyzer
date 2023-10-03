import dpkt


def zistiEtyp(packet):                                                                          #zistujem Ethernet TYP
    hodnota = str(format(packet[12], '02x')) + str(format(packet[13], '02x'))
    hodnota = int(hodnota, 16)      

    for i in range(0, len(eTypPole), 2):
        if (eTypPole[i] == hodnota):
            return(eTypPole[i+1])

    return ''

def zistiIEEEtyp(packet):                                                                       #zistujem IEEE TYP
    for i in range(0, len(ieeeTypPole), 2):
        if (ieeeTypPole[i] == packet[14] or ieeeTypPole[i] == packet[15]):
            typ = [x.replace('_', ' ') for x in ieeeTypPole[i+1]]
            text = ''.join(typ)
            return text
        
    return 'IEEE 802.3 LLC'

def zistiIPv4typ(packet):                                                                       #zistujem IPv4 TYP
    for i in range(0, len(ipv4TypPole), 2):
        if (ipv4TypPole[i] == packet[23]):
            return(ipv4TypPole[i+1])          
    return ''


def zistiTCPport(packet, typ, co):                                                              #zistujem TCP port
    if typ == 'zdroj':
        hodnota = str(format(packet[34], '02x')) + str(format(packet[35], '02x')) 
    else:
        hodnota = str(format(packet[36], '02x')) + str(format(packet[37], '02x'))
    hodnota = int(hodnota, 16)
    if co == 'cislo':
        return hodnota
        
    for i in range(0, len(tcpTypPole), 2):
        if (tcpTypPole[i] == hodnota):
            return(tcpTypPole[i+1])
    return ''


def zistiUDPport(packet, typ, co):                                                              #zistujem UDP port
    if typ == 'zdroj':
        hodnota = str(format(packet[34], '02x')) + str(format(packet[35], '02x')) 
    else:
        hodnota = str(format(packet[36], '02x')) + str(format(packet[37], '02x'))
    hodnota = int(hodnota, 16)   
    if co == 'cislo':
        return hodnota
     
    for i in range(0, len(udpTypPole), 2):
        if (udpTypPole[i] == hodnota):
            return(udpTypPole[i+1]) 
    return ''


def zistiICMPtyp(packet):                                                                       #zistujem ICMP typ spravy
    for i in range(0, len(icmpTypPole), 2):
        if (icmpTypPole[i] == packet[34]):
            typ = [x.replace('_', ' ') for x in icmpTypPole[i+1]]
            text = ''.join(typ)
            return text  
    return ''


def zistiARPtyp(packet):                                                                        #zistujem ARP typ
    for i in range(0, len(arpTypPole), 2):
        if (arpTypPole[i] == packet[21]):
            return(arpTypPole[i+1])  
    return ''
    

def vratPoleTypov(typ):                                                                         #z externych suborov vracia pole, v ktorom su hodnoty a nazvy typov v suboroch
    words = []
    j=0
    for line in typ:
        words += line.split()

    pTyp = []
    for word in words:
        j += 1
        if (j % 2 == 1):
            pTyp.append(int(word, 16))
        else:
            pTyp.append(word)
            
    return pTyp


def zistiIPadr(packet, typ):                                                                    #pri IPv4 zistuje IP adresy
    zdr_ip = ''
    ciel_ip = ''
    if typ == 'zdroj':
        for i in range(4):
            if i == 3:
                zdr_ip += str(int(packet[26+i]))
            else:
                zdr_ip += str(int(packet[26+i]))+'.'
        return zdr_ip
    else:
        for i in range(4):
            if i == 3:
                ciel_ip += str(int(packet[30+i]))
            else:
                ciel_ip += str(int(packet[30+i]))+'.'       
        return ciel_ip
    
        
def ipv4(packet, adresy, kde):                                                                  #vypisuje adresy a zistuje zdrojove adresy a ktora z nich je najpouzivanejsia
    ip = zistiIPadr(packet, 'zdroj')
    print("zdrojova IP adresa:", ip)    
    print("cielova IP adresa:",zistiIPadr(packet, 'ciel'))
    print(zistiIPv4typ(packet))

    if kde == 1:
        jetam = False
        for i in range(len(adresy)):
            if adresy[i] == ip:
                adresy[i+1] += 1
                jetam = True
                break
                
        if not jetam:        
            adresy.append(ip)
            adresy.append(int(1))
        return adresy
    

def vypisV4(pack, por_cislo, typ):                                                              #vypisuje ramce pri TCP a UDP komunikaciach
    print("ramec ", por_cislo)
    print("dlzka ramca poskytnuta pcap API:" , len(pack))
    print("dlzka ramca prenasaneho po mediu:" , max(len(pack) + 4, 64))
    print("Ethernet II")

    print("Zdrojova MAC adresa:", end = " ")
    for i in range(6,12):
        print(format(pack[i], '02x'), end = " ")
    print("\nCielova MAC adresa:", end = " ")
    for i in range(6):
        print(format(pack[i], '02x'), end = " ")
        
    print("\nIPv4")
    pole = []
    ipv4(pack, pole, 2)

    print(typ)

    print("Zdrojovy port:", zistiTCPport(pack, "zdroj", "cislo"))
    print("Cielovy port:", zistiTCPport(pack, "ciel", "cislo"))   
    
    i = 0
    for byte in pack:
        print(format(byte, '02x'), end = " ")
        i += 1
        if i % 16 == 0:
            print()
        elif i % 8 == 0:
            print(end ="  ")
    print('\n')
    

def vypisTCP(typ):                                                                              #vypise komunikacie podla typu ktory dostane ako parameter
    pocet = 0
    for pack in packets:
        pack = pack[1]
        if zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "TCP" and ( zistiTCPport(pack, "zdroj", "meno") == typ or zistiTCPport(pack, "ciel", "meno") == typ):
            pocet += 1
            
    desat = 0
    j = 0
    for pack in packets:
        pack = pack[1]
        j += 1            
        if  (zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "TCP" and ( zistiTCPport(pack, "zdroj", "meno") == typ or zistiTCPport(pack, "ciel", "meno") == typ)):
            desat += 1
            if desat <= 10 or desat > pocet-10:
                vypisV4(pack, j, typ)


def zistiTCPflag(packet):
    for i in range(0, len(tcpFlagPole), 2):
        if (tcpFlagPole[i] == packet[47]):
            return(tcpFlagPole[i+1])
    return ''


def vypisTCP1(typ):                                                                                #vypise prvu kompletnu a prvu nekompletnu TCP komunikaciu
    j = 0
    poc = 0
    zac = 0
    nekomp = False
    komp = False
    pocet = 0    
    for pack in packets:
        pack = pack[1]
        j += 1
        if zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "TCP" and (zistiTCPport(pack, "zdroj", "meno") == typ or zistiTCPport(pack, "ciel", "meno") == typ):
            if zistiTCPflag(pack) == "SYN":
                zac = j-1 
                zdr_port = zistiTCPport(pack, "zdroj", "cislo")
                ciel_port = zistiTCPport(pack, "ciel", "cislo")
                zdr_ip = zistiIPadr(pack, 'zdroj')
                ciel_ip = zistiIPadr(pack, 'ciel')
                konec1 = [0, 0, 0]
                konec2 = [0, 0, 0]
                konec3 = 0
                konec4 = [0, 0, 0]
            
                for k in range(j, len(packets)):
                    pac = packets[k][1]
                    if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and zistiTCPflag(pac) == "SYN_ACK" and zdr_port == zistiTCPport(pac, "ciel", "cislo") and ciel_port == zistiTCPport(pac, "zdroj", "cislo") and zdr_ip == zistiIPadr(pac, 'ciel') and ciel_ip == zistiIPadr(pac, 'zdroj'):
                        for m in range(k+1, len(packets)):
                            pac = packets[m][1]
                            if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and zistiTCPflag(pac) == "ACK" and zdr_port == zistiTCPport(pac, "zdroj", "cislo") and ciel_port == zistiTCPport(pac, "ciel", "cislo") and zdr_ip == zistiIPadr(pac, 'zdroj') and ciel_ip == zistiIPadr(pac, 'ciel'):
                                poc = m + 1
                                pocet = 3
                                for n in range(m+1, len(packets)):
                                    poc += 1
                                    pac = packets[n][1]
                                    if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and (zdr_port == zistiTCPport(pac, "zdroj", "cislo") or zdr_port == zistiTCPport(pac, "ciel", "cislo")) and (ciel_port == zistiTCPport(pac, "zdroj", "cislo") or ciel_port == zistiTCPport(pac, "ciel", "cislo")) and (zdr_ip == zistiIPadr(pac, 'zdroj') or zdr_ip == zistiIPadr(pac, 'ciel')) and (ciel_ip == zistiIPadr(pac, 'zdroj') or ciel_ip == zistiIPadr(pac, 'ciel')):
                                    #if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and (zdr_ip == zistiIPadr(pac, 'zdroj') or zdr_ip == zistiIPadr(pac, 'ciel')) and (ciel_ip == zistiIPadr(pac, 'zdroj') or ciel_ip == zistiIPadr(pac, 'ciel')):
                                        pocet += 1
                                        if (zistiTCPflag(pac) == "FIN_ACK" or zistiTCPflag(pac) == "FIN") and konec4 == [1, 0, 0]:
                                            konec4[1] = 1
                                        if zistiTCPflag(pac) == "FIN" or zistiTCPflag(pac) == "FIN_ACK":
                                            konec1[0] = 1
                                            konec2[0] = 1
                                        if (zistiTCPflag(pac) == "FIN_ACK" or zistiTCPflag(pac) == "FIN") and konec4 == [0, 0, 0]:
                                            konec4[0] = 1
                                        if zistiTCPflag(pac) == "ACK" and (konec2 == [1, 0, 0] or konec1 == [1, 1, 0]):
                                            konec1[1] = 1
                                            konec2[1] = 1
                                        if zistiTCPflag(pac) == "ACK" and konec4 == [1, 1, 0]:
                                            konec4[2] = 1
                                            break
                                        if (zistiTCPflag(pac) == "FIN_ACK" or zistiTCPflag(pac) == "FIN") and konec1 == [1, 1, 0]:
                                            konec1[2] = 1
                                            break
                                        if (zistiTCPflag(pac) == "RST_ACK" or zistiTCPflag(pac) == "RST") and konec2 == [1, 1, 0]:
                                            konec2[2] = 1
                                            break
                                        elif (zistiTCPflag(pac) == "RST_ACK" or zistiTCPflag(pac) == "RST"):
                                            konec3 = 1
                                            break
                                pis = False
                                if konec1 != [1, 1, 1] and konec2 != [1, 1, 1] and konec3 != 1 and konec4 != [1,1,1] and not nekomp:
                                    nekomp = True
                                    pis = True
                                    print("PRVA NEKOMOPLETNA KOMUNIKACIA")
                                elif (konec1 == [1, 1, 1] or konec2 == [1, 1, 1] or konec3 == 1 or konec4 == [1, 1, 1]) and not komp:
                                    komp = True
                                    pis = True
                                    print("KOMPLETNA KOMUNIKACIA")
                                desat = 0
                                if pis:
                                    for n in range(zac, poc):
                                        pac = packets[n][1]
                                        if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and (zdr_port == zistiTCPport(pac, "zdroj", "cislo") or zdr_port == zistiTCPport(pac, "ciel", "cislo")) and (ciel_port == zistiTCPport(pac, "zdroj", "cislo") or ciel_port == zistiTCPport(pac, "ciel", "cislo")) and (zdr_ip == zistiIPadr(pac, 'zdroj') or zdr_ip == zistiIPadr(pac, 'ciel')) and (ciel_ip == zistiIPadr(pac, 'zdroj') or ciel_ip == zistiIPadr(pac, 'ciel')):
                                        #if zistiEtyp(pac) == "IPv4" and zistiIPv4typ(pac) == "TCP" and (zdr_ip == zistiIPadr(pac, 'zdroj') or zdr_ip == zistiIPadr(pac, 'ciel')) and (ciel_ip == zistiIPadr(pac, 'zdroj') or ciel_ip == zistiIPadr(pac, 'ciel')):
                                            desat += 1
                                            if (zistiTCPport(pac, "ciel", "meno")) != '':
                                                typ = zistiTCPport(pac, "ciel", "meno")
                                            else:
                                                typ = zistiTCPport(pac, "zdroj", "meno")

                                            if desat <= 10 or desat > pocet-10: 
                                                vypisV4(pac, n+1, typ)
                                break
                        break
                if nekomp and komp:
                    break


def vypisICMP():                                                                            #vypise ICMP komunikacie podla IP adries
    """
    pocet = 0
    for pack in packets:
        pack = pack[1]
        if zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "ICMP":
            pocet += 1
            
    desat = 0   
    j = 0
    for pack in packets:
        pack = pack[1]
        j += 1
        if zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "ICMP":
            desat += 1
            if desat <= 10 or desat > pocet-10: 
                print("ramec ",j)
                print("dlzka ramca poskytnuta pcap API:" , len(pack))
                print("dlzka ramca prenasaneho po mediu:" , max(len(pack) + 4, 64))
                print("Ethernet II")

                print("Zdrojova MAC adresa:", end = " ")
                for i in range(6,12):
                    print(format(pack[i], '02x'), end = " ")
                print("\nCielova MAC adresa:", end = " ")
                for i in range(6):
                    print(format(pack[i], '02x'), end = " ")
                    
                print("\nIPv4")
                pole = []
                ipv4(pack, pole, 2)

                print(zistiICMPtyp(pack))
                
                i = 0
                for byte in pack:
                    print(format(byte, '02x'), end =" ")
                    i += 1
                    if i % 16 == 0:
                        print()
                    elif i % 8 == 0:
                        print(end ="  ")
                print('\n')

    """          
    j = 0
    icmpkom = []
    for pack in packets:
        pack = pack[1]
        j += 1
        ciel_adr = ''
        zdr_adr = ''
        uzje = False
        if zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "ICMP":
            zdr_adr = zistiIPadr(pack, "zdroj")
            ciel_adr = zistiIPadr(pack, "ciel")
            
            for kom in icmpkom:
                if ((kom[0] == zdr_adr or kom[0] == ciel_adr) and (kom[1] == ciel_adr or kom[1] == zdr_adr)):
                    kom.append(j)
                    kom.append(pack)
                    uzje = True
                    break
                
            if not uzje:
                icmpkom.append([zdr_adr, ciel_adr, j, pack])

    poc = 0
    for kom in icmpkom:
        poc += 1
        print("Komunikacia c.", poc)
        
        for j in range(2, len(kom), 2):
            print("ramec ",kom[j])
            print("dlzka ramca poskytnuta pcap API:" , len(kom[j+1]))
            print("dlzka ramca prenasaneho po mediu:" , max(len(kom[j+1]) + 4, 64))
            print("Ethernet II")
            print("IPv4")
            print("Zdrojova MAC adresa:", end = " ")
            for i in range(6,12):
                print(format(kom[j+1][i], '02x'), end = " ")
                    
            print("\nCielova MAC adresa:", end = " ")
            for i in range(6):
                print(format(kom[j+1][i], '02x'), end = " ")
            print()

            print("Zdrojova IP: ", zistiIPadr(kom[j+1], "zdroj"))
            print("Cielova IP: ", zistiIPadr(kom[j+1], "ciel"))
            print("ICMP")
            print(zistiICMPtyp(kom[j+1]))
            
            for i in range(len(kom[j+1])):
                print(format(kom[j+1][i], '02x'), end =" ")
                if (i+1) % 16 == 0:
                    print()
                elif (i+1) % 8 == 0:
                    print(end ="  ")
                    
            print('\n')



def vypisTFTP():                                                                                            #vypise TFTP komunikaciu
    j = 0
    prvy = False
    druhy = False
    for pack in packets:
        pack = pack[1]
        j += 1 
        if not prvy and zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "UDP" and (zistiUDPport(pack, "zdroj", "meno") == "TFTP" or zistiUDPport(pack, "ciel", "meno") == "TFTP"):
            zdr_ip = zistiIPadr(pack, 'zdroj')
            ciel_ip = zistiIPadr(pack, 'ciel')
            prvy = True
            vypisV4(pack, j, 'TFTP')

        elif prvy and not druhy and zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "UDP" and (zdr_ip == zistiIPadr(pack, 'zdroj') or zdr_ip == zistiIPadr(pack, 'ciel')) and (ciel_ip == zistiIPadr(pack, 'zdroj') or ciel_ip == zistiIPadr(pack, 'ciel')):
            zdr_port = zistiUDPport(pack, "zdroj", "cislo")
            ciel_port = zistiUDPport(pack, "ciel", "cislo")
            druhy = True
            vypisV4(pack, j, 'TFTP')

        elif druhy and zistiEtyp(pack) == "IPv4" and zistiIPv4typ(pack) == "UDP" and (zdr_ip == zistiIPadr(pack, 'zdroj') or zdr_ip == zistiIPadr(pack, 'ciel')) and (ciel_ip == zistiIPadr(pack, 'zdroj') or ciel_ip == zistiIPadr(pack, 'ciel')) and (zdr_port == zistiUDPport(pack, "zdroj", "cislo") or zdr_port == zistiUDPport(pack, "ciel", "cislo")) and (ciel_port == zistiUDPport(pack, "zdroj", "cislo") or ciel_port == zistiUDPport(pack, "ciel", "cislo")):
            vypisV4(pack, j, 'TFTP')                                                                                                                                                    
                                                                                                                                                                  

def vypisARP():                                                                                             #vypise vsetky ARP dvojice v pcap subore
    j = 0
    arpkom = []
    for pack in packets:
        pack = pack[1]
        j += 1
        cieladr = ''
        zdrojadr = ''
        uzje = False
        if zistiEtyp(pack) == "ARP":
            for i in range(38,42):
                if i == 41:
                    cieladr += str(int(pack[i]))
                else:
                    cieladr += str(int(pack[i])) + '.'
            for i in range(28,32):
                if i == 31:
                    zdrojadr += str(int(pack[i]))
                else:
                    zdrojadr += str(int(pack[i])) + '.'

            if zistiARPtyp(pack) == "Request":
                for kom in arpkom:
                    if kom[0] == zdrojadr and kom[1] == cieladr:
                        kom.append(j)
                        kom.append(pack)
                        uzje = True
                        break
                    
                if not uzje:
                    arpkom.append([zdrojadr, cieladr, j, pack])

                
            elif zistiARPtyp(pack) == "Reply":
                for kom in arpkom:
                    if kom[1] == zdrojadr and kom[0] == cieladr:
                        kom.append(j)
                        kom.append(pack)
                        uzje = True
                        break
                    
                if not uzje:
                    arpkom.append([zdrojadr, cieladr, j, pack])

    poc = 0
    for kom in arpkom:
        poc += 1
        print("Komunikacia c.", poc)

        if zistiARPtyp(kom[3]) == "Request":
            print("ARP-Request, IP adresa:", kom[1], ", MAC adresa: ???")
            print("Zdrojova IP:", kom[0])
            print("Cielova IP:", kom[1])
        else:
            print("ARP-Reply, IP adresa:", kom[1], ", MAC adresa:", end = ' ')
            for i in range(6,12):
                    print(format(kom[3][i], '02x'), end = " ")
            print()
            print("Zdrojova IP:", kom[1])
            print("Cielova IP:", kom[0])

        for j in range(2, len(kom), 2):
            if zistiARPtyp(kom[j+1]) == "Reply":
                print("ARP-Reply, IP adresa:", kom[1], ", MAC adresa:", end = ' ')
                for i in range(6,12):
                    print(format(kom[j+1][i], '02x'), end = " ")
                print()
                print("Zdrojova IP:", kom[1])
                print("Cielova IP:", kom[0])
                
            print("ramec ",kom[j])
            print("dlzka ramca poskytnuta pcap API:" , len(kom[j+1]))
            print("dlzka ramca prenasaneho po mediu:" , max(len(kom[j+1]) + 4, 64))
            print("Ethernet II")
            print("ARP")
            print("Zdrojova MAC adresa:", end = " ")
            for i in range(6,12):
                print(format(kom[j+1][i], '02x'), end = " ")
                    
            print("\nCielova MAC adresa:", end = " ")
            for i in range(6):
                print(format(kom[j+1][i], '02x'), end = " ")
            print()
                
            for i in range(len(kom[j+1])):
                print(format(kom[j+1][i], '02x'), end =" ")
                if (i+1) % 16 == 0:
                    print()
                elif (i+1) % 8 == 0:
                    print(end ="  ")
                    
            print('\n')            
          
    
def vypisovacka():                                                                              #vypise vsetky ramce komunikacie
    adresy = []
    j = 0 
    for pack in packets:
        pack = pack[1]
        i = 0
        j += 1
        print("ramec ",j)
        print("dlzka ramca poskytnuta pcap API:" , len(pack))
        print("dlzka ramca prenasaneho po mediu:" , max(len(pack) + 4, 64))
        k = 0
        ciel = ''
        zdroj = ''
        dlzka = ''
        for byte in pack:
            if (k < 6):
                ciel += str(format(byte, '02x'))+' '
            elif (k < 12):
                zdroj += str(format(byte, '02x'))+' '
            elif (k < 14):
                dlzka += str(format(byte, '02x'))
            else:
                break   
            k += 1    

        dlzka = int(dlzka, 16)
        
        if dlzka > 0x05DC:
            print("Ethernet II")
        else:
            print(zistiIEEEtyp(pack))
        
        print("Zdrojova MAC adresa:", zdroj)            
        print("Cielova MAC adresa:", ciel)

        if dlzka > 0x05DC:
            print(zistiEtyp(pack))
            if zistiEtyp(pack) == "IPv4":
                ipv4(pack, adresy, 1)

        for byte in pack:
            print(format(byte, '02x'), end =" ")
            i += 1
            if i % 16 == 0:
                print()
            elif i % 8 == 0:
                print(end ="  ")
        print('\n')

    print("IP adresy vysielajucich uzlov:")

    imax = 0
    for i in range(len(adresy)):
         if i % 2 == 0:
             print(adresy[i])
             if adresy[i+1] > adresy[imax + 1]:
                 imax = i
    print("Adresa uzla s najvacsim poctom odoslanych paketov:")
    print(adresy[imax], adresy[imax+1], "paketov\n")
    

with open('eTyp.txt', 'r') as file:                                                         #otvaranie externych suborov a ukladanie informacii z nich do poli
    data = file.readlines()
    eTypPole = vratPoleTypov(data)
with open('ipv4Typ.txt', 'r') as file:
    data = file.readlines()
    ipv4TypPole = vratPoleTypov(data)
with open('tcpTyp.txt', 'r') as file:
    data = file.readlines()
    tcpTypPole = vratPoleTypov(data)
with open('udpTyp.txt', 'r') as file:
    data = file.readlines()
    udpTypPole = vratPoleTypov(data)
with open('icmpTyp.txt', 'r') as file:
    data = file.readlines()
    icmpTypPole = vratPoleTypov(data)
with open('arpTyp.txt', 'r') as file:
    data = file.readlines()
    arpTypPole = vratPoleTypov(data)
with open('ieeeTyp.txt', 'r') as file:
    data = file.readlines()
    ieeeTypPole = vratPoleTypov(data)
with open('tcpFlag.txt', 'r') as file:
    data = file.readlines()
    tcpFlagPole = vratPoleTypov(data)  

with open('trace-14.pcap', 'rb') as f:                                                      #otvaranie pcap suboru
    pcap = dpkt.pcap.Reader(f)
    packets = pcap.readpkts()

while True:                                                                                 #menu
    print("Co si prajete vypisat")
    print("1: Vsetko")
    print("2: HTTP")
    print("3: HTTPS")
    print("4: TELNET")
    print("5: SSH")
    print("6: FTP DATOVE")
    print("7: FTP RIADIACE")
    print("8: ICMP")
    print("9: ARP")
    print("10: Komunikacia TFTP")
    print("11: Komunikacia TCP")
    print("20: Ukonci program")
    vyber = int(input())
    if vyber == 1:
        vypisovacka()
    elif vyber == 2:
        vypisTCP("HTTP")
    elif vyber == 3:
        vypisTCP("HTTPS")
    elif vyber == 4:
        vypisTCP("TELNET")
    elif vyber == 5:
        vypisTCP("SSH")
    elif vyber == 6:
        vypisTCP("FTP_DATA")
    elif vyber == 7:
        vypisTCP("FTP_RIADENIE")
    elif vyber == 8:
        vypisICMP()
    elif vyber == 9: 
        vypisARP()
    elif vyber ==10:
        vypisTFTP()
    elif vyber ==11:
        port = input()
        vypisTCP1(port)
    else:
        break
