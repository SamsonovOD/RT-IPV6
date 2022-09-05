import subprocess as s
from bs4 import BeautifulSoup

def write(capfiles, TSHARK):
    for cap in capfiles:
        console = s.check_output([TSHARK, "-r", cap+".pcapng", "-2", "-R", "(eth.src == 7c:39:53 || eth.dst == 7c:39:53) && (ipv6cp || icmpv6 || dhcpv6)", "-T", "pdml"], universal_newlines=True)
        with open(cap+".pdml", "w") as file:
            file.write(console)
    print("converted.")

def test1(soup):
    print("\n#1: Проверить наличие пакетов IPV6CP")
    ipv6cp = len(soup.find_all(attrs={"name": "ipv6cp"}))
    print("ipv6cp:", ipv6cp)
    if ipv6cp != 0: return True
    else: False

def test2(soup):
    print("\n#2: Убедиться что CPE отправило пакет RS")
    rs = len(soup.find_all(showname = "Type: Router Solicitation (133)"))
    print("Router Solicitation:", rs)
    if rs != 0: return True
    else: return False
        
def test3(soup):
    print("\n#3: Убедится что получен ответ RA")
    ra = len(soup.find_all(showname = "Type: Router Advertisement (134)"))
    print("Router Advertisement:", ra)
    if ra != 0: return True
    else: return False
        
def test4(soup):
    print("\n#4: CPE отправило запрос Solicit; Запрос содержит только поля Client identifier, Identity Association for Prefix Delegation, Elapsed time, Vendor Class, Option Request содержит DNS recursive name server")
    sol = soup.find(showname = "Message type: Solicit (1)")
    check = 0
    for option in sol.parent.find_all(attrs={"name": ""}):
        print(option.get("show"), end=", ")
        if option.get("show") == "Client Identifier": check += 1
        elif option.get("show") == "Identity Association for Prefix Delegation": check += 1
        elif option.get("show") == "Elapsed time": check += 1
        elif option.get("show") == "Vendor Class": check += 1
        elif option.get("show") == "Option Request":
            check += 1
            req = option.find(attrs={"name": "dhcpv6.requested_option_code"}).get("showname")
            print(req)
        else: check += 100
    if check == 5: return True
    else: return False
    
def test5(soup):
    print("\n#5: В ответе сервера (1275) содержится Client Identifier, Server Identifier, Identity Association for Prefix Delegation, DNS recursive name server, В поле Identity Association есть IA Prefix. Значение префикса нужно запомнить, длина префикса = 56, Поле DNS recursive name server содержит DNS")
    rep = soup.find(showname = "Message type: Reply (7)")
    check = 0
    for option in rep.parent.find_all(attrs={"name": ""}):
        print(option.get("show"), end=", ")
        if option.get("show") == "Client Identifier": check += 1
        elif option.get("show") == "Server Identifier": check += 1
        elif option.get("show") == "Identity Association for Prefix Delegation": check += 1
        elif option.get("show") == "IA Prefix":
            check += 1
            prefix = option.find(attrs={"name": "dhcpv6.iaprefix.pref_addr"}).get("show")
            pref_len = option.find(attrs={"name": "dhcpv6.iaprefix.pref_len"}).get("value")
        elif option.get("show") == "DNS recursive name server":
            check += 1
            dns = option.find(attrs={"name": "dhcpv6.dns_server"}).get("show")
        else: check += 100
    print("Prefix length:", pref_len, ", Prefix:", prefix, "DNS:", dns)
    if check == 5: return prefix, True
    else: return None, False
   
def test6(soup, prefix):
    print("\n#6 Клиент запрашивает адрес RS и CPE отвечает RA. Ответ содержит как минимум одно поле ICMPv6 Option (Prefix information : 2a01:620::/64) причем значение равно полученному на шаге 5, но длина префикса 64. Значение Valid Lifetime не равно 0. Если содержится несколько полей, то нужно проанализировать все.")
    # rs = soup.find(showname = "Type: Router Solicitation (133)") ??
    # print(rs.get("showname"), end=", ")
    ra = soup.find(showname = "Type: Router Advertisement (134)")
    print(ra.get("showname"), end=", ")
    options = soup.find_all(showname = "ICMPv6 Option (Prefix information : 2a01:::/64)")
    print(len(options))
    if len(options) > 0:
        for option in options:
            opt_prefix = option.find(attrs={"name": "icmpv6.opt.prefix"}).get("show")
            pref_len = option.find(attrs={"name": "icmpv6.opt.prefix.length"}).get("show")
            pref_life = option.find(attrs={"name": "icmpv6.opt.prefix.valid_lifetime"}).get("show")
    print("Prefix:", opt_prefix, "Prefix Length:", pref_len, "Valid Lifetime:", pref_life)
    if opt_prefix==prefix and pref_len == "64" and pref_life != "0": return True
    else: return False

def test7(soup):
    print("\n#7: Процедура получения адреса аналогична 1-5, но длина получаемого префикса 64. После получения нового адреса на WAN клиент LAN должен корректно получить новый адрес (IPV6_LAN_PPP).")
    rep = soup.find_all(showname = "Message type: Reply (7)")
    for reply in rep:
        print("")
        check = 0
        for option in reply.parent.find_all(attrs={"name": ""}):
            print(option.get("show"), end=", ")
            if option.get("show") == "Client Identifier": check += 1
            elif option.get("show") == "Server Identifier": check += 1
            elif option.get("show") == "Identity Association for Prefix Delegation": check += 1
            elif option.get("show") == "IA Prefix":
                check += 1
                prefix = option.find(attrs={"name": "dhcpv6.iaprefix.pref_addr"}).get("show")
                pref_len = option.find(attrs={"name": "dhcpv6.iaprefix.pref_len"}).get("value")
                pref_life = option.find(attrs={"name": "dhcpv6.iaprefix.valid_lifetime"}).get("show")
            elif option.get("show") == "DNS recursive name server":
                check += 1
                dns = option.find(attrs={"name": "dhcpv6.dns_server"}).get("show")
            else: check += 100
        if check == 5:
            print("Prefix length:", pref_len, ", Prefix:", prefix, "Valid Lifetime:", pref_life)
            return prefix, True
    return None, False
        
def test8(soup):
    print("\n#8 CPE отправляет в сторону клиента RA (79) который содержит старый префикс (полученный в п5.) с Valid Lifetime = 0 и новый полученный на шаге 7 Valid Lifetime > 0. Допускается что новый и старый префиксы могут быть отправлены в разных RA.")
    ras = soup.find_all(showname = "Type: Router Advertisement (134)")
    for ra in ras:
        pi = ra.parent.find_all(showname = "Type: Prefix information (3)")
        for p in pi:
            print("Prefix:", p.parent.find(attrs={"name": "icmpv6.opt.prefix"}).get("show"))
            print("Lifetime:", p.parent.find(attrs={"name": "icmpv6.opt.prefix.valid_lifetime"}).get("show"))
    
def test9(dhcpv6):
    print("\n#9 Получение IPv6 через IPoE")
  
def read(capfiles):
    with open(capfiles[0]+".pdml", "r") as file:
        soup = BeautifulSoup(file, "xml")      
        print(test1(soup))
        print(test2(soup))
        print(test3(soup))
        print(test4(soup))
        prefix, t5 = test5(soup)
        print(t5)
        
    with open(capfiles[1]+".pdml", "r") as file:
        soup = BeautifulSoup(file, "xml")
        print(test6(soup, prefix))
        
    with open(capfiles[2]+".pdml", "r") as file:
        soup = BeautifulSoup(file, "xml")
        print(test7(soup))
        
    with open(capfiles[3]+".pdml", "r") as file:
        soup = BeautifulSoup(file, "xml")
        print(test8(soup))
        
if __name__ == "__main__":
    TSHARK = "C:/Program Files/Wireshark/tshark.exe"
    capfiles = ["IPV6_WAN_PPP_TEST", "IPV6_LAN_PPP_Test", "IPV6_WAN_PPP_TEST_to_SPB", "IPV6_LAN_PPP_Test_to_SPB"]
    write(capfiles, TSHARK)
    read(capfiles)