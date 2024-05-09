import sys
import Scan_nslookup
import Scan_Dig
import Scan_whois
import Scan_whatweb
import Scan_sub
import Recon_ng
import scan_shodan
import webbrowser
import Scan_nmap
import Harvester

def main():
    print("Footprinting and Reconnaissance:")
    print("1. Collect information ")
    print("2. Scan Network")
    print("3. Scan Recon")
    
    choice = input("Nhập số tương ứng với chức năng bạn muốn sử dụng: ")
    
    if choice == "1":
        xu_ly_chucnang1()
    elif choice == "2":
        xu_ly_chucnang2()
    elif choice == "3":
        xu_ly_chucnang3()
    else:
        print("Lựa chọn không hợp lệ.")

def xu_ly_chucnang1():
    print("Thu thập thông tin:")
    print("1. Specified Domain")
    print("2. Information Public (Search engine)")
    chon= input("Nhập số tương ứng với chức năng: ")
    if chon == "1":
        print("Nhập domain: ", end="")
        domain = input()
        record_types = ["A", "NS", "MX", "SOA"] 
        print("Đang xử lý chức năng 1...")
        
        # Mở một tệp tin để ghi dữ liệu
        with open("output.txt", "w") as f:
            f.write("Kết quả thu thập thông tin:\n")

            f.write("--------------------------------------------\n")
            f.write(f"Kết quả của NSlookup {domain}\n")
            for record_type in record_types:
                f.write(f"Truy vấn bản ghi {record_type} cho tên miền {domain}:\n")
                Scan_nslookup.query_dns_records(domain, record_type)

            f.write("--------------------------------------------\n")
            f.write("Kết quả của Dig\n")
            s_dig = Scan_Dig.dig(domain)
            f.write(s_dig + "\n")

            # f.write("--------------------------------------------\n")
            # f.write(f"Kết quả của whois {domain}\n")
            # s_whois = Scan_whois.query_whois(domain)
            # f.write(str(s_whois) + "\n")

            f.write("--------------------------------------------\n")
            f.write(f"Kết quả của whatweb {domain}\n")
            s_whatweb = Scan_whatweb.run_whatweb(domain)
            f.write(s_whatweb + "\n")

            f.write("--------------------------------------------\n")
            f.write(f"Kết quả của sublister {domain}\n")
            s_sub = Scan_sub.run_sublist3r(domain)
            f.write(s_sub + "\n")

            f.write("--------------------------------------------\n")
            f.write(f"Kết quả của nmap {domain}\n")
            nmap_output = Scan_nmap.run_nmap(domain)
            f.write(str(nmap_output) + "\n")

            f.write("--------------------------------------------\n")

        print("Kết quả đã được ghi vào tệp output.txt")
        
    elif chon == "2":
        Harvester.harvester()
    else:
        print("Lựa chọn không hợp lệ.")

def xu_ly_chucnang2():
    print("Quét mạng và các cổng dịch vụ")
    print("1. Shodan ")
    print("2. Netcraft")
    chon= input("Nhập số tương ứng với chức năng: ")
    if chon == "1":
        scan_shodan.shodan()
    elif chon == "2":
        domain = input("Nhập domain: ")
        webbrowser.open(f"https://sitereport.netcraft.com/?url=http://{domain}")
        webbrowser.open(f"https://searchdns.netcraft.com/?restriction=site+contains&host={domain}&position=limited")
    else:
        print("Lựa chọn không hợp lệ.")

def xu_ly_chucnang3():
    print("Quét thông tin bằng recon-ng")
    domain = input("Nhập domain: ")
    company = input("Nhập company: ")
    Recon_ng.recon_ng(domain, company)

if __name__ == "__main__":
    main()