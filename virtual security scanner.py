import psutil
import subprocess
import socket
import os

LOG_FILE = "security_log.txt"
BAN_THRESHOLD = 10

def write_log(data):
    """Log dosyasına yazma fonksiyonu"""
    with open(LOG_FILE, "a") as file:
        file.write(data + "\n")
    print(data)


def get_network_info():
    """Makinenin IP adresini ve hostname'ini loglara ekler."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        write_log(f"\n=== AĞ BİLGİLERİ ===\nHostname: {hostname}\nIP Adresi: {ip_address}")
    except Exception as e:
        write_log(f"Hata: Ağ bilgileri alınamadı! {e}")


def analyze_processes():
    """Sanal makinede çalışan süreçleri analiz eder ve loglar."""
    write_log("\n=== ÇALIŞAN SÜREÇLER ===")
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        write_log(str(proc.info))


def check_open_ports():
    """Açık portları tespit eder ve loglar."""
    write_log("\n=== AÇIK PORTLAR ===")
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'LISTEN':
            try:
                ip = socket.gethostbyaddr(conn.laddr.ip)[0]
            except:
                ip = conn.laddr.ip
            write_log(f"Port {conn.laddr.port} açık - IP: {ip} - Süreç: {conn.pid}")


def check_updates():
    """Güncellenmesi gereken paketleri listeler ve loglar."""
    write_log("\n=== GÜNCELLENMEMİŞ PAKETLER ===")
    try:
        output = subprocess.check_output("apt list --upgradable", shell=True).decode()
        write_log(output)
    except:
        write_log("Güncelleme bilgisi alınamadı.")


def update_system():
    """Kullanıcı onayı alarak sistemi ve sürücüleri günceller ve loglar."""
    confirm = input("\nSistemi ve sürücüleri güncellemek ister misiniz? (evet/hayır): ").strip().lower()

    if confirm == "evet":
        try:
            write_log("\n📌 Güncellemeler başlatılıyor...")
            update_command = "sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y && sudo apt autoremove -y"

            # Kullanıcıya terminalde sudo şifresi girme imkanı sağlayacak yeni komut
            subprocess.run([
                "gnome-terminal", "--", "bash", "-c",
                f"echo 'Lütfen terminalde sudo şifrenizi girin ve işlemi tamamlayın:'; {update_command}; exec bash"
            ])

            write_log("\n✅ Güncellemeler tamamlandı!")
        except Exception as e:
            write_log(f"❌ Güncelleme sırasında hata oluştu: {e}")
    else:
        write_log("\n🚀 Güncelleme işlemi iptal edildi.")


def find_auth_log():
    """Sistemde hangi log dosyasının kullanıldığını bulur."""
    possible_logs = ["/var/log/auth.log", "/var/log/secure"]  # Ubuntu vs CentOS log konumları
    for log_file in possible_logs:
        if os.path.exists(log_file):
            return log_file
    return None  # Eğer hiçbir dosya yoksa None döndür


def check_ssh_bruteforce():
    """SSH brute-force girişimlerini kontrol eder ve loglar."""
    log_file = find_auth_log()
    if not log_file:
        write_log("\n❌ SSH giriş loglarını bulamadık. Sistem journalctl kullanıyor olabilir.")
        return

    write_log(f"\n=== SSH BRUTE FORCE KONTROLLERİ ({log_file}) ===")
    
    try:
        # Başarısız girişlerin toplam sayısını bul
        total_failed_attempts = subprocess.check_output(f"grep 'Failed password' {log_file} | wc -l", shell=True).decode().strip()
        write_log(f"Başarısız SSH girişimleri: {total_failed_attempts}")
        
        # Saldırgan IP'leri tespit et
        command = f"grep 'Failed password' {log_file} | awk '{{print $(NF-3)}}' | sort | uniq -c | sort -nr"
        result = subprocess.check_output(command, shell=True).decode()
        
        if result.strip():
            write_log("\n🔍 Şüpheli IP adresleri ve giriş denemeleri:")
            write_log(result)
            
            # Eğer belirlenen eşik değerinden fazla deneme yapan bir IP varsa uyarı ver
            for line in result.split("\n"):
                if line.strip():
                    count, ip = line.strip().split()
                    count = int(count)
                    if count >= BAN_THRESHOLD:
                        write_log(f"🚨 UYARI! {ip} adresinden {count} başarısız giriş denemesi tespit edildi!")
                        block_ip(ip)
        else:
            write_log("📌 Şüpheli IP bulunamadı.")
    except Exception as e:
        write_log(f"Hata oluştu: {e}")


def block_ip(ip):
    """Belirtilen IP adresini iptables ile engelle."""
    confirm = input(f"⚠️ {ip} IP adresini engellemek ister misiniz? (evet/hayır): ").strip().lower()
    if confirm == "evet":
        try:
            subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            write_log(f"✅ {ip} adresi başarıyla engellendi!")
        except Exception as e:
            write_log(f"❌ IP engellenirken hata oluştu: {e}")
    else:
        write_log("🚀 IP engelleme işlemi iptal edildi.")


def run_security_tool():
    """Tüm analizleri başlatır ve loglar."""
    write_log("\n🚀 Sanal Makine Güvenlik Denetleyicisi Başlatılıyor...")
    get_network_info()
    analyze_processes()
    check_open_ports()
    check_updates()
    check_ssh_bruteforce()
    update_system()
    block_ip()
    write_log("\n✅ Güvenlik taraması tamamlandı! Log dosyası oluşturuldu.")


if __name__ == "__main__":

    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    run_security_tool()
