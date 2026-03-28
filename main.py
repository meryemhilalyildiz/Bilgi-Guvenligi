import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Görev 1: SHA-256 Hash Üretme [cite: 8]
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Dosyayı parça parça okuyarak belleği koruruz
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Görev 2: Manifest (metadata.json) Oluşturucu [cite: 9]
def create_manifest(directory):
    manifest = {}
    for filename in os.listdir(directory):
        print(f"Checking file: {filename}")
        # Sadece dosyaları tara, klasörleri ve manifest'in kendisini atla
        if os.path.isfile(filename) and filename != "metadata.json":
            manifest[filename] = calculate_hash(filename)
            print(f"Added {filename} to manifest")
    
    with open("metadata.json", "w") as f:
        json.dump(manifest, f, indent=4)
    print("✅ metadata.json oluşturuldu.")

# Görev 3: Kontrol (Check) Fonksiyonu [cite: 10]
def check_integrity():
    if not os.path.exists("metadata.json"):
        print("❌ Hata: metadata.json bulunamadı!")
        return

    with open("metadata.json", "r") as f:
        old_manifest = json.load(f)

    for filename, old_hash in old_manifest.items():
        if not os.path.exists(filename):
            print(f"⚠️ Uyarı: {filename} dosyası kayıp!")
            continue
        
        current_hash = calculate_hash(filename)
        if current_hash == old_hash:
            print(f"✅ {filename}: Değişiklik yok.")
        else:
            print(f"🚨 KRİTİK: {filename} KURCALANMIŞ! (Hash uyuşmuyor)")
# test kısmı
def generate_keys():
    # Görev 4: Anahtar Çifti Üretme [cite: 12]
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("🔑 RSA Anahtarlar (Public/Private) başarıyla üretildi.")

def sign_manifest():
    # Görev 5: İmzalama [cite: 13]
    if not os.path.exists("private_key.pem"):
        print("❌ Hata: Önce anahtarları üretmelisin (Seçenek 2).")
        return

    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open("metadata.json", "rb") as f:
        manifest_data = f.read()

    signature = private_key.sign(
        manifest_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("✍️ Manifest (metadata.json) Private Key ile imzalandı.")

def verify_signature():
    # Görev 6: Doğrulama [cite: 14]
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open("metadata.json", "rb") as f:
            manifest_data = f.read()
        with open("signature.sig", "rb") as f:
            signature = f.read()

        public_key.verify(signature, manifest_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("🛡️ İMZA DOĞRULANDI: Manifest güvenilir bir kaynaktan geliyor.")
        check_integrity() # İmza doğruysa dosyaları kontrol et
    except Exception:
        print("❌ HATA: İmza geçersiz! Manifest kurcalanmış veya sahte!")

# --- ANA MENÜ ---
if __name__ == "__main__":
    while True:
        print("\n--- TrustVerify CLI Tool ---")
        print("1. Manifest Oluştur (Dosyaları Hashle)")
        print("2. RSA Anahtar Çifti Üret")
        print("3. Manifest'i İmzala (Sign)")
        print("4. İmzayı ve Dosyaları Doğrula (Verify)")
        print("5. Çıkış")
        
        secim = input("Yapmak istediğiniz işlemi seçin (1-5): ")
        
        if secim == "1": create_manifest(".")
        elif secim == "2": generate_keys()
        elif secim == "3": sign_manifest()
        elif secim == "4": verify_signature()
        elif secim == "5": break
        else: print("Geçersiz seçim!")