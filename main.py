import hashlib
import json
import os

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

# Test etmek için alt kısma basit bir menü ekleyebilirsin
if __name__ == "__main__":
    print("--- TrustVerify CLI Tool ---")
    # create_manifest(".")
    check_integrity()
    # Buraya CLI komutlarını ekleyebilirsin