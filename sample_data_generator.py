# sample_data_generator.py
import csv, os, random
os.makedirs("data", exist_ok=True)
out = "data/train_small.csv"

legit_bases = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://accounts.microsoft.com",
    "https://www.github.com",
    "https://www.stackoverflow.com"
]

phish_templates = [
    "http://{sub}.{domain}.com/login",
    "http://{domain}.{evil}.com/verify",
    "http://{domain}@{evil}.com/secure",
    "http://{ip}/account/{rand}",
    "http://{domain}/free/{rand}",
    "http://{evil}-{domain}.com/{rand}"
]

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def gen_phish(domain="paypal", evil="evilsite"):
    t = random.choice(phish_templates)
    rand = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))
    return t.format(sub="login", domain=domain, evil=evil, ip=rand_ip(), rand=rand)

rows = []
for _ in range(200):
    rows.append((random.choice(legit_bases), 0))
for _ in range(300):
    rows.append((gen_phish(domain=random.choice(["paypal","google","amazon","apple","bank"]), evil=random.choice(["evil","phish","malicious","scam"])), 1))

random.shuffle(rows)
with open(out, "w", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)
    writer.writerow(["url", "label"])
    for u,l in rows:
        writer.writerow([u, l])

print("Wrote sample data to", out)
