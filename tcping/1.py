import glob
import json
import os


def S():
    domain = {}

    file_list = glob.glob(r"D:\golang\src\github.com\gamexg\TlsScanner\google-ip\*\*-443.txt")

    for fpath in file_list:
        filename = os.path.basename(fpath)
        ip = filename.replace("-443.txt", "")

        with open(fpath, "rb") as f:
            j = json.load(f, encoding="utf-8")
            certificatess = j.get("VerifiedChains", [])
            if certificatess!=None:
                for certificates in certificatess:
                    if certificates!=None:
                        for c in certificates:
                            dnsNames = c.get("DNSNames", [])
                            if dnsNames == None:
                                continue
                            for n in dnsNames:
                                domain.setdefault(n, set())
                                domain[n].add(ip)
                                # print(n, ip)

    for k,v in domain.iteritems():
        domain[k]=list(v)

    with open(r"D:\golang\src\github.com\gamexg\TlsScanner\google-ip\ip.txt", "wb") as f:
        json.dump(domain, f)


if __name__ == '__main__':
    S()
