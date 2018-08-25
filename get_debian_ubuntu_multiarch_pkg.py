#!/usr/bin/python
#Python 10.8.18 SM V2 13.8.18 TM V3 18.8.18
import sys
import os


distri_url = sys.argv[1]
pkg = 'Packages.xz'
outputdatei = sys.argv[2]
pkg_url = (distri_url)+(pkg)

print ("Distri-URL:",distri_url)
print ("Package:", pkg_url)


try:
    os.system('wget %s' %pkg_url)
except:
    print("[!] Package konnte nicht heruntergeladen werden")
    exit

try:
    os.system("unxz Packages.xz") #####
except:
    print("[!] Datei konnte nicht entpackt werden")
    exit

try:
    fileopen = open("Packages", "r") #Datei die geoeffnet wird
except:
    print("[!] Datei Packages konnte nicht geoeffnet werden")
    exit

    
filewrite = open(outputdatei, "w") # Datei in die geschrieben wird
p,v,a,m,s = "Package:","Version:","Architecture:","Multi-Arch","SHA256:"
Package, Version, Architecture, Multiarch= "None","None","None","None"

for line in fileopen:
    if p in line:
        Package = line.split(" " , 1)
        Package = Package[1].split("\n")
        Package = Package[0]

    elif v in line:
        Version = line.split(" " , 1)
        Version = Version[1].split("\n")
        Version = Version[0]

    elif a in line:
        Architecture = line.split(" " ,1)
        Architecture = Architecture[1].split("\n")
        Architecture = Architecture[0]

    elif m in line:
        Multiarch = line.split(" " , 1)
        Multiarch = Multiarch[1].split("\n")
        Multiarch = Multiarch[0]

    elif s in line:
        if(Package!="None" and Version!="None" and Architecture!="None" and Multiarch!="None"):   
            filewrite.write("{} {} {} {}\n".format(Package, Version, Architecture, Multiarch))
        Package, Version, Architecture, Multiarch= "None","None","None","None"
        
fileopen.close()
filewrite.close()
os.remove ('Packages')

