import os
import re
import sys

asName = []
asCountry = []

f = open('listAS','r')

for line in f.readlines():
    split = line.split(" |")
    asInfo = split[2].rstrip()
    if asInfo == ' NA' or asInfo == '':
        continue
        
    split2 = asInfo.split(",")
    

    if not (split2[0] in asName):
        asName.append(split2[0])
    
    if len(split2) == 2 and not (split2[1] in asCountry):
        asCountry.append(split2[1].rstrip())
            


print "number of ASes = " + str(len(asName))

print "number of countries = " + str(len(asCountry))

i= 0
for x in sorted(asCountry):
    i += 1
    
print asCountry
