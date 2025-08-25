text = 'YNNJC MLGML TGJJYEC QNPYW'
newtext = ''
for i in range(1,26):
    for j in range(len(text)):
        if text[j] == ' ':
            newtext += text[j]
        else:
            newtext += chr((ord(text[j])+1)%26)
    print(newtext)
    newtext = ''



    # Not finished yet.