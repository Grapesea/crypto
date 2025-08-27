import base64
import string
string1 = "JKLMNOxyUVzABCDEFGH789PQIabcdefghijklmWXYZ0123456RSTnopqrstuvw+/="
str = 'FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw'
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

print(base64.b64decode(str.translate(str.maketrans(string1, string2))).decode())