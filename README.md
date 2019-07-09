# encode-me
This tool takes in input a payload and generates a list of encoded payloads based on 34 tampering functions (credits to whatwaf).
The list of encoded payloads can be used to test the WAF.


# Usage

Generate about 40k encoded payload based on tampering functions
```
go run encode-me.go -p "<script> alert(1) </script>"  > list.txt
```
The list may contain duplicates. So let's delete them using awk
```
awk '!seen[$0]++' list.txt > listFinal.txt
```
