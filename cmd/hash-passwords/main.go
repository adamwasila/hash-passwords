package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// kPasswordPrefix matches SPH_kPasswordPrefix in hashed-password.js
const kPasswordPrefix = "@@"

// knownSLDs mirrors the domain list in domain-extractor.js
var knownSLDs = func() map[string]bool {
	list := "ab.ca|ac.ac|ac.at|ac.be|ac.cn|ac.il|ac.in|ac.jp|ac.kr|ac.nz|ac.th|ac.uk|ac.za|adm.br|adv.br|agro.pl|ah.cn|aid.pl|alt.za|am.br|arq.br|art.br|arts.ro|asn.au|asso.fr|asso.mc|atm.pl|auto.pl|bbs.tr|bc.ca|bio.br|biz.pl|bj.cn|br.com|cn.com|cng.br|cnt.br|co.ac|co.at|co.il|co.in|co.jp|co.kr|co.nz|co.th|co.uk|co.za|com.au|com.br|com.cn|com.ec|com.fr|com.hk|com.mm|com.mx|com.pl|com.ro|com.ru|com.sg|com.tr|com.tw|cq.cn|cri.nz|de.com|ecn.br|edu.au|edu.cn|edu.hk|edu.mm|edu.mx|edu.pl|edu.tr|edu.za|eng.br|ernet.in|esp.br|etc.br|eti.br|eu.com|eu.lv|fin.ec|firm.ro|fm.br|fot.br|fst.br|g12.br|gb.com|gb.net|gd.cn|gen.nz|gmina.pl|go.jp|go.kr|go.th|gob.mx|gov.br|gov.cn|gov.ec|gov.il|gov.in|gov.mm|gov.mx|gov.sg|gov.tr|gov.za|govt.nz|gs.cn|gsm.pl|gv.ac|gv.at|gx.cn|gz.cn|hb.cn|he.cn|hi.cn|hk.cn|hl.cn|hn.cn|hu.com|idv.tw|ind.br|inf.br|info.pl|info.ro|iwi.nz|jl.cn|jor.br|jpn.com|js.cn|k12.il|k12.tr|lel.br|ln.cn|ltd.uk|mail.pl|maori.nz|mb.ca|me.uk|med.br|med.ec|media.pl|mi.th|miasta.pl|mil.br|mil.ec|mil.nz|mil.pl|mil.tr|mil.za|mo.cn|muni.il|nb.ca|ne.jp|ne.kr|net.au|net.br|net.cn|net.ec|net.hk|net.il|net.in|net.mm|net.mx|net.nz|net.pl|net.ru|net.sg|net.th|net.tr|net.tw|net.za|nf.ca|ngo.za|nm.cn|nm.kr|no.com|nom.br|nom.pl|nom.ro|nom.za|ns.ca|nt.ca|nt.ro|ntr.br|nx.cn|odo.br|on.ca|or.ac|or.at|or.jp|or.kr|or.th|org.au|org.br|org.cn|org.ec|org.hk|org.il|org.mm|org.mx|org.nz|org.pl|org.ro|org.ru|org.sg|org.tr|org.tw|org.uk|org.za|pc.pl|pe.ca|plc.uk|ppg.br|presse.fr|priv.pl|pro.br|psc.br|psi.br|qc.ca|qc.com|qh.cn|re.kr|realestate.pl|rec.br|rec.ro|rel.pl|res.in|ru.com|sa.com|sc.cn|school.nz|school.za|se.com|se.net|sh.cn|shop.pl|sk.ca|sklep.pl|slg.br|sn.cn|sos.pl|store.ro|targi.pl|tj.cn|tm.fr|tm.mc|tm.pl|tm.ro|tm.za|tmp.br|tourism.pl|travel.pl|tur.br|turystyka.pl|tv.br|tw.cn|uk.co|uk.com|uk.net|us.com|uy.com|vet.br|web.za|web.com|www.ro|xj.cn|xz.cn|yk.ca|yn.cn|za.com"
	m := make(map[string]bool)
	for _, s := range strings.Split(list, "|") {
		m[s] = true
	}
	return m
}()

// extractDomain replicates SPH_DomainExtractor.extractDomain from domain-extractor.js.
func extractDomain(host string) string {
	host = strings.Replace(host, "http://", "", 1)
	host = strings.Replace(host, "https://", "", 1)

	// Take the part before the first '/'
	re := regexp.MustCompile(`([^/]+)`)
	if m := re.FindString(host); m != "" {
		host = m
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		s := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if knownSLDs[s] {
			s = parts[len(parts)-3] + "." + s
		}
		return s
	}
	return strings.Join(parts, ".")
}

// applyConstraints replicates SPH_HashedPassword._applyConstraints from hashed-password.js.
// It ensures the result contains upper, lower, digit, and (optionally) non-alphanumeric chars.
func applyConstraints(hash string, size int, nonalphanumeric bool) string {
	startingSize := size - 4
	if startingSize < 0 {
		startingSize = 0
	}
	if startingSize > len(hash) {
		startingSize = len(hash)
	}

	result := hash[:startingSize]
	extras := []byte(hash[startingSize:])

	nextExtra := func() int {
		if len(extras) > 0 {
			c := int(extras[0])
			extras = extras[1:]
			return c
		}
		return 0
	}
	nextExtraChar := func() string {
		return string(rune(nextExtra()))
	}
	nextBetween := func(base rune, interval int) string {
		return string(rune(int(base) + nextExtra()%interval))
	}
	contains := func(re *regexp.Regexp) bool {
		return re.MatchString(result)
	}

	upperRe := regexp.MustCompile(`[A-Z]`)
	lowerRe := regexp.MustCompile(`[a-z]`)
	digitRe := regexp.MustCompile(`[0-9]`)
	nonalnumRe := regexp.MustCompile(`\W`)

	// Each contains() call reads the current value of result (updated by prior appends).
	if contains(upperRe) {
		result += nextExtraChar()
	} else {
		result += nextBetween('A', 26)
	}
	if contains(lowerRe) {
		result += nextExtraChar()
	} else {
		result += nextBetween('a', 26)
	}
	if contains(digitRe) {
		result += nextExtraChar()
	} else {
		result += nextBetween('0', 10)
	}
	if contains(nonalnumRe) && nonalphanumeric {
		result += nextExtraChar()
	} else {
		result += "+"
	}

	// Replace any remaining non-alphanumeric chars when nonalphanumeric is false.
	for contains(nonalnumRe) && !nonalphanumeric {
		loc := nonalnumRe.FindStringIndex(result)
		if loc == nil {
			break
		}
		result = result[:loc[0]] + nextBetween('A', 26) + result[loc[1]:]
	}

	// Rotate left — replicates: while(amount--) arr.push(arr.shift())
	amount := nextExtra()
	runes := []rune(result)
	n := len(runes)
	if n > 0 && amount > 0 {
		rotateBy := amount % n
		runes = append(runes[rotateBy:], runes[:rotateBy]...)
	}
	return string(runes)
}

// b64HmacMD5 replicates b64_hmac_md5(key, data) from md5.js.
// The JS binl2b64 uses standard base64 alphabet with b64pad="" (no padding).
func b64HmacMD5(key, data string) string {
	h := hmac.New(md5.New, []byte(key))
	h.Write([]byte(data))
	sum := h.Sum(nil)
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(sum)
}

// generateOriginalHash replicates generatePwdHash + SPH_HashedPassword from the extension.
func generateOriginalHash(site, password string) string {
	domain := extractDomain(site)

	// Strip @@ prefix if present (mirrors pwdhash-core.js logic).
	data := password
	if strings.HasPrefix(data, kPasswordPrefix) {
		data = data[len(kPasswordPrefix):]
	}

	hash := b64HmacMD5(data, domain)
	size := len(data) + len(kPasswordPrefix)
	nonalphanumeric := regexp.MustCompile(`\W`).MatchString(data)
	return applyConstraints(hash, size, nonalphanumeric)
}

// pbkdf2SHA256 derives a key using PBKDF2-SHA256 without external dependencies.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size // 32
	numBlocks := (keyLen + hashLen - 1) / hashLen

	result := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		// U1 = PRF(Password, Salt || INT(block))
		u := func() []byte {
			s := make([]byte, len(salt)+4)
			copy(s, salt)
			s[len(salt)] = byte(block >> 24)
			s[len(salt)+1] = byte(block >> 16)
			s[len(salt)+2] = byte(block >> 8)
			s[len(salt)+3] = byte(block)
			h := hmac.New(sha256.New, password)
			h.Write(s)
			return h.Sum(nil)
		}()

		t := make([]byte, hashLen)
		copy(t, u)
		for i := 1; i < iterations; i++ {
			h := hmac.New(sha256.New, password)
			h.Write(u)
			u = h.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}

// generateStrongHash replicates the generateStrongPwdHash function from popup.js.
// Uses PBKDF2-SHA256 with 100 000 iterations, site as salt.
func generateStrongHash(site, password string) string {
	domain := extractDomain(site)

	key := pbkdf2SHA256([]byte(password), []byte(domain), 100_000, 32)
	// btoa() in JS produces standard base64 with padding.
	hash := base64.StdEncoding.EncodeToString(key)
	size := len(password) + len(kPasswordPrefix)
	nonalphanumeric := regexp.MustCompile(`\W`).MatchString(password)
	return applyConstraints(hash, size, nonalphanumeric)
}

func main() {
	var (
		flagOriginal = flag.Bool("original", false, "Use original HMAC-MD5 algorithm (default)")
		flagStrong   = flag.Bool("strong", false, "Use strong PBKDF2-SHA256 algorithm")
		flagHostname = flag.String("hostname", "", "Site hostname or URL (required)")
	)
	flag.Parse()

	if *flagHostname == "" {
		fmt.Fprintln(os.Stderr, "error: -hostname is required")
		flag.Usage()
		os.Exit(1)
	}
	if *flagOriginal && *flagStrong {
		fmt.Fprintln(os.Stderr, "error: specify only one of -original or -strong")
		os.Exit(1)
	}
	useStrong := !*flagOriginal // default (neither flag) → strong

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "error: could not read password from stdin")
		os.Exit(1)
	}
	password := scanner.Text()

	var result string
	if useStrong {
		result = generateStrongHash(*flagHostname, password)
	} else {
		result = generateOriginalHash(*flagHostname, password)
	}

	fmt.Println(result)
}
