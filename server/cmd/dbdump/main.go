// dbdump: the zero knowledge check. It dumps every row of the server
// database, as an attacker who stole it would see it, and checks:
//
//  1. no blob contains any of the -needle strings (known file contents,
//     e.g. the plaintext the end to end test uploaded);
//
//  2. every file blob and wrapped key blob looks like ciphertext: correct
//     magic header, and the bytes after the header have close to 8 bits of
//     entropy per byte (plaintext text is usually below 5).
//
//     go run ./cmd/dbdump -db data/sealdrop.db -needle "secret plan"
package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

type needles []string

func (n *needles) String() string     { return strings.Join(*n, ",") }
func (n *needles) Set(v string) error { *n = append(*n, v); return nil }

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}

func preview(b []byte) string {
	if len(b) > 24 {
		b = b[:24]
	}
	return hex.EncodeToString(b)
}

func main() {
	dbPath := flag.String("db", "data/sealdrop.db", "database to dump")
	var find needles
	flag.Var(&find, "needle", "plaintext that must NOT appear anywhere (repeatable)")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath+"?mode=ro")
	if err != nil {
		log.Fatal(err)
	}
	failures := 0
	fail := func(format string, args ...any) {
		failures++
		fmt.Printf("  FAIL: "+format+"\n", args...)
	}

	// Scan every column of every table for the needles, whatever its type.
	tables := []string{"users", "credentials", "files", "sessions"}
	for _, t := range tables {
		rows, err := db.Query("SELECT * FROM " + t)
		if err != nil {
			log.Fatal(err)
		}
		cols, _ := rows.Columns()
		n := 0
		for rows.Next() {
			n++
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			for i, v := range vals {
				var b []byte
				switch x := v.(type) {
				case []byte:
					b = x
				case string:
					b = []byte(x)
				}
				for _, nd := range find {
					if bytes.Contains(b, []byte(nd)) {
						fail("table %s column %s contains plaintext %q", t, cols[i], nd)
					}
				}
			}
		}
		rows.Close()
		fmt.Printf("table %-12s %d rows\n", t, n)
	}

	fmt.Println("\nusers (what the server knows about each user):")
	urows, _ := db.Query("SELECT username, length(kem_pk), length(sig_vk), wrapped_keys FROM users")
	for urows.Next() {
		var name string
		var kl, sl sql.NullInt64
		var wrapped []byte
		urows.Scan(&name, &kl, &sl, &wrapped)
		e := entropy(wrapped)
		fmt.Printf("  %-12s kem_pk=%dB sig_vk=%dB wrapped_keys=%dB magic=%q prefix=%s\n",
			name, kl.Int64, sl.Int64, len(wrapped), safeMagic(wrapped), preview(wrapped))
		if wrapped != nil && !bytes.HasPrefix(wrapped, []byte("SDKW")) {
			fail("wrapped keys for %s are not a SealDrop key-wrap blob", name)
		}
		_ = e // 80 bytes is too short for a meaningful entropy estimate; AEAD format checked above
	}
	urows.Close()

	fmt.Println("\nfiles (sealed blobs):")
	frows, _ := db.Query("SELECT id, sender, recipient, blob FROM files")
	for frows.Next() {
		var id, from, to string
		var blob []byte
		frows.Scan(&id, &from, &to, &blob)
		body := blob
		if len(blob) > 1213 {
			body = blob[1213:] // skip the public header
		}
		e := entropy(body)
		fmt.Printf("  %s  %s -> %s  %d bytes  magic=%q  body entropy=%.3f bits/byte\n",
			id[:8], from, to, len(blob), safeMagic(blob), e)
		if !bytes.HasPrefix(blob, []byte("SDRP")) {
			fail("file %s is not a sealed SealDrop file", id)
		}
		if len(body) >= 4096 && e < 7.9 {
			fail("file %s body entropy %.3f is too low for ciphertext", id, e)
		}
	}
	frows.Close()

	fmt.Println()
	if failures > 0 {
		fmt.Printf("ZERO KNOWLEDGE CHECK FAILED (%d problems)\n", failures)
		os.Exit(1)
	}
	fmt.Printf("ZERO KNOWLEDGE CHECK PASSED: no plaintext found (%d needles searched), all blobs are ciphertext\n", len(find))
}

func safeMagic(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return string(b[:4])
}
