package main

import (
	"crypto/sha1"
	"encoding/hex"
	_ "fmt"
	"io"
	"os"
)

type File struct {
	Path            string `json:"Path" xml:"path"`
	Size            int64  `json:"Size" xml:"size"`
	Hash            string `json:"Hash" xml:"hash"`
	FastFingerprint bool   `json:"FastFingerprint" xml:"fastfingerprint"`
}

func (this *File) GetFileHash(maxBytes int) (string, int64, error) {

	//fmt.Println("\t****GetFileHash: ", this.Path)
	fi, err := os.Open(this.Path)
	if err != nil {
		return "", 0, err
	}

	defer func() {
		if err := fi.Close(); err != nil {
			return
		}
	}()

	// Get the filesize for the fstat system call
	fstat, err := os.Stat(this.Path)
	if err != nil {
		return "", 0, err
	}
	fSize := fstat.Size()

	// Used to be 1K, but increased to 4K in order to decrease number of reads
	var buf []byte
	buffSize1 := 2048
	buffSize2 := 4096

	if this.FastFingerprint {

		if fSize < int64(buffSize1) {

			buf = make([]byte, fSize)
			buffSize1 = int(fSize / 3)

		} else {
			buf = make([]byte, buffSize1)
		}

	} else {

		if fSize < int64(buffSize2) {

			buf = make([]byte, fSize)
			buffSize2 = int(fSize / 3)
		} else {
			buf = make([]byte, buffSize2)
		}

	}

	hash := sha1.New()

	// If fast finger print option is enable, the determine the 3 parts where a finger print will be taken
	fpBlock := make([]int64, 3)
	if this.FastFingerprint {
		fpBlock[0] = 0
		fpBlock[1] = (fSize / int64(2)) - (int64(buffSize1) / int64(2))
		fpBlock[2] = fSize - int64(buffSize1)
	}

	var totalBytes int64

	// Now loop and fill the buffer with data until non is left
	i := 0
	n := 0
	for {

		if this.FastFingerprint {
			n, err = fi.ReadAt(buf, fpBlock[i])
			i++
		} else {
			n, err = fi.Read(buf)
		}

		if err != nil && err != io.EOF {
			return "", 0, err
		}

		totalBytes += int64(n)

		// If no more data to enter into the buffer, then break out of loop
		if n == 0 {
			break
		}

		// if it's a fast finger print, and all 3 pieces have been read, then break out
		if this.FastFingerprint && i >= 2 {
			break
		}

		if _, err := io.WriteString(hash, string(buf[:n])); err != nil {
			return "", 0, err
		}

		// If we only want to read a certain ammount of bytes, then return when we reach that number
		if maxBytes > 0 && totalBytes >= int64(maxBytes) || totalBytes > fSize {
			break
		}
	}

	return string(hex.EncodeToString(hash.Sum(nil))), totalBytes, nil

}
