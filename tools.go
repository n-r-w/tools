// Package tools Различные фукции общего назначения
package tools

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/n-r-w/nerr"
	"golang.org/x/crypto/bcrypt"
)

// EncryptPassword Генерация хэша пароля
func EncryptPassword(s string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(s)), bcrypt.MinCost)
	if err != nil {
		return "", nerr.New("failed GenerateFromPassword", err)
	}

	return string(b), nil
}

// ComparePassword Подходит ли пароль
func ComparePassword(encryptedPassword string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encryptedPassword), []byte(password)) == nil
}

// RequiredIf Валидатор для проверки по условию
func RequiredIf(cond bool) validation.RuleFunc {
	return func(value interface{}) error {
		if cond {
			return nerr.New(fmt.Scanf("failed validation %v", validation.Validate(value, validation.Required)))
		}

		return nil
	}
}

// PanicIf паника если выполнено условие
func PanicIf(cond bool) {
	if cond {
		if pc, file, line, ok := runtime.Caller(1); ok {
			details := runtime.FuncForPC(pc)
			place := fmt.Sprintf("%s (%s:%d)", details.Name(), file, line)
			panic(place)
		}
	}
}

// CompressData Сжатие массива данных
func CompressData(deflateCompression bool, data []byte) (resData []byte, err error) {
	if data == nil {
		return []byte{}, nil
	}

	// алгоритм сжатия
	var compressor io.WriteCloser
	// целевой буфер
	var compressedBuf bytes.Buffer

	// сжимаем по нужному алгоритму
	if deflateCompression {
		if compressor, err = flate.NewWriter(&compressedBuf, flate.BestSpeed); err != nil {
			return nil, nerr.New(err, "deflate error")
		}
	} else {
		if compressor, err = gzip.NewWriterLevel(&compressedBuf, gzip.BestSpeed); err != nil {
			return nil, nerr.New(err, "gzip error")
		}
	}

	if _, err := compressor.Write(data); err != nil {
		return nil, nerr.New(err, "compress error")
	}

	if err := compressor.Close(); err != nil {
		return nil, nerr.New(err, "compress error")
	}

	return compressedBuf.Bytes(), nil
}

// Sha256sum - вычисление контрольной суммы
func Sha256sum(data []byte) (string, error) {
	h := sha256.New()
	buf := bytes.NewBuffer(data)

	if _, err := io.Copy(h, buf); err != nil {
		return "", nerr.New(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Убирает из строки лишние пробелы, символы табуляции, переносы строк
func SimplifyString(s string) string {
	var res []byte
	tfound := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\t' {
			if !tfound {
				res = append(res, byte(' '))
			}
			tfound = true
			continue
		}
		tfound = false
		res = append(res, c)
	}

	return string(res)
}
