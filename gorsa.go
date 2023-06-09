package gorsa

import (
	"encoding/base64"
)

// PublicEncryptBytes 公钥加密
func PublicEncryptBytes(data []byte, publicKey string) (string, error) {
	gRsa := RSASecurity{}
	gRsa.SetPublicKey(publicKey)

	rsaData, err := gRsa.PubKeyENCTYPT(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsaData), nil
}

// PublicEncryptString 公钥加密
func PublicEncryptString(data, publicKey string) (string, error) {
	return PublicEncryptBytes([]byte(data), publicKey)
}

// PriKeyEncryptBytes 私钥加密
func PriKeyEncryptBytes(data []byte, privateKey string) (string, error) {
	gRsa := RSASecurity{}
	gRsa.SetPrivateKey(privateKey)

	rsaData, err := gRsa.PriKeyENCTYPT(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rsaData), nil
}

// PriKeyEncryptString 私钥加密
func PriKeyEncryptString(data, privateKey string) (string, error) {
	return PriKeyEncryptBytes([]byte(data), privateKey)
}

// PublicDecryptBytes 公钥解密
func PublicDecryptBytes(data string, publicKey string) ([]byte, error) {
	gRsa := RSASecurity{}
	if err := gRsa.SetPublicKey(publicKey); err != nil {
		return nil, err
	}

	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	decData, err := gRsa.PubKeyDECRYPT(dataByte)
	if err != nil {
		return nil, err
	}

	return decData, nil
}

// PublicDecryptString 公钥解密
func PublicDecryptString(data, publicKey string) (string, error) {
	decData, err := PublicDecryptBytes(data, publicKey)

	if err != nil {
		return "", err
	}

	return string(decData), nil
}

// PriKeyDecryptBytes 私钥解密
func PriKeyDecryptBytes(data string, privateKey string) ([]byte, error) {
	dataBs, _ := base64.StdEncoding.DecodeString(data)
	gRsa := RSASecurity{}

	if err := gRsa.SetPrivateKey(privateKey); err != nil {
		return nil, err
	}

	decData, err := gRsa.PriKeyDECRYPT(dataBs)
	if err != nil {
		return nil, err
	}

	return decData, nil
}

// PriKeyDecryptString 私钥解密
func PriKeyDecryptString(data, privateKey string) (string, error) {
	decData, err := PriKeyDecryptBytes(data, privateKey)
	if err != nil {
		return "", err
	}
	return string(decData), nil
}
