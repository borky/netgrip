// selfsigned.go — el certificado que el panel genera para servirse por HTTPS.
//
// Se construye aquí en vez de llamar a px5g u openssl. No es por evitar un
// fork: es que el par que salía de ahí llevaba una extensión
// subjectAltName VACÍA, que OpenSSL y curl aceptan y Chromium rechaza de
// plano - "the website sent scrambled credentials", sin opción de
// continuar. Un certificado que ningún navegador basado en Chromium puede
// cargar no sirve para un panel web.
//
// Generarlo con crypto/x509 también permite meter las direcciones del
// router en el SAN, que es lo que decide si el navegador avisa por nombre
// que no coincide, y quita la dependencia de que px5g u openssl estén
// instalados.
package modules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// selfSignedValidity: dos años. Bastante para no tener que pensar en ello y
// poco para que un par filtrado no valga una década.
const selfSignedValidity = 2 * 365 * 24 * time.Hour

// buildSelfSigned crea el par en memoria. Puro salvo por la fuente de
// aleatoriedad, para poder comprobar en un test lo que de verdad importa:
// que el SAN lleva algo.
func buildSelfSigned(hostname string, addrs []net.IP, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("serial: %w", err)
	}
	if hostname == "" {
		hostname = "netgrip"
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             now.Add(-time.Hour), // margen para relojes sin RTC
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		// El SAN es lo que miran los navegadores; el CN lo ignoran desde
		// hace años. Van el nombre del equipo y todas sus direcciones, para
		// que entrar por IP -que es como se entra a un router- no dé aviso
		// de nombre que no coincide.
		DNSNames:    []string{hostname},
		IPAddresses: addrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// localAddresses son las direcciones por las que se puede llegar al panel,
// sin loopback ni enlaces locales: entran en el SAN.
func localAddresses() []net.IP {
	var out []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			out = append(out, ipn.IP)
		}
	}
	// Loopback al final: entrar por 127.0.0.1 es raro pero los
	// healthchecks lo hacen.
	return append(out, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
}

// writeSelfSigned deja el par en disco con los permisos que corresponden a
// una clave privada.
func writeSelfSigned(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
