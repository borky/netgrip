// tlscert.go — el par certificado/clave con el que el panel sirve HTTPS,
// releído del disco cuando cambia.
//
// El par por defecto es el de uhttpd, que ya está en el router: así el panel
// hereda la misma decisión de confianza que LuCI en vez de pedir una segunda.
// Ese par lo regenera px5g cuando caduca, de modo que cargarlo una sola vez
// al arrancar dejaría al panel sirviendo un certificado caducado hasta el
// siguiente reinicio - que en un router puede ser meses.
package server

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Variables y no constantes para que los tests puedan apuntarlas a un
// directorio temporal; en ejecución nadie las cambia.
var (
	// PanelCertPath y PanelKeyPath: el par que genera el propio panel desde
	// Ajustes (GenerateSelfSignedCert). Si está, es el que quiso el usuario.
	PanelCertPath = "/etc/netgrip/ssl/cert.pem"
	PanelKeyPath  = "/etc/netgrip/ssl/key.pem"

	// DefaultCertPath y DefaultKeyPath: el par de uhttpd, el reserva. Son
	// los que sirve LuCI, así que el navegador que ya aceptó ese
	// certificado no ve nada nuevo más allá del origen distinto.
	DefaultCertPath = "/etc/uhttpd.crt"
	DefaultKeyPath  = "/etc/uhttpd.key"
)

const (

	// retryAfterFailure: tras una recarga fallida (el par a medio escribir
	// mientras px5g lo regenera) no se vuelve a tocar el disco hasta pasado
	// este tiempo, para no golpear el filesystem en cada handshake.
	retryAfterFailure = 30 * time.Second
)

// CertReloader sirve un par cert/clave y lo repuebla cuando el mtime de
// alguno de los dos ficheros avanza. Si la recarga falla sigue sirviendo el
// último par válido: una regeneración a medio escribir no debe tumbar el
// listener ni, peor, dejar el panel sin responder.
type CertReloader struct {
	certPath string
	keyPath  string

	mu       sync.Mutex
	cert     *tls.Certificate
	mtime    time.Time
	lastFail time.Time
}

// NewCertReloader carga el par inicial. Devuelve error si no existe o no
// parsea: quien pidió TLS debe enterarse al arrancar, no en el primer
// handshake.
func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	if certPath == "" {
		certPath = DefaultCertPath
	}
	if keyPath == "" {
		keyPath = DefaultKeyPath
	}
	r := &CertReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// TLSConfig es la configuración del listener: GetCertificate en lugar de una
// lista estática, para que la recarga en caliente tenga efecto.
func (r *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// GetCertificate implementa tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mt, err := newestMtime(r.certPath, r.keyPath)
	if err != nil {
		return r.cert, nil // stat falla: servir lo cacheado
	}
	if mt.After(r.mtime) && time.Since(r.lastFail) > retryAfterFailure {
		if err := r.reload(); err != nil {
			r.lastFail = time.Now()
			return r.cert, nil
		}
	}
	return r.cert, nil
}

// reload repuebla la caché desde disco. Debe llamarse con r.mu tomado, salvo
// en el constructor.
func (r *CertReloader) reload() error {
	cert, err := loadPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	mt, err := newestMtime(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.mtime = mt
	r.lastFail = time.Time{}
	return nil
}

// newestMtime es el mtime más reciente de los dos ficheros: basta con que uno
// se mueva para que el par sea otro.
func newestMtime(paths ...string) (time.Time, error) {
	var newest time.Time
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return time.Time{}, err
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest, nil
}

// loadPair lee el par en cualquiera de las dos codificaciones.
//
// OpenWrt guarda el de uhttpd en DER: /etc/uhttpd.crt empieza por 30 82
// (SEQUENCE ASN.1), no por "-----BEGIN", porque ustream-ssl lo lee así. La
// biblioteca estándar de Go solo entiende PEM, de modo que cargar el par del
// router - que es justo lo que hace útil esta opción - exige reconocer
// ambas. Comprobado en un router, no deducido: con solo PEM el panel se
// negaba a arrancar.
func loadPair(certPath, keyPath string) (tls.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if bytes.Contains(certBytes, []byte("-----BEGIN")) {
		return tls.X509KeyPair(certBytes, keyBytes)
	}
	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate is neither PEM nor DER: %w", err)
	}
	key, err := parseDERKey(keyBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: key, Leaf: leaf}, nil
}

// parseDERKey acepta las tres formas en que una clave puede venir en DER;
// px5g escribe EC (SEC1) con la configuración por defecto de OpenWrt, pero un
// par propio puede ser PKCS#8 o RSA.
func parseDERKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("private key is neither PEM nor DER (EC, PKCS#8 or PKCS#1)")
}

// certCandidates son los pares a probar, en el orden en que un usuario lo
// esperaría: lo que pidió explícitamente; si no, el que generó desde el
// panel; si no, el de uhttpd, que en un router siempre está.
//
// El par propio va antes que el de uhttpd a propósito: generarlo es un acto
// deliberado desde Ajustes, y quien lo hizo esperaba que se usara.
func certCandidates(certPath, keyPath string) [][2]string {
	var out [][2]string
	if certPath != "" && keyPath != "" {
		out = append(out, [2]string{certPath, keyPath})
	}
	return append(out,
		[2]string{PanelCertPath, PanelKeyPath},
		[2]string{DefaultCertPath, DefaultKeyPath},
	)
}

// ResolveCertPaths es el par que se serviría: el primero que exista.
func ResolveCertPaths(certPath, keyPath string) (string, string) {
	for _, c := range certCandidates(certPath, keyPath) {
		if fileExists(c[0]) && fileExists(c[1]) {
			return c[0], c[1]
		}
	}
	return DefaultCertPath, DefaultKeyPath
}

// OpenCertificate abre el primer par utilizable y dice cuál fue.
//
// Que el par configurado falte o no cargue no es razón para dejar el panel
// sin arrancar: un certificado borrado, un fichero a medio escribir o una
// ruta que apunta a donde ya no hay nada dejarían el router sin panel hasta
// que alguien entre por SSH. Se sirve otro y se avisa. Lo que no se hace
// nunca es caer a texto plano: si ninguno sirve, esto devuelve error y quien
// llama se niega a arrancar.
func OpenCertificate(certPath, keyPath string) (r *CertReloader, usedCert, usedKey string, err error) {
	var firstErr error
	for _, c := range certCandidates(certPath, keyPath) {
		r, err := NewCertReloader(c[0], c[1])
		if err == nil {
			return r, c[0], c[1], nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, "", "", firstErr
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
