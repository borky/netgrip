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
	"crypto/tls"
	"os"
	"sync"
	"time"
)

const (
	// DefaultCertPath y DefaultKeyPath: el par de uhttpd. Son los que sirve
	// LuCI, así que el navegador que ya aceptó ese certificado no ve nada
	// nuevo más allá del origen distinto (host:puerto).
	DefaultCertPath = "/etc/uhttpd.crt"
	DefaultKeyPath  = "/etc/uhttpd.key"

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
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
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
