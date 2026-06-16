package security

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	// AllowedNetworks contiene una lista de redes privadas permitidas
	AllowedNetworks []net.IPNet
)

// RefreshAllowedNetworks reinicia la lista blanca usando las redes del entorno y los servicios proporcionados.
func RefreshAllowedNetworks(servicios map[string]string) {
	AllowedNetworks = nil
	allowedNets := os.Getenv("ALLOWED_NETWORKS")
	if allowedNets != "" {
		InitAllowedNetworks(allowedNets)
	}

	for _, target := range servicios {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		if ip != nil && IsPrivateIP(ip) {
			AddAllowedIP(ip)
		}
	}
}

// AddAllowedIP añade una IP individual a la lista blanca de redes permitidas.
func AddAllowedIP(ip net.IP) {
	if ip == nil {
		return
	}
	// Crear una red /32 (IPv4) o /128 (IPv6)
	mask := net.CIDRMask(len(ip)*8, len(ip)*8)
	if ip4 := ip.To4(); ip4 != nil {
		mask = net.CIDRMask(32, 32)
	}
	AllowedNetworks = append(AllowedNetworks, net.IPNet{IP: ip, Mask: mask})
}

// InitAllowedNetworks inicializa la lista de redes permitidas a partir de una cadena (ej: "192.168.30.0/24,10.0.0.0/8")
func InitAllowedNetworks(networks string) error {
	if networks == "" {
		return nil
	}
	for _, s := range strings.Split(networks, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Intentar como CIDR
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			AllowedNetworks = append(AllowedNetworks, *ipNet)
			continue
		}
		// Intentar como IP individual
		ip := net.ParseIP(s)
		if ip != nil {
			AddAllowedIP(ip)
			continue
		}
		return fmt.Errorf("formato de red inválido: %s", s)
	}
	return nil
}

// SafeDialContext resuelve DNS y valida que la IP no sea privada antes de conectar.
// Previene ataques SSRF por DNS rebinding (TOCTOU).
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var targetIP net.IP
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			allowed := false
			for _, subnet := range AllowedNetworks {
				if subnet.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("acceso a IP privada bloqueado: %s", ip.String())
			}
		}
		targetIP = ip
		break
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(targetIP.String(), port))
}

// IsValidTarget verifica que la URL de destino sea segura.
func IsValidTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("URL inválida: %v", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("esquema no permitido: %s", u.Scheme)
	}

	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("no se permite apuntar a la interfaz de loopback o IPs restringidas por seguridad")
		}
	} else if host == "localhost" {
		return fmt.Errorf("no se permite apuntar a la interfaz de loopback por seguridad")
	}

	return nil
}

// IsPrivateIP comprueba si una IP pertenece a rangos privados o reservados.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Rangos IPv4 privados (RFC 1918)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Rangos IPv6 privados (ULA)
	return (ip[0] & 0xfe) == 0xfc
}
