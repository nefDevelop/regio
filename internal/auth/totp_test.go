package auth

import (
	"testing"
	"time"
)

// TestVerifyTOTPConVentana cubre la ventana de deriva ±1 epoch y la
// comparación constante (mejora A2).
func TestVerifyTOTPConVentana(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	actual := time.Now().Unix() / 30

	t.Run("código del epoch actual es válido", func(t *testing.T) {
		ok, epoch := VerifyTOTP(secret, GetTOTPCodeAt(secret, actual))
		if !ok {
			t.Error("el código vigente debe ser válido")
		}
		if epoch != actual {
			t.Errorf("epoch = %d; want %d", epoch, actual)
		}
	})

	t.Run("deriva de -30s (epoch-1) aceptada", func(t *testing.T) {
		ok, epoch := VerifyTOTP(secret, GetTOTPCodeAt(secret, actual-1))
		if !ok {
			t.Error("el código de la ventana -1 debe aceptarse (deriva de reloj)")
		}
		if epoch != actual-1 {
			t.Errorf("epoch = %d; want %d", epoch, actual-1)
		}
	})

	t.Run("deriva de +30s (epoch+1) aceptada", func(t *testing.T) {
		if ok, _ := VerifyTOTP(secret, GetTOTPCodeAt(secret, actual+1)); !ok {
			t.Error("el código de la ventana +1 debe aceptarse")
		}
	})

	t.Run("epoch-2 rechazado (fuera de ventana)", func(t *testing.T) {
		if ok, _ := VerifyTOTP(secret, GetTOTPCodeAt(secret, actual-2)); ok {
			t.Error("dos epochs de desfase queda fuera de la ventana ±1")
		}
	})

	t.Run("basura y vacío rechazados", func(t *testing.T) {
		if ok, _ := VerifyTOTP(secret, "abcdefgh"); ok {
			t.Error("código no numérico de 6 dígitos debe rechazarse")
		}
		if ok, _ := VerifyTOTP(secret, ""); ok {
			t.Error("código vacío debe rechazarse")
		}
		if ok, _ := VerifyTOTP("", GetTOTPCodeAt(secret, actual)); ok {
			t.Error("secret vacío debe rechazarse")
		}
	})

	t.Run("GetTOTPCode sigue devolviendo el vigente", func(t *testing.T) {
		if GetTOTPCode(secret) != GetTOTPCodeAt(secret, time.Now().Unix()/30) {
			t.Error("GetTOTPCode debe equivaler a GetTOTPCodeAt(epoch actual)")
		}
	})
}
