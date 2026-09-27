package auth

import "testing"

// Benchmarks del coste de almacenamiento de contraseñas (Argon2id).
// El coste es intencionado: solo miden la evolución de los parámetros (A3).

func BenchmarkHashPassword(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		HashPassword("contrasena-de-benchmark-123")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	// Pre-generar el hash para medir SOLO la verificación
	hash := HashPassword("contrasena-de-benchmark-123")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !VerifyPassword("contrasena-de-benchmark-123", hash) {
			b.Fatal("verify falló")
		}
	}
}
