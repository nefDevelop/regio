# Contribuir a reGIO

¡Gracias por tu interés en mejorar reGIO! Como proyecto enfocado en la seguridad, valoramos mucho las contribuciones de la comunidad.

## Cómo empezar

1.  **Reportar Bugs:** Si encuentras un error, abre un *Issue* describiendo los pasos para reproducirlo.
2.  **Sugerir Mejoras:** Las ideas para nuevas protecciones o mejoras en la UX son bienvenidas.
3.  **Enviar Pull Requests:**
    *   Haz un fork del repositorio.
    *   Crea una rama para tu mejora (`git checkout -b feature/nueva-mejora`).
    *   Asegúrate de que `make test` pase correctamente.
    *   Envía tu PR detallando los cambios.

## Estándares de Código

*   Sigue las convenciones estándar de Go (`gofmt`).
*   Toda nueva funcionalidad debe incluir tests (especialmente si afecta a la seguridad).
*   Documenta cualquier cambio en las variables de entorno o comandos CLI.

## Reporte de Vulnerabilidades

**POR FAVOR, NO ABRAS UN ISSUE PÚBLICO PARA VULNERABILIDADES DE SEGURIDAD.**

Si encuentras un fallo de seguridad crítico, por favor contacta directamente con el mantenedor o sigue las instrucciones en [SECURITY.md](SECURITY.md).
