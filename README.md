# Analisis-Forense-Windows-Sysmon
Análisis forense digital (DFIR) de una intrusión por RDP. Correlación de registros de Windows (Security.evtx) y telemetría de Sysmon para rastrear fuerza bruta, persistencia de cuenta backdoor, y extracción automatizada de IoCs de malware (C2) en flujos ADS utilizando PowerShell.

# 🛡️ DFIR: Análisis Forense de Registros Windows & Sysmon (RDP Brute Force a Malware C2)

**Autor:** Sebastián Alejandro Navarro Maldonado  
**Categoría:** Digital Forensics & Incident Response (DFIR) / Threat Hunting  
**Entorno de Análisis:** TryHackMe - Windows SOC Lab  

---

## 🎥 Demostración Práctica

> 🚧 **Video en preparación:** El análisis en vivo del visor de eventos y la extracción del malware mediante PowerShell se publicará próximamente.

---

## 🚨 Contexto del Escenario

En un turno habitual dentro del SOC, se detectó la activación de una alerta crítica indicando anomalías de autenticación en la estación de trabajo corporativa `THM-PC`. Tras realizar el triaje inicial de los eventos, la evidencia apuntaba a un compromiso activo, por lo que se decidió escalar el incidente e iniciar una investigación forense profunda (Deep Dive).

El objetivo de este análisis es reconstruir la cadena completa del ataque (Kill Chain) examinando los registros nativos de Windows (`Security.evtx`) y correlacionando los hallazgos con la telemetría avanzada de Microsoft Sysmon (`Sysmon.evtx`), rastreando el incidente desde el vector de entrada inicial hasta la identificación del servidor de Comando y Control (C2) del atacante.

---

## 📋 Resumen Ejecutivo

El análisis forense digital confirmó una brecha de seguridad total en el endpoint `THM-PC`. El actor de la amenaza logró ingresar mediante un ataque de fuerza bruta a través del protocolo RDP. Una vez establecido el acceso, ejecutó acciones de persistencia creando una cuenta de usuario oculta y escalando privilegios a nivel de administrador. Finalmente, el atacante utilizó la sesión activa para descargar y ejecutar un artefacto malicioso, logrando comunicación con infraestructura externa.

---

## 🗂️ Matriz de Artefactos Forenses Identificados

A continuación, se detalla la correlación de eventos extraídos para trazar las acciones del atacante:

| Origen del Registro | Event ID | Categoría de Evento | Hallazgo Clave en la Investigación |
| :--- | :---: | :--- | :--- |
| **Security** | `4625` | *Failed Logon* | Identificación de ráfaga de fuerza bruta desde IP atacante `10.10.53.248`. |
| **Security** | `4624` | *Successful Logon* | Confirmación de compromiso vía RDP (Logon Type 10) con Logon ID `0x183C36D`. |
| **Security** | `4720` | *User Account Created* | Creación de la cuenta backdoor `svc_sysrestore` por parte del atacante. |
| **Security** | `4732` | *Group Member Added* | Asignación de privilegios a *Backup Operators* y *Remote Desktop Users*. |
| **Sysmon** | `1` | *Process Creation* | Ejecución de Chrome y posterior ejecución de `WMIC.exe` por el malware. |
| **Sysmon** | `11` / `15` | *File Created / Stream* | Descarga de `ckjg.exe` y extracción de la URL fuente en el flujo ADS. |

---

## 🔍 Fase I: Reconocimiento y Fuerza Bruta RDP (Vector de Entrada)

La investigación inició con el análisis del archivo `Practice-Security.evtx`. El filtro sobre el identificador de evento **4625** reveló múltiples intentos fallidos de inicio de sesión dirigidos hacia cuentas estándar y de servicio en un corto periodo de tiempo.

```yaml
# Indicadores Iniciales
IP Origen (Atacante): 10.10.53.248
Técnica MITRE ATT&CK: Brute Force (T1110)
Protocolo Objetivo: Remote Desktop Protocol (RDP)
```

**Confirmación de la Brecha (Event ID 4624):**
Inmediatamente después de la ráfaga de errores, se registró un evento **4624** exitoso. El tipo de inicio de sesión `10` confirmó la entrada remota directa vía RDP.

```diff
- ALERTA CRÍTICA: Compromiso de cuenta administrativa
! Usuario Comprometido: administrator
! Logon ID Asignado: 0x183C36D
! Tipo de Acceso: Remote Interactive (Logon Type 10)
```

---

## 🔑 Fase II: Persistencia y Escalada de Privilegios

Bajo la sesión `0x183C36D`, el atacante procedió a garantizar su acceso a largo plazo creando una cuenta furtiva diseñada para emular un servicio legítimo del sistema operativo.

Mediante la inspección de los eventos de administración de cuentas, se interceptó el Evento **4720**, que registra la creación del usuario local `svc_sysrestore`. Segundos después, los Eventos **4732** registraron la adición de este usuario a grupos críticos:

1. **Backup Operators:** Permite al atacante eludir los controles de acceso (ACLs) para leer, escribir o exfiltrar cualquier archivo en el sistema.
2. **Remote Desktop Users:** Garantiza autenticación remota directa a futuro sin requerir elevación interactiva previa.

---

## 🦠 Fase III: Ejecución de Malware y Análisis de ADS (Sysmon)

Para determinar el impacto a nivel de punto final, el análisis se trasladó a `Practice-Sysmon.evtx`. Ordenando los eventos cronológicamente, se identificó una sesión activa ejecutando Google Chrome (Event ID 1).

El análisis del **Event ID 11 (Creación de Archivos)** reveló que el atacante alojó un nuevo ejecutable en el sistema de archivos del usuario corporativo:
`C:\Users\sarah.miller\Downloads\ckjg.exe`

### 🎯 Extracción del Servidor C2 mediante Alternate Data Streams (ADS)
Para investigar la procedencia del binario, se analizó el **Event ID 15 (FileCreateStreamHash)**. Los navegadores basados en Chromium adjuntan un flujo de datos alternativo (`Zone.Identifier`) a los archivos descargados. Al revisar el campo `Contents` dentro del XML del evento, se extrajo la metamemoria exacta de la descarga:

```ini
TargetFilename: C:\Users\sarah.miller\Downloads\ckjg.exe:Zone.Identifier
CreationUtcTime: 2025-05-18 16:07:23.848
Contents: 
[ZoneTransfer]
ZoneId=3
HostUrl=[http://gettsveriff.com/bgj3/ckjg.exe](http://gettsveriff.com/bgj3/ckjg.exe)
```

**Significado Forense:** El indicador `ZoneId=3` corresponde a la zona de "Internet", y el parámetro `HostUrl` revela de manera irrefutable la dirección URL desde la cual se descargó la carga útil.

---

## 💻 Automatización mediante PowerShell en el SOC

La investigación manual de archivos `.evtx` en el Visor de Eventos nativo (`eventvwr.exe`) presenta fricciones operativas y demoras críticas, especialmente por la falta de búsqueda *Full-Text* en cadenas anidadas (como el campo `Contents`).

Para superar estas limitaciones y agilizar futuras respuestas a incidentes, se estructuró la siguiente consulta en PowerShell utilizando la API de Windows, permitiendo la extracción automatizada de las URLs maliciosas:

```powershell
# Comando de Extracción Automatizada de URLs de Descarga (Sysmon Event ID 15)
Get-WinEvent -Path ".\Practice-Sysmon.evtx" | 
    Where-Object { $_.Id -eq 15 } | 
    Select-Object TimeCreated, Id, Message | 
    Format-List
```

---

## 📈 Impacto Estratégico y Lecciones Aprendidas

El análisis de registros avanzados aportó un valor directo a la contención del incidente y a la postura de ciberseguridad corporativa:

1. **Generación Inmediata de IoCs:** La extracción del dominio `gettsveriff.com` y el ejecutable `ckjg.exe` alimentaron de forma inmediata las reglas de bloqueo en Firewalls perimetrales y EDR.
2. **Reducción del MTTD y MTTR:** La correlación rápida entre los eventos 4624 y Sysmon 15 redujo drásticamente el tiempo de análisis.
3. **Recomendaciones de Infraestructura:**
   * Implementación estricta de Autenticación de Múltiples Factores (MFA) para RDP.
   * Justificación técnica para centralizar y correlacionar logs en una plataforma SIEM (Splunk, Sentinel), eliminando el análisis forense manual sobre archivos `.evtx` aislados.
