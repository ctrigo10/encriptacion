# Prueba de concepto de qr seguro

## Generar llaves
1. Generación de clave privada EC (Elliptic Curve)
    ```bash
    openssl ecparam -name prime256v1 -genkey -noout -out ec-raw.pem
    ```
2. Conversión de la clave privada EC a formato PKCS#8
    ```bash
    openssl pkcs8 -topk8 -inform PEM -outform PEM -in ec-raw.pem -nocrypt -out llavePrivada.p8
    ```
3. Generación de la clave pública EC a partir de la clave privada
    ```bash
    openssl ec -in ec-raw.pem -pubout -out clavePublica.pem
    ```

## Realizar la prueba
1. Firmar el json ejemplo.json y guardar en prueba
    ```bash
    cat ejemplo.json | npx tsx cose_sign.ts > prueba
    ```
2. Verificar la firma de prueba
    ```bash
    cat prueba | npx tsx cose_verify.ts
    ```