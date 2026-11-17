export class WebhookHatasi extends Error {}

export type DogrulamaNedeni = "expired" | "mismatch" | "malformed";

export interface DogrulamaSonucu {
    ok: boolean;
    reason?: DogrulamaNedeni;
}

const METIN_KODLAYICI = new TextEncoder();

function webCrypto(): Crypto {
    const tarayici = globalThis.crypto;
    if (tarayici?.subtle === undefined) {
        throw new WebhookHatasi("WebCrypto bulunamadı; Node 20+, tarayıcı ya da edge çalışma ortamı gerekir");
    }
    return tarayici;
}

function saniyeyeCevir(at: number | Date): number {
    const milisaniye = at instanceof Date ? at.getTime() : at;
    if (typeof milisaniye !== "number" || !Number.isFinite(milisaniye)) {
        throw new WebhookHatasi(`Geçersiz zaman: ${String(at)}`);
    }
    return Math.floor(milisaniye / 1000);
}

function hexKodla(bytes: Uint8Array): string {
    let cikti = "";
    for (const bayt of bytes) {
        cikti += bayt.toString(16).padStart(2, "0");
    }
    return cikti;
}

function sabitKarsilastir(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let fark = 0;
    for (let i = 0; i < a.length; i += 1) {
        fark |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return fark === 0;
}

export async function hmacSha256(secret: string, payload: string): Promise<string> {
    if (typeof secret !== "string" || typeof payload !== "string") {
        throw new WebhookHatasi(`Girdiler metin olmalı; secret: ${typeof secret}, payload: ${typeof payload}`);
    }
    if (secret === "") {
        throw new WebhookHatasi("Secret boş olamaz; WebCrypto boş HMAC anahtarını desteklemez");
    }

    const anahtar = await webCrypto().subtle.importKey(
        "raw",
        METIN_KODLAYICI.encode(secret) as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const imza = await webCrypto().subtle.sign("HMAC", anahtar, METIN_KODLAYICI.encode(payload) as BufferSource);
    return hexKodla(new Uint8Array(imza));
}

export interface ImzaSecenekleri {
    at?: number | Date;
}

export async function sign(payload: string, secret: string, options: ImzaSecenekleri = {}): Promise<string> {
    const { at = Date.now() } = options;
    const zaman = saniyeyeCevir(at);
    const imza = await hmacSha256(secret, `${zaman}.${payload}`);
    return `t=${zaman},v1=${imza}`;
}

export interface DogrulamaSecenekleri {
    tolerance?: number;
    now?: number | Date;
}

export async function verify(
    payload: string,
    header: string,
    secret: string,
    options: DogrulamaSecenekleri = {},
): Promise<DogrulamaSonucu> {
    const { tolerance = 300, now = Date.now() } = options;
    if (!Number.isInteger(tolerance) || tolerance < 0) {
        throw new WebhookHatasi(`Tolerans saniye cinsinden negatif olmayan tam sayı olmalı, alınan değer: ${tolerance}`);
    }
    if (typeof header !== "string") {
        return { ok: false, reason: "malformed" };
    }

    let zaman: number | undefined;
    const imzalar: string[] = [];
    for (const parca of header.split(",")) {
        const temiz = parca.trim();
        const esit = temiz.indexOf("=");
        if (esit === -1) continue;
        const ad = temiz.slice(0, esit).trim();
        const deger = temiz.slice(esit + 1).trim();
        if (ad === "t" && /^\d+$/.test(deger)) {
            zaman = Number(deger);
        } else if (ad === "v1" && deger !== "") {
            imzalar.push(deger.toLowerCase());
        }
    }

    if (zaman === undefined || imzalar.length === 0) {
        return { ok: false, reason: "malformed" };
    }

    if (Math.abs(saniyeyeCevir(now) - zaman) > tolerance) {
        return { ok: false, reason: "expired" };
    }

    const beklenen = await hmacSha256(secret, `${zaman}.${payload}`);
    for (const aday of imzalar) {
        if (sabitKarsilastir(aday, beklenen)) {
            return { ok: true };
        }
    }
    return { ok: false, reason: "mismatch" };
}
