import { describe, expect, it } from "vitest";
import { hmacSha256, sign, verify, WebhookHatasi } from "./webhook.js";

const ZAMAN = 1_700_000_000_000; // 2023-11-14 22:13:20 UTC, t=1700000000
const SIR = "gizli-anahtar";

describe("hmacSha256", () => {
    it("RFC 4231 Test Case 2 vektörünü üretir", async () => {
        expect(await hmacSha256("Jefe", "what do ya want for nothing?")).toBe(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
    });

    it("boş payload'ı da imzalar, boş secret'ta hata fırlatır", async () => {
        expect(await hmacSha256("s", "")).toHaveLength(64);
        await expect(hmacSha256("", "x")).rejects.toThrow(WebhookHatasi);
    });

    it("metin olmayan girdide hata fırlatır", async () => {
        await expect(hmacSha256(5 as never, "x")).rejects.toThrow(WebhookHatasi);
        await expect(hmacSha256("x", null as never)).rejects.toThrow(WebhookHatasi);
    });
});

describe("sign", () => {
    it("t ve v1 içeren başlığı deterministik üretir", async () => {
        const beklenen = `t=1700000000,v1=${await hmacSha256(SIR, "1700000000.selam")}`;
        expect(await sign("selam", SIR, { at: ZAMAN })).toBe(beklenen);
    });

    it("Date kabul eder", async () => {
        expect(await sign("selam", SIR, { at: new Date(ZAMAN) })).toBe(await sign("selam", SIR, { at: ZAMAN }));
    });

    it("geçersiz zamanda hata fırlatır", async () => {
        await expect(sign("selam", SIR, { at: Number.NaN })).rejects.toThrow(WebhookHatasi);
    });
});

describe("verify", () => {
    const yuk = '{"id":"evt_1","tutar":1250}';

    it("kendi imzasını kabul eder", async () => {
        const baslik = await sign(yuk, SIR, { at: ZAMAN });
        expect(await verify(yuk, baslik, SIR, { now: ZAMAN })).toEqual({ ok: true });
    });

    it("tolerans sınırında kabul, bir saniye sonrasında expired", async () => {
        const baslik = await sign(yuk, SIR, { at: ZAMAN });
        expect(await verify(yuk, baslik, SIR, { now: ZAMAN + 300_000, tolerance: 300 })).toEqual({ ok: true });
        expect(await verify(yuk, baslik, SIR, { now: ZAMAN + 301_000, tolerance: 300 })).toEqual({
            ok: false,
            reason: "expired",
        });
    });

    it("gelecekteki damgayı da pencere dışındaysa reddeder", async () => {
        const baslik = await sign(yuk, SIR, { at: ZAMAN + 601_000 });
        expect(await verify(yuk, baslik, SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "expired" });
    });

    it("yanlış secret ve kurcalanmış gövdede mismatch der", async () => {
        const baslik = await sign(yuk, SIR, { at: ZAMAN });
        expect(await verify(yuk, baslik, "başka-sır", { now: ZAMAN })).toEqual({ ok: false, reason: "mismatch" });
        expect(await verify(`${yuk} `, baslik, SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "mismatch" });
    });

    it("çoklu v1 imzasından biri tutarsa kabul eder", async () => {
        const baslik = `t=1700000000,v1=${"0".repeat(64)},${await sign(yuk, SIR, { at: ZAMAN })}`;
        expect(await verify(yuk, baslik, SIR, { now: ZAMAN })).toEqual({ ok: true });
    });

    it("büyük harfli hex imzayı ve boşlukları tolere eder", async () => {
        const baslik = await sign(yuk, SIR, { at: ZAMAN });
        const buyuk = ` t=${ZAMAN / 1000} , v1=${baslik.split("v1=")[1].toUpperCase()} `;
        expect(await verify(yuk, buyuk, SIR, { now: ZAMAN })).toEqual({ ok: true });
    });

    it("bozuk başlığı malformed diye ayırır", async () => {
        expect(await verify(yuk, "", SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "malformed" });
        expect(await verify(yuk, "selam", SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "malformed" });
        expect(await verify(yuk, "t=abc,v1=ff", SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "malformed" });
        expect(await verify(yuk, "t=1700000000.5,v1=ff", SIR, { now: ZAMAN })).toEqual({
            ok: false,
            reason: "malformed",
        });
        expect(await verify(yuk, "t=1700000000", SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "malformed" });
        expect(await verify(yuk, "t=1700000000,v1=", SIR, { now: ZAMAN })).toEqual({ ok: false, reason: "malformed" });
    });

    it("geçersiz toleransta hata fırlatır", async () => {
        await expect(verify(yuk, "t=1,v1=ff", SIR, { tolerance: -1 })).rejects.toThrow(WebhookHatasi);
        await expect(verify(yuk, "t=1,v1=ff", SIR, { tolerance: 1.5 })).rejects.toThrow(WebhookHatasi);
    });
});
