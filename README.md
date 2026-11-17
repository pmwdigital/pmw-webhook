# @pmwdigital/webhook

Webhook gövdesini HMAC-SHA256 ile imzalar ve doğrular. Zaman damgası
tekrar saldırısını (`t=`), imza sahteleşmesini (`v1=`) ve kurcalanmış gövdeyi
aynı akışta yakalar. Tarayıcının ve Node'un yerleşik `WebCrypto`'sunu
kullanır; bağımlılığı yoktur.

Başlık biçimi Stripe'ın kullandığı `t=...,v1=...` düzenidir; aynı düzeni
kullanan sağlayıcılarla (ödeme, SMS, CI) doğrudan çalışır.

## Neden

- İmza olmadan webhook herkese açık bir uç noktadır: adresi bilen herkes
  "ödemeyi tamamlandı" diye POST atabilir.
- İmza tek başına yetmez; mesaj ele geçirildiyse sonsuza kadar tekrar
  oynatılabilir. Zaman damgası penceresi bunu `expired` ile keser.
- İmza karşılaştırması sabit zamanlıdır; `===` erken çıkışının sızdırdığı
  bilgiyi sızdırmaz.
- Secret döndürürken iki `v1` imzası gönderilebilir; çoklu imza desteklenir,
  böylece secret rotasyonu kesintisiz olur.
- Doğrulama `boolean` değil sonuç nesnesi döner: gelen isteği "süresi
  geçmiş", "imza tutmadı" ya da "bozuk başlık" olarak ayırabilirsiniz.

## Kurulum

```bash
npm install github:pmwdigital/pmw-webhook
```

npm, GitHub'dan kurarken paketi `prepare` betiğiyle derler. Ayarlarınızda
`ignore-scripts` açıksa bu adım atlanır ve `dist` eksik kalır; o makinede
kurulumu `npm install --ignore-scripts=false github:pmwdigital/pmw-webhook`
ile yapın.

## Kullanım

Gönderen taraf:

```ts
import { sign } from "@pmwdigital/webhook";

const baslik = await sign(govde, process.env.WEBHOOK_SECRET);
await fetch("https://alan.taraf/hook", {
    method: "POST",
    headers: { "content-type": "application/json", "x-imza": baslik },
    body: govde,
});
```

Alan taraf:

```ts
import { verify } from "@pmwdigital/webhook";

app.post("/hook", async (istek) => {
    const sonuc = await verify(hamGovde, istek.headers["x-imza"], process.env.WEBHOOK_SECRET, {
        tolerance: 300, // saniye, varsayılan 300
    });

    if (!sonuc.ok) {
        return new Response(sonuc.reason, { status: 401 }); // expired | mismatch | malformed
    }
    return new Response("kabul");
});
```

**Ham gövdeyi kullanın.** Gövdeyi önce JSON olarak ayrıştırıp yeniden
serileştirirseniz boşluklar ve anahtar sırası değişir, imza tutmaz. Express'te
`express.raw({ type: "application/json" })`, diğer sunucularda gövdeyi
metin olarak okuyan yolu seçin.

Düşük seviyeli imza da açıktır:

```ts
import { hmacSha256 } from "@pmwdigital/webhook";

await hmacSha256("Jefe", "what do ya want for nothing?");
// "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" (RFC 4231)
```

## API

| Fonksiyon | İş |
| --- | --- |
| `sign(payload, secret, options?)` | `t=<unix saniye>,v1=<hex>` başlığı üretir; `at` ile saat sabitlenir |
| `verify(payload, header, secret, options?)` | Başlığı doğrular; `tolerance` (300 sn) ve `now` alır |
| `hmacSha256(secret, payload)` | Ham HMAC-SHA256, küçük harf hex |

`verify` sonucu:

| Sonuç | Anlamı |
| --- | --- |
| `{ ok: true }` | İmza tuttu ve damga pencerede |
| `{ ok: false, reason: "expired" }` | Damga `tolerance` dışında (geçmiş ya da gelecek) |
| `{ ok: false, reason: "mismatch" }` | Damga pencerede ama imzalardan hiçbiri tutmadı |
| `{ ok: false, reason: "malformed" }` | Başlıkta `t` ya da `v1` yok, okunamıyor |

## Güvenlik notları

- Secret'ı yalnızca sunucuda tutun; loglara yazmayın.
- Aynı olayın iki kez işlenmesini istemiyorsanız imza doğrulamasından sonra
  idempotency anahtarına da bakın; imza, mesajın sahibini söyler, kaç kez
  geldiğini değil.
- `tolerance` büyüdükçe tekrar saldırısı penceresi büyür; saat kayması
  sorununuz yoksa 300 saniye yeterlidir.
- Secret rotasyonunda bir süre iki anahtarı kabul edin: eski anahtarla
  gelenlere bir de yeni anahtarla `verify` çağırın ya da gönderene iki `v1`
  imzası taşıtın.

## Sınırlar

- Yalnız SHA-256 ve hex imza vardır; base64 imza (GitHub tarzı) kapsam
  dışıdır.
- Boş secret kullanılamaz; WebCrypto boş HMAC anahtarını desteklemez.
  Boş gövde imzalanabilir.
- Saat kaynağı sizin sorumluluğunuzdadır; `now` ve `at` verilmezse
  `Date.now()` kullanılır.
- İmza, gönderenin bu gövdeyi bu secret'la ürettiğini söyler; iş kuralını
  (tutar, hesap) ayrıca doğrulayın.

## Geliştirme

```bash
npm install
npm test
npm run typecheck
npm run build
```

Kapsam 14 testtir. HMAC vektörü uydurma değil: RFC 4231 Test Case 2'den
alınmıştır; pencere, çoklu imza ve başlık ayrıştırma davranışları ayrıca
test edilir.

## Lisans

MIT
