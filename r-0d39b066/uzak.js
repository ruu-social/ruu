/* =========================================================================
   UZAKTAN RAPORLAR — telefondaki sayfa
   -------------------------------------------------------------------------
   Bu dosya yayında herkese açık durur; içinde gizli hiçbir şey yoktur.
   Raporların kendisi ayrı dosyalarda ve ŞİFRELİ. Parola yalnızca burada,
   telefonun içinde anahtara çevrilir ve çözme de burada yapılır — yayın
   sunucusu veriyi hiçbir aşamada açık görmez.

   Şifreleme tarafının karşılığı: Services/ReportCrypto.cs
     · Anahtar: PBKDF2-SHA256, tuz ve döngü sayısı anahtar.json'dan gelir
     · Veri:    AES-GCM (nonce ‖ şifreli ‖ etiket), açılınca gzip çözülür
   ========================================================================= */

(() => {
    'use strict';

    const DEPO_ANAHTAR = 'ruu-rapor-anahtar';
    const DEPO_SEKME = 'ruu-rapor-sekme';

    const $ = (id) => document.getElementById(id);

    const girisEkrani = $('giris');
    const uygulama = $('uygulama');
    const hataKutusu = $('giris-hata');
    const girisDugme = $('giris-dugme');

    let anahtar = null;        // Uint8Array(32)
    let dizin = null;          // çözülmüş dizin
    let sekmeKod = localStorage.getItem(DEPO_SEKME) || 'ozet';
    let donemKod = null;

    const bellek = new Map();  // dosya adı → çözülmüş dönem

    // ------------------------------------------------------------ yardımcı

    const b64Bayt = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

    const baytB64 = (u8) => btoa(String.fromCharCode(...u8));

    async function getir(yol, taze) {
        // Yayın sunucusu dosyaları on dakika kadar hafızada tutuyor. Dizin ve
        // anahtar dosyasında bu, "gönderdim ama göremiyorum" demek olurdu:
        // adrese zaman damgası eklenince taze kopya gelir. Veri dosyalarının
        // adı zaten içerikten türediği için onlarda gerek yok.
        const adres = taze ? `${yol}?t=${Date.now()}` : yol;

        const yanit = await fetch(adres, taze ? { cache: 'no-store' } : {});
        if (!yanit.ok) throw new Error(`Dosya alınamadı (${yanit.status}): ${yol}`);

        return new Uint8Array(await yanit.arrayBuffer());
    }

    async function anahtarTuret(parola, tuz, dongu) {
        const ham = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(parola.trim()), 'PBKDF2', false, ['deriveBits']);

        const bitler = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: tuz, iterations: dongu, hash: 'SHA-256' }, ham, 256);

        return new Uint8Array(bitler);
    }

    async function coz(paket) {
        const anahtarNesne = await crypto.subtle.importKey(
            'raw', anahtar, 'AES-GCM', false, ['decrypt']);

        // İlk 12 bayt nonce; gerisi şifreli metin + doğrulama etiketi.
        const acik = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: paket.slice(0, 12), tagLength: 128 },
            anahtarNesne, paket.slice(12));

        const akis = new Blob([acik]).stream().pipeThrough(new DecompressionStream('gzip'));
        return JSON.parse(await new Response(akis).text());
    }

    // --------------------------------------------------------------- giriş

    function hataGoster(mesaj) {
        hataKutusu.textContent = mesaj;
        hataKutusu.hidden = false;
    }

    async function dizinYukle() {
        const paket = await getir('veri/dizin.dat', true);
        return await coz(paket);
    }

    async function ac(parola) {
        hataKutusu.hidden = true;
        girisDugme.disabled = true;
        girisDugme.textContent = 'Açılıyor…';

        try {
            const bilgi = JSON.parse(new TextDecoder().decode(await getir('anahtar.json', true)));
            anahtar = await anahtarTuret(parola, b64Bayt(bilgi.tuz), bilgi.dongu);

            dizin = await dizinYukle();

            localStorage.setItem(DEPO_ANAHTAR, baytB64(anahtar));
            baslat();
        } catch (ex) {
            anahtar = null;

            // Çözme hatası tek bir şey demektir: anahtar yanlış, yani parola yanlış.
            const agSorunu = ex instanceof TypeError || /alınamadı/.test(ex.message || '');
            hataGoster(agSorunu
                ? 'Rapor dosyalarına ulaşılamadı. İnternet bağlantını kontrol et.'
                : 'Parola yanlış.');
        } finally {
            girisDugme.disabled = false;
            girisDugme.textContent = 'Aç';
        }
    }

    async function kayitliAnahtarlaDene() {
        const kayitli = localStorage.getItem(DEPO_ANAHTAR);
        if (!kayitli) return false;

        try {
            anahtar = b64Bayt(kayitli);
            dizin = await dizinYukle();
            baslat();
            return true;
        } catch {
            // Parola yenilenmiş ya da bağlantı yok: giriş ekranına düşülür.
            anahtar = null;
            return false;
        }
    }

    function cikis() {
        localStorage.removeItem(DEPO_ANAHTAR);
        location.reload();
    }

    // ----------------------------------------------------------- uygulama

    function baslat() {
        girisEkrani.hidden = true;
        uygulama.hidden = false;

        $('isletme').textContent = dizin.isletme;
        $('tazelik').textContent = `Veriler: ${dizin.uretim}`;

        // Hazır aralıklar düğme olur; geçmiş ay/yıllar ve tek tek geceler kendi
        // açılır listelerine girer. Kasadaki Raporlar ekranının düzeni budur.
        const secici = $('donemler');
        secici.innerHTML = '';

        Tur('hazir').forEach((d) => {
            const dugme = document.createElement('button');
            dugme.textContent = d.ad;
            dugme.dataset.kod = d.kod;
            dugme.onclick = () => donemSec(d.kod);
            secici.appendChild(dugme);
        });

        // Aylar ve yıllar tek kutuda, başlıklarla ayrılmış: iki ayrı düğme
        // koymak, çoğu zaman tek bir yılı olan bir işletme için fazlaydı.
        const aylar = Tur('ay');
        const yillar = Tur('yil');

        if (aylar.length + yillar.length > 0) {
            const liste = $('ay');
            liste.innerHTML = '';

            Grup(liste, 'Yıllar', yillar);
            Grup(liste, 'Aylar', aylar);

            liste.onchange = () => donemSec(liste.value);
            KutuDugmesi(secici, 'ay-dugme', 'Ay / yıl seç…', liste);
        }

        const geceler = Tur('gun');

        if (geceler.length > 0) {
            const liste = $('gun');
            liste.innerHTML = '';

            geceler.forEach((d) => liste.appendChild(Secenek(d)));

            liste.onchange = () => donemSec(liste.value);
            KutuDugmesi(secici, 'gun-dugme', 'Gün seç…', liste);
        }

        const sekmeler = $('sekmeler');
        sekmeler.innerHTML = '';

        dizin.sekmeler.forEach((s) => {
            const dugme = document.createElement('button');
            dugme.className = 'rapor-sekme';
            dugme.textContent = s.ad;
            dugme.dataset.kod = s.kod;
            dugme.onclick = () => sekmeSec(s.kod);
            sekmeler.appendChild(dugme);
        });

        if (!dizin.sekmeler.some((s) => s.kod === sekmeKod)) sekmeKod = 'ozet';

        donemSec(dizin.donemler[0].kod);
    }

    /** Bir türe ait dönemler (hazir | ay | yil | gun). */
    const Tur = (tur) => dizin.donemler.filter((d) => d.tur === tur);

    function Secenek(d) {
        const secenek = document.createElement('option');
        secenek.value = d.kod;
        secenek.textContent = d.bos ? `${d.ad} — satış yok` : d.ad;
        if (d.bos) secenek.className = 'bos';

        return secenek;
    }

    function Grup(liste, baslik, donemler) {
        if (donemler.length === 0) return;

        const grup = document.createElement('optgroup');
        grup.label = baslik;
        donemler.forEach((d) => grup.appendChild(Secenek(d)));

        liste.appendChild(grup);
    }

    /** Açılır listeyi açan düğmeyi düğme sırasına ekler. */
    function KutuDugmesi(secici, kimlik, yazi, liste) {
        const dugme = document.createElement('button');
        dugme.id = kimlik;
        dugme.textContent = yazi;
        dugme.onclick = () => donemSec(liste.value);

        secici.appendChild(dugme);
    }

    async function donemSec(kod) {
        donemKod = kod;

        const satir = dizin.donemler.find((d) => d.kod === kod);
        const tur = satir ? satir.tur : 'hazir';

        // Hangi düğme yanacak: hazır dönemlerde kendi düğmesi, ay/yıl ve
        // gecelerde onları açan kutu düğmesi.
        const kutuKimligi = tur === 'gun' ? 'gun-dugme' : tur === 'hazir' ? null : 'ay-dugme';

        document.querySelectorAll('#donemler button').forEach((d) => {
            d.classList.toggle('aktif', kutuKimligi ? d.id === kutuKimligi : d.dataset.kod === kod);
        });

        // Açılır listeler yalnızca kendi dönemleri seçiliyken görünür; hazır bir
        // aralığa dönüldüğünde kapanır, yoksa hangisine bakıldığı belirsiz kalırdı.
        $('ay-panel').hidden = kutuKimligi !== 'ay-dugme';
        $('gun-panel').hidden = kutuKimligi !== 'gun-dugme';

        if (kutuKimligi === 'ay-dugme') $('ay').value = kod;
        if (kutuKimligi === 'gun-dugme') $('gun').value = kod;

        $('aralik').textContent = satir ? satir.aralik : '';

        await ciz();
    }

    function sekmeSec(kod) {
        sekmeKod = kod;
        localStorage.setItem(DEPO_SEKME, kod);

        ciz();
    }

    async function donemGetir(kod) {
        const satir = dizin.donemler.find((d) => d.kod === kod);
        if (!satir) return null;

        if (bellek.has(satir.dosya)) return bellek.get(satir.dosya);

        const veri = await coz(await getir(satir.dosya, false));
        bellek.set(satir.dosya, veri);

        return veri;
    }

    function durum(mesaj) {
        $('icerik').innerHTML = `<div class="durum">${mesaj}</div>`;
    }

    async function ciz() {
        document.querySelectorAll('.rapor-sekme').forEach((d) => {
            d.classList.toggle('aktif', d.dataset.kod === sekmeKod);
        });

        // Sekme şeridi telefonda yana kayıyor; hatırlanan sekme şeridin
        // dışında kalırsa kullanıcı hangi raporda olduğunu göremezdi.
        document.querySelector('.rapor-sekme.aktif')
            ?.scrollIntoView({ block: 'nearest', inline: 'center' });

        durum('Yükleniyor…');

        let veri;
        try {
            veri = await donemGetir(donemKod);
        } catch {
            durum('Rapor alınamadı. İnternet bağlantını kontrol et.');
            return;
        }

        if (!veri) {
            durum('Bu dönem bulunamadı.');
            return;
        }

        if (veri.bos) {
            durum('Bu dönemde kayıtlı satış yok.');
            return;
        }

        $('icerik').innerHTML = veri.sekmeler[sekmeKod] || '';
        window.scrollTo({ top: 0 });
    }

    // ------------------------------------------------------------- açılış

    $('giris-form').addEventListener('submit', (e) => {
        e.preventDefault();

        const parola = $('parola').value;
        if (parola.trim()) ac(parola);
    });

    $('cikis').addEventListener('click', cikis);

    /**
     * Adresin sonundaki #p=… parolayı taşır: Yönetim ekranındaki QR kod
     * okutulunca sayfa kendiliğinden açılsın, kullanıcı on altı haneyi
     * telefona elle yazmak zorunda kalmasın.
     *
     * Adres çubuğundaki bu ek hemen siliniyor — telefonun geçmişinde ve
     * paylaş düğmesinde parola durmasın. (Adresin # sonrası hiçbir zaman
     * sunucuya gönderilmez, orada kalmaz.)
     */
    function adresteParola() {
        const eslesme = /[#&]p=([^&]+)/.exec(location.hash || '');
        if (!eslesme) return null;

        history.replaceState(null, '', location.pathname + location.search);
        return decodeURIComponent(eslesme[1]);
    }

    if (!window.crypto || !crypto.subtle) {
        // Şifre çözme yalnızca güvenli bağlantıda (https) çalışır.
        hataGoster('Bu sayfa güvenli bağlantı gerektiriyor. Adresin https ile başladığından emin ol.');
    } else {
        const adrestenGelen = adresteParola();

        if (adrestenGelen) {
            ac(adrestenGelen);
        } else {
            kayitliAnahtarlaDene().then((oldu) => {
                if (!oldu) $('parola').focus();
            });
        }
    }
})();
