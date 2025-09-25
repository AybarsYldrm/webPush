// sw.js - daha dayanıklı push payload parsing
self.addEventListener('push', event => {
  event.waitUntil((async () => {
    let payloadObj = null;

    if (event.data) {
      // 1) en temiz yol: event.data.json()
      try {
        payloadObj = event.data.json();
        console.log('[sw] payload parsed via event.data.json():', payloadObj);
      } catch (e1) {
        // 2) fallback: text, sonra JSON.parse dene (bazı padding/control char'lar olabilir)
        try {
          let text = await event.data.text();
          console.log('[sw] raw text payload:', text);

          // temizle: sondaki kontrol karakterlerini (ör. \x00,\x02) çıkar
          text = text.replace(/[\x00-\x1F]+$/g, '');
          // ayrıca baştaki kontrolleri de temizle (nadir)
          text = text.replace(/^[\x00-\x1F]+/g, '');

          try {
            const parsed = JSON.parse(text);
            payloadObj = parsed;
            console.log('[sw] parsed payload after trimming control chars:', payloadObj);
          } catch (e2) {
            // eğer JSON değilse, metin olarak kullan (title/body'yi metinle doldur)
            payloadObj = { title: text, body: text };
            console.warn('[sw] payload not JSON, using raw text for title/body');
          }
        } catch (e3) {
          // en son çare: boş bildirim
          console.error('[sw] could not read event.data.text()', e3);
          payloadObj = { title: 'Yeni bildirim', body: '' };
        }
      }
    } else {
      payloadObj = { title: 'Yeni bildirim', body: '' };
    }

    // Normalizasyon: beklenen alanlar
    const titleRaw = payloadObj.title || payloadObj.titleText || payloadObj.t || 'Bildirim';
    const bodyRaw = payloadObj.body || payloadObj.b || payloadObj.message || '';

    // Basit sanitization / limit (title çok uzunsa kısalt)
    const MAX_TITLE = 100;
    const title = typeof titleRaw === 'string'
      ? (titleRaw.length > MAX_TITLE ? titleRaw.slice(0, MAX_TITLE - 1) + '…' : titleRaw)
      : String(titleRaw);

    const options = {
      body: typeof bodyRaw === 'string' ? bodyRaw : String(bodyRaw),
      icon: payloadObj.icon || undefined,
      badge: payloadObj.badge || undefined,
      data: payloadObj.data || {}
    };

    await self.registration.showNotification(title, options);
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});
