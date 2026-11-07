/* SV Pro Downloads — interactions légères (sans dépendance) */
(function () {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  /* Menu mobile */
  const toggle = $('[data-nav-toggle]');
  const nav = $('[data-nav]');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  /* Alertes : clic pour fermer, disparition auto des succès */
  $$('.alert[data-dismiss]').forEach((a) => {
    a.addEventListener('click', () => a.remove());
    if (a.classList.contains('alert-success')) setTimeout(() => a.remove(), 6000);
  });

  /* Toast */
  function toast(msg) {
    let t = $('.toast');
    if (!t) { t = document.createElement('div'); t.className = 'toast'; document.body.appendChild(t); }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove('show'), 1800);
  }

  /* Copier dans le presse-papiers */
  document.addEventListener('click', async (ev) => {
    const el = ev.target.closest('[data-copy]');
    if (!el) return;
    const txt = el.getAttribute('data-copy');
    try {
      await navigator.clipboard.writeText(txt);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = txt; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    toast('Copié dans le presse-papiers');
  });
  $$('[data-select]').forEach((i) => i.addEventListener('focus', () => i.select()));

  /* Confirmation des formulaires sensibles */
  $$('form[data-confirm]').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      if (!confirm(f.getAttribute('data-confirm'))) ev.preventDefault();
    });
  });

  /* Sélection multiple + barre d'actions */
  const bulk = $('form[data-bulk]');
  if (bulk) {
    const bar = $('[data-bulkbar]', bulk);
    const all = $('[data-check-all]', bulk);
    const boxes = $$('[data-check]', bulk);
    const count = $('[data-count]', bulk);
    const action = $('[data-bulk-action]', bulk);
    const moveTo = $('[data-move-to]', bulk);
    const refresh = () => {
      const n = boxes.filter((b) => b.checked).length;
      count.textContent = n;
      bar.classList.toggle('show', n > 0);
      if (all) all.checked = n > 0 && n === boxes.length;
    };
    all && all.addEventListener('change', () => { boxes.forEach((b) => (b.checked = all.checked)); refresh(); });
    boxes.forEach((b) => b.addEventListener('change', refresh));
    const sums = $('[data-sums]', bulk);
    action.addEventListener('change', () => {
      moveTo.hidden = action.value !== 'move';
      if (sums) sums.hidden = !action.value.startsWith('sums_');
    });
    bulk.addEventListener('submit', (ev) => {
      if (!action.value) { ev.preventDefault(); toast('Choisissez une action'); return; }
      if (action.value === 'delete') {
        const n = boxes.filter((b) => b.checked).length;
        if (!confirm('Supprimer définitivement ' + n + ' fichier(s) et toutes leurs versions ? Cette action est irréversible.')) ev.preventDefault();
      }
    });
    refresh();
  }

  /* Envoi : glisser-déposer, liste, barre de progression */
  const form = $('form[data-upload]');
  if (form) {
    const dz = $('[data-dropzone]', form);
    const input = $('input[type=file]', dz);
    const list = $('[data-dz-list]', form);
    const prog = $('[data-progress]', form);
    const errBox = $('[data-errors]');
    const human = (b) => {
      const u = ['o', 'Ko', 'Mo', 'Go', 'To']; let i = 0;
      while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
      return (i ? b.toFixed(1).replace('.', ',') : b) + ' ' + u[i];
    };
    const ext = (n) => (n.split('.').pop() || '').slice(0, 4).toUpperCase();

    /* Glisser-déposer : on prend la main sur le dépôt (sinon le navigateur ouvre ou télécharge le fichier) */
    const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
    let depth = 0;
    dz.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth++; dz.classList.add('over'); });
    dz.addEventListener('dragover', (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    dz.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; dz.classList.remove('over'); } });
    dz.addEventListener('drop', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      e.stopPropagation();
      depth = 0;
      dz.classList.remove('over');
      let dropped = Array.from(e.dataTransfer.files || []);
      if (!dropped.length) return;
      const dt = new DataTransfer();
      if (input.multiple) {
        // ajout à la sélection existante (sans doublon)
        const key = (f) => f.name + '|' + f.size + '|' + f.lastModified;
        const seen = new Set();
        [...Array.from(input.files || []), ...dropped].forEach((f) => { if (!seen.has(key(f))) { seen.add(key(f)); dt.items.add(f); } });
      } else {
        dt.items.add(dropped[0]); // modification d'une fiche : un seul fichier (nouvelle version)
      }
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    // Un fichier lâché à côté du cadre ne doit pas faire quitter la page (et perdre le formulaire)
    ['dragover', 'drop'].forEach((t) => window.addEventListener(t, (e) => {
      if (hasFiles(e) && !dz.contains(e.target)) { e.preventDefault(); if (t === 'dragover') e.dataTransfer.dropEffect = 'none'; }
    }));
    input.addEventListener('change', () => {
      list.innerHTML = '';
      Array.from(input.files).forEach((f) => {
        const li = document.createElement('li');
        const k = document.createElement('span');
        k.className = 'kind kind-file'; k.textContent = ext(f.name);
        li.appendChild(k);
        li.appendChild(document.createTextNode(' ' + f.name + ' '));
        const s = document.createElement('span'); s.className = 'muted'; s.textContent = '· ' + human(f.size);
        li.appendChild(s);
        list.appendChild(li);
      });
    });

    /* ---- Envoi par morceaux : les gros fichiers (ISO de plusieurs Go) passent sous les limites PHP ---- */
    const chunkUrl = form.dataset.chunkUrl;
    const maxSize = parseInt(form.dataset.max || '0', 10);
    const csrf = (form.querySelector('input[name=_csrf]') || {}).value || '';
    const status = $('[data-upstatus]', form);
    const info = $('[data-upinfo]', form);
    const cancelBtn = $('[data-upcancel]', form);
    let aborted = false, currentXhr = null, busy = false;

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const fmtTime = (s) => (s < 60 ? Math.max(1, Math.round(s)) + ' s' : s < 3600 ? Math.round(s / 60) + ' min' : (s / 3600).toFixed(1).replace('.', ',') + ' h');

    function post(data, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        currentXhr = xhr;
        xhr.open('POST', chunkUrl);
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        if (onProgress) xhr.upload.addEventListener('progress', (e) => e.lengthComputable && onProgress(e.loaded));
        xhr.onload = () => {
          let res = null;
          try { res = JSON.parse(xhr.responseText); } catch (e) { /* page d'erreur du serveur web */ }
          if (res) resolve(res);
          else reject(Object.assign(new Error(xhr.status === 413 ? 'morceau refusé par le serveur web (taille : réduire « Taille des morceaux » ou augmenter client_max_body_size)' : 'erreur serveur ' + xhr.status), { retry: xhr.status >= 500 || xhr.status === 0 }));
        };
        xhr.onerror = () => reject(Object.assign(new Error('connexion interrompue'), { retry: true }));
        xhr.ontimeout = xhr.onerror;
        xhr.onabort = () => reject(Object.assign(new Error('interrompu'), { abort: true }));
        const fd = new FormData();
        fd.append('_csrf', csrf);
        Object.entries(data).forEach(([k, v]) => fd.append(k, v));
        xhr.send(fd);
      });
    }

    /** Envoie un fichier par morceaux ; renvoie l'identifiant d'envoi */
    async function sendFile(file, progress) {
      const fp = file.lastModified + ':' + file.size;
      let init = await post({ op: 'init', name: file.name, size: file.size, fp });
      if (!init.ok) throw new Error(init.error || 'refusé');
      let offset = init.offset;
      const id = init.id, size = init.chunk;
      if (init.resumed) toast('Reprise de « ' + file.name + ' » à ' + Math.round(offset / file.size * 100) + ' %');
      progress(offset, 0);
      while (offset < file.size) {
        if (aborted) throw Object.assign(new Error('interrompu'), { abort: true });
        const end = Math.min(offset + size, file.size);
        const blob = file.slice(offset, end);
        let tries = 0;
        for (;;) {
          try {
            const res = await post({ op: 'put', id, offset, chunk: blob }, (loaded) => progress(offset, loaded));
            if (res.ok) { offset = res.offset; break; }
            if (res.resync) { offset = res.offset; break; }          // le serveur avait déjà ce morceau
            if (!res.retry) throw new Error(res.error || 'refusé');
            throw Object.assign(new Error(res.error), { retry: true });
          } catch (e) {
            if (e.abort || !e.retry || ++tries > 8) throw e;
            info.textContent = 'Connexion perdue — nouvel essai ' + tries + '/8…';
            await sleep(Math.min(30000, 1000 * 2 ** (tries - 1)));
          }
        }
        progress(offset, 0);
      }
      return id;
    }

    cancelBtn && cancelBtn.addEventListener('click', () => {
      aborted = true;
      if (currentXhr) currentXhr.abort();
    });
    window.addEventListener('beforeunload', (e) => { if (busy) { e.preventDefault(); e.returnValue = ''; } });

    form.addEventListener('submit', async (ev) => {
      if (!window.FormData || !window.XMLHttpRequest || !window.Promise || !chunkUrl) return; // repli : envoi classique
      ev.preventDefault();
      const btn = $('button', form.querySelector('.form-actions'));
      const files = Array.from(input.files || []);
      const tooBig = files.filter((f) => maxSize && f.size > maxSize);
      errBox.innerHTML = '';
      const showErr = (m) => { const d = document.createElement('div'); d.className = 'alert alert-error'; d.textContent = m; errBox.appendChild(d); };
      if (tooBig.length) {
        tooBig.forEach((f) => showErr(f.name + ' : dépasse la taille maximale autorisée (' + human(maxSize) + ') — voir Réglages.'));
        window.scrollTo({ top: 0, behavior: 'smooth' });
        return;
      }
      btn.disabled = true; busy = true; aborted = false;
      prog.hidden = false; status.hidden = !files.length;
      const bar = $('.bar', prog), lbl = $('span', prog);
      const total = files.reduce((n, f) => n + f.size, 0) || 1;
      let doneBefore = 0;
      const t0 = Date.now(); let lastBytes = 0, lastT = t0, speed = 0, startBytes = null;
      const ids = [];
      try {
        for (let i = 0; i < files.length; i++) {
          const f = files[i];
          const id = await sendFile(f, (offset, loaded) => {
            const sent = doneBefore + offset + loaded;
            if (startBytes === null) startBytes = sent;   // une reprise ne fausse pas le débit
            const now = Date.now();
            if (now - lastT > 800) { speed = (sent - lastBytes) / ((now - lastT) / 1000); lastBytes = sent; lastT = now; }
            const p = Math.min(100, Math.floor(sent / total * 100));
            bar.style.width = p + '%';
            lbl.textContent = p + ' %';
            info.textContent = (files.length > 1 ? 'Fichier ' + (i + 1) + '/' + files.length + ' — ' : '') + f.name + ' · '
              + human(sent) + ' / ' + human(total) + (speed > 0 ? ' · ' + human(speed) + '/s · reste ' + fmtTime((total - sent) / speed) : '');
          });
          ids.push(id);
          doneBefore += f.size;
        }
      } catch (e) {
        busy = false; btn.disabled = false; prog.hidden = true; status.hidden = true; bar.style.width = '0';
        showErr(e.abort ? 'Envoi interrompu. Resélectionnez le(s) même(s) fichier(s) pour reprendre là où il s\'était arrêté.' : 'Échec de l\'envoi : ' + e.message + '. Relancez : l\'envoi reprendra là où il s\'était arrêté.');
        window.scrollTo({ top: 0, behavior: 'smooth' });
        return;
      }

      // Tous les morceaux sont reçus : création de la (des) fiche(s)
      bar.style.width = '100%'; lbl.textContent = 'Finalisation…';
      info.textContent = 'Assemblage et vérification sur le serveur…';
      cancelBtn && (cancelBtn.hidden = true);
      const fd = new FormData(form);
      fd.delete('files[]');
      ids.forEach((id) => fd.append('chunked[]', id));
      const xhr = new XMLHttpRequest();
      xhr.open('POST', form.action || location.href);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.onload = () => {
        let res = null;
        try { res = JSON.parse(xhr.responseText); } catch (e) { /* réponse inattendue */ }
        busy = false;
        if (res && res.ok) { location.href = res.redirect; return; }
        btn.disabled = false; prog.hidden = true; status.hidden = true; bar.style.width = '0';
        cancelBtn && (cancelBtn.hidden = false);
        ((res && res.errors) || ['Erreur serveur (' + xhr.status + ').']).forEach(showErr);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      };
      xhr.onerror = () => { busy = false; btn.disabled = false; prog.hidden = true; status.hidden = true; toast('Connexion interrompue'); };
      xhr.send(fd);
    });
  }
})();

/* Réglages : champs SMTP affichés seulement si la méthode SMTP est choisie */
(function () {
  const sel = document.querySelector('[data-transport]');
  const box = document.querySelector('[data-smtp]');
  if (sel && box) sel.addEventListener('change', () => { box.hidden = sel.value !== 'smtp'; });
})();

/* Fiche : générateur de sommes — cohérence format / algorithme et nom du fichier produit */
(function () {
  const form = document.querySelector('[data-gen-form]');
  if (!form) return;
  const fmt = form.querySelector('[data-gen-format]');
  const alg = form.querySelector('[data-gen-algo]');
  const out = form.querySelector('[data-gen-name]');
  const base = form.dataset.name || 'fichier';
  const short = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512', crc32b: 'crc', 'blake2b-512': 'b2' };
  const gnu = { md5: 'md5sum', sha1: 'sha1sum', sha256: 'sha256sum', sha512: 'sha512sum', 'blake2b-512': 'b2sum' };
  const opt = (v) => alg.querySelector('option[value="' + v + '"]');
  function sync() {
    const f = fmt.value;
    alg.querySelectorAll('option').forEach((o) => { if (!o.dataset.base) o.dataset.base = o.disabled ? '1' : ''; o.disabled = o.dataset.base === '1'; });
    if (f === 'sfv') { alg.value = 'crc32b'; alg.querySelectorAll('option').forEach((o) => { if (o.value !== 'crc32b') o.disabled = true; }); }
    if (f !== 'bsd' && opt('all')) { opt('all').disabled = true; if (alg.value === 'all') alg.value = 'sha256'; }
    if (f !== 'sfv' && f !== 'hash' && alg.value === 'crc32b' && f === 'gnu') { /* CRC32 en GNU => SFV côté serveur */ }
    let n;
    const a = alg.value;
    if (f === 'sfv' || (f === 'gnu' && a === 'crc32b')) n = base + '.sfv';
    else if (f === 'hash') n = base + '.' + short[a];
    else if (f === 'gnu') n = base + '.' + gnu[a];
    else n = a === 'all' ? base + '.checksums.txt' : base + '.' + short[a];
    out.textContent = 'Fichier produit : ' + n;
  }
  fmt.addEventListener('change', sync);
  alg.addEventListener('change', sync);
  sync();
})();
