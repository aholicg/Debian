(function() {
    const pageSelectors = [
        'div.outer_page',
        'div.document_page',
        'div.page_container',
        'div.page-container',
        '[id^="page_container_"]'
    ];
    let pages = [];
    for (const sel of pageSelectors) {
        pages = document.querySelectorAll(sel);
        if (pages.length > 0) break;
    }

    if (pages.length === 0) {
        alert("⚠️ Không tìm thấy trang nào trên trang Scribd này.\n(Hãy cuộn chuột xuống cuối tài liệu để web tải hết nội dung trước!)");
        return;
    }

    const lang = window.__banhmi_lang || 'vi';
    
    const messages = {
        vi: {
            title: `Sẵn sàng tạo PDF cho tài liệu Scribd gồm ${pages.length} trang.`,
            watermark: '📍 Trước khi tải nhớ bấm "MỞ KHÓA" nếu tài liệu bị dính Blur/Banner.',
            cancel: '❌ Bấm Cancel nếu bạn CHƯA kéo tài liệu xuống cuối cùng (tài liệu sẽ bị trắng nếu chưa được load toàn bộ)',
            ok: '✅ Bấm Ok nếu bạn ĐÃ kéo tài liệu xuống cuối cùng trước khi tải.'
        },
        en: {
            title: `Ready to generate PDF for a ${pages.length}-page Scribd document.`,
            watermark: '📍 Before downloading, remember to click "UNLOCK" if the document has Blur/Banner.',
            cancel: '❌ Click Cancel if you HAVE NOT scrolled the document to the bottom (the document will be blank if not fully loaded).',
            ok: '✅ Click OK if you HAVE scrolled the document to the bottom before downloading.'
        },
        es: {
            title: `Listo para generar PDF para un documento Scribd de ${pages.length} páginas.`,
            watermark: '📍 Antes de descargar, recuerde hacer clic en "DESBLOQUEAR" si el documento tiene Blur/Banner.',
            cancel: '❌ Haga clic en Cancelar si NO HA desplazado el documento hasta el final (el documento estará en blanco si no está completamente cargado).',
            ok: '✅ Haga clic en Aceptar si HA desplazado el documento hasta el final antes de descargarlo.'
        },
        id: {
            title: `Siap menghasilkan PDF untuk dokumen Scribd ${pages.length} halaman.`,
            watermark: '📍 Sebelum mengunduh, harap klik "BUKA KUNCI" jika dokumen memiliki Blur/Banner.',
            cancel: '❌ Klik Batal (Cancel) jika Anda BELUM menggulir dokumen ke bagian bawah (dokumen akan kosong/putih jika tidak dimuat sepenuhnya).',
            ok: '✅ Klik OK jika Anda SUDAH menggulir dokumen ke bagian bawah sebelum mengunduh.'
        },
        pt: {
            title: `Pronto para gerar PDF para um documento Scribd de ${pages.length} páginas.`,
            watermark: '📍 Antes de baixar, lembre-se de clicar em "DESBLOQUEAR" se o documento tiver Blur/Banner.',
            cancel: '❌ Clique em Cancelar se você NÃO ROLOU o documento até o final (o documento ficará em branco se não estiver totalmente carregado).',
            ok: '✅ Clique em OK se você ROLOU o documento até o final antes de baixar.'
        }
    };

    const msg = messages[lang] || messages.vi;
    const confirmMsg = `${msg.title}\n\nLưu ý quan trọng:\n${msg.watermark}\n${msg.cancel}\n${msg.ok}`;

    if (!confirm(confirmMsg)) return;

    const overlayInfo = document.createElement('div');
    overlayInfo.id = "banhmi-overlay-status";
    overlayInfo.style.cssText = "position:fixed; top:20px; right:20px; background:#FF6B00; color:white; padding:15px 25px; border-radius:10px; font-family:sans-serif; font-weight:bold; z-index:999999; box-shadow:0 4px 12px rgba(0,0,0,0.2); transition: opacity 0.3s ease;";
    overlayInfo.innerText = "🚀 Đang xử lý dàn trang PDF Scribd...";
    document.body.appendChild(overlayInfo);

    function cleanPage(el) {
        el.classList.remove('blurred_page', 'blur');
        el.querySelectorAll('.blurred_page, .blur').forEach(inner => {
            inner.classList.remove('blurred_page', 'blur');
        });

        el.querySelectorAll('img, .absimg').forEach(img => {
            img.style.setProperty('opacity', '1', 'important');
            img.style.setProperty('filter', 'none', 'important');
            img.style.setProperty('display', 'block', 'important');
        });

        // 1. Dọn dẹp bằng CSS Selectors nâng cao
        const promoSelectors = [
            '.page-blur-promo',
            '.page-blur-promo-overlay',
            '.promo_overlay',
            '.between_page_portal',
            '.between_page_ads',
            '.page_missing_explanation',
            '.page_missing_explanation_inner',
            '[class*="blur-promo"]',
            '[class*="promo-overlay"]',
            '[class*="paywall"]',
            '[class*="unlock"]',
            '[class*="promo"]'
        ];
        promoSelectors.forEach(sel => {
            el.querySelectorAll(sel).forEach(inner => inner.remove());
        });

        // 2. Dọn dẹp bằng tìm kiếm văn bản nhạy cảm
        const promoTexts = [
            "Unlock this document",
            "Upload to download",
            "Start your 30 day free trial",
            "Unlock thenext",
            "Unlock the next",
            "Skip ad",
            "Read for free"
        ];
        
        try {
            const allElements = Array.from(el.querySelectorAll('*'));
            allElements.forEach(item => {
                if (item && item.tagName !== 'SCRIPT' && item.tagName !== 'STYLE' && 
                    item.childNodes.length === 1 && item.childNodes[0].nodeType === 3) {
                    const text = item.textContent.trim();
                    const matched = promoTexts.some(promo => text.includes(promo));
                    if (matched) {
                        let current = item;
                        while (current && current.parentElement && 
                               !current.parentElement.classList.contains('outer_page') && 
                               !current.parentElement.classList.contains('std-page') && 
                               !current.parentElement.classList.contains('document_page') && 
                               !current.parentElement.classList.contains('page_container') &&
                               !current.parentElement.id.startsWith('page-') &&
                               current.parentElement.tagName !== 'BODY') {
                            current = current.parentElement;
                        }
                        if (current && current !== el && current.tagName !== 'BODY') {
                            current.remove();
                        }
                    }
                }
            });
        } catch (e) {
            console.error("Lỗi xóa overlay văn bản: ", e);
        }

        el.querySelectorAll('.text_layer, .text_layer_container, [class*="text_layer"]').forEach(tl => {
            tl.style.setProperty('opacity', '1', 'important');
            tl.style.setProperty('color', 'black', 'important');
            tl.style.setProperty('text-shadow', 'none', 'important');
            tl.style.setProperty('visibility', 'visible', 'important');
        });

        el.querySelectorAll('svg').forEach(svg => {
            svg.style.setProperty('opacity', '1', 'important');
            svg.style.setProperty('filter', 'none', 'important');
            svg.style.setProperty('visibility', 'visible', 'important');
        });
    }

    const viewerContainer = document.createElement('div');
    viewerContainer.id = 'clean-viewer-container';

    pages.forEach((page, index) => {
        const pageStyle = window.getComputedStyle(page);
        let width = parseFloat(pageStyle.width);
        let height = parseFloat(pageStyle.height);

        if (isNaN(width) || width <= 0 || isNaN(height) || height <= 0) {
            const rect = page.getBoundingClientRect();
            width = rect.width;
            height = rect.height;
        }

        if (isNaN(width) || width <= 10) width = 595.3;
        if (isNaN(height) || height <= 10) height = 841.9;

        const newPage = document.createElement('div');
        newPage.className = 'std-page';
        newPage.id = `page-${index + 1}`;
        newPage.setAttribute('data-page-number', index + 1);

        newPage.style.width = width + 'px';
        newPage.style.height = height + 'px';
        newPage.style.position = 'relative';
        newPage.style.overflow = 'hidden';
        newPage.style.margin = '0 auto 20px auto';
        newPage.style.backgroundColor = 'white';

        const pageClone = page.cloneNode(true);

        pageClone.style.setProperty('position', 'absolute', 'important');
        pageClone.style.setProperty('top', '0', 'important');
        pageClone.style.setProperty('left', '0', 'important');
        pageClone.style.setProperty('width', '100%', 'important');
        pageClone.style.setProperty('height', '100%', 'important');
        pageClone.style.setProperty('transform', 'none', 'important');
        pageClone.style.setProperty('margin', '0', 'important');
        pageClone.style.setProperty('box-shadow', 'none', 'important');

        cleanPage(pageClone);

        newPage.appendChild(pageClone);
        viewerContainer.appendChild(newPage);
    });

    document.body.appendChild(viewerContainer);

    const styleEl = document.createElement('style');
    styleEl.innerHTML = `
        body > *:not(#clean-viewer-container) { 
            display: none !important; 
        }
        #clean-viewer-container {
            position: absolute !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            display: flex !important;
            flex-direction: column !important;
            align-items: center !important;
            padding: 30px 0 !important;
            z-index: 999999 !important;
            background: #f6f7fb !important;
        }
        @media print {
            @page { 
                margin: 0; 
                size: auto; 
            }
            body { 
                background-color: white !important; 
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            #clean-viewer-container { 
                position: static !important; 
                width: 100% !important; 
                padding: 0 !important; 
                margin: 0 !important; 
            }
            .std-page {
                margin: 0 !important; 
                margin-bottom: 0 !important;
                box-shadow: none !important;
                page-break-after: always !important;
                break-after: always !important;
                border: none !important;
            }
        }
    `;
    document.head.appendChild(styleEl);

    setTimeout(() => {
        overlayInfo.style.opacity = '0';
        setTimeout(() => overlayInfo.remove(), 300);
        window.print();
    }, 1000);
})();
