(function() {
    const pages = document.querySelectorAll('div[data-page-index]');
    if (pages.length === 0) {
        alert("⚠️ Không tìm thấy trang nào.\n(Hãy cuộn chuột xuống cuối tài liệu để web tải hết nội dung trước!)");
        return;
    }

    const lang = window.__banhmi_lang || 'vi';
    
    const messages = {
        vi: {
            title: `Sẵn sàng tạo PDF cho tài liệu gồm ${pages.length} trang.`,
            watermark: '📍 Trước khi tải nhớ bấm "XEM FILE" nếu file bị dính Watermark.',
            cancel: '❌ Bấm Cancel nếu bạn CHƯA kéo tài liệu xuống cuối cùng (tài liệu sẽ bị trắng nếu chưa được load toàn bộ)',
            ok: '✅ Bấm Ok nếu bạn ĐÃ kéo tài liệu xuống cuối cùng trước khi tải.'
        },
        en: {
            title: `Ready to generate PDF for a ${pages.length}-page document.`,
            watermark: '📍 Before downloading, remember to click "VIEW FILE" if the file has a Watermark.',
            cancel: '❌ Click Cancel if you HAVE NOT scrolled the document to the bottom (the document will be blank if not fully loaded).',
            ok: '✅ Click OK if you HAVE scrolled the document to the bottom before downloading.'
        },
        es: {
            title: `Listo para generar PDF para un documento de ${pages.length} páginas.`,
            watermark: '📍 Antes de descargar, recuerde hacer clic en "VER ARCHIVO" si el archivo tiene Marca de agua.',
            cancel: '❌ Haga clic en Cancelar si NO HA desplazado el documento hasta el final (el documento estará en blanco si no está completamente cargado).',
            ok: '✅ Haga clic en Aceptar si HA desplazado el documento hasta el final antes de descargarlo.'
        },
        id: {
            title: `Siap menghasilkan PDF untuk dokumen ${pages.length} halaman.`,
            watermark: '📍 Sebelum mengunduh, harap klik "LIHAT FILE" jika file memiliki Watermark.',
            cancel: '❌ Klik Batal (Cancel) jika Anda BELUM menggulir dokumen ke bagian bawah (dokumen akan kosong/putih jika tidak dimuat sepenuhnya).',
            ok: '✅ Klik OK jika Anda SUDAH menggulir dokumen ke bagian bawah sebelum mengunduh.'
        },
        pt: {
            title: `Pronto para gerar PDF para um documento de ${pages.length} páginas.`,
            watermark: '📍 Antes de baixar, lembre-se de clicar em "VER ARQUIVO" se o arquivo tiver Marca d\'água.',
            cancel: '❌ Clique em Cancelar se você NÃO ROLOU o documento até o final (o documento ficará em branco se não estiver totalmente carregado).',
            ok: '✅ Clique em OK se você ROLOU o documento até o final antes de baixar.'
        }
    };

    const msg = messages[lang] || messages.vi;
    const confirmMsg = `${msg.title}\n\nLưu ý quan trọng:\n${msg.watermark}\n${msg.cancel}\n${msg.ok}`;

    if (!confirm(confirmMsg)) return;

    const SCALE_FACTOR = 4;
    const HEIGHT_SCALE_DIVISOR = 4;

    function copyComputedStyle(source, target, scaleFactor, shouldScaleHeight = false, shouldScaleWidth = false, heightScaleDivisor = 4, widthScaleDivisor = 4, shouldScaleMargin = false, marginScaleDivisor = 4) {
        const computedStyle = window.getComputedStyle(source);

        const normalProps = [
            'position', 'left', 'top', 'bottom', 'right',
            'font-family', 'font-weight', 'font-style',
            'color', 'background-color',
            'text-align', 'white-space',
            'display', 'visibility', 'opacity', 'z-index',
            'text-shadow', 'unicode-bidi', 'font-feature-settings', 'padding'
        ];

        const scaleProps = ['font-size', 'line-height'];
        let styleString = '';

        normalProps.forEach(prop => {
            const value = computedStyle.getPropertyValue(prop);
            if (value && value !== 'none' && value !== 'auto' && value !== 'normal') {
                styleString += `${prop}: ${value} !important; `;
            }
        });

        const widthValue = computedStyle.getPropertyValue('width');
        if (widthValue && widthValue !== 'none' && widthValue !== 'auto') {
            if (shouldScaleWidth) {
                const numValue = parseFloat(widthValue);
                if (!isNaN(numValue) && numValue > 0) {
                    const unit = widthValue.replace(numValue.toString(), '');
                    styleString += `width: ${numValue / widthScaleDivisor}${unit} !important; `;
                } else {
                    styleString += `width: ${widthValue} !important; `;
                }
            } else {
                styleString += `width: ${widthValue} !important; `;
            }
        }

        const heightValue = computedStyle.getPropertyValue('height');
        if (heightValue && heightValue !== 'none' && heightValue !== 'auto') {
            if (shouldScaleHeight) {
                const numValue = parseFloat(heightValue);
                if (!isNaN(numValue) && numValue > 0) {
                    const unit = heightValue.replace(numValue.toString(), '');
                    styleString += `height: ${numValue / heightScaleDivisor}${unit} !important; `;
                } else {
                    styleString += `height: ${heightValue} !important; `;
                }
            } else {
                styleString += `height: ${heightValue} !important; `;
            }
        }

        ['margin-top', 'margin-right', 'margin-bottom', 'margin-left'].forEach(prop => {
            const value = computedStyle.getPropertyValue(prop);
            if (value && value !== 'auto') {
                const numValue = parseFloat(value);
                if (!isNaN(numValue)) {
                    if (shouldScaleMargin && numValue !== 0) {
                        const unit = value.replace(numValue.toString(), '');
                        styleString += `${prop}: ${numValue / marginScaleDivisor}${unit} !important; `;
                    } else {
                        styleString += `${prop}: ${value} !important; `;
                    }
                }
            }
        });

        scaleProps.forEach(prop => {
            const value = computedStyle.getPropertyValue(prop);
            if (value && value !== 'none' && value !== 'auto' && value !== 'normal') {
                const numValue = parseFloat(value);
                if (!isNaN(numValue) && numValue !== 0) {
                    const unit = value.replace(numValue.toString(), '');
                    styleString += `${prop}: ${numValue / scaleFactor}${unit} !important; `;
                } else {
                    styleString += `${prop}: ${value} !important; `;
                }
            }
        });

        let transformOrigin = computedStyle.getPropertyValue('transform-origin');
        if (transformOrigin) {
            styleString += `transform-origin: ${transformOrigin} !important; -webkit-transform-origin: ${transformOrigin} !important; `;
        }

        styleString += 'overflow: visible !important; max-width: none !important; max-height: none !important; clip: auto !important; clip-path: none !important; ';
        target.style.cssText += styleString;
    }

    function deepCloneWithStyles(element, scaleFactor, heightScaleDivisor, depth = 0) {
        const clone = element.cloneNode(false);
        const hasTextClass = element.classList && element.classList.contains('t');
        const hasUnderscoreClass = element.classList && element.classList.contains('_');

        const shouldScaleMargin = element.tagName === 'SPAN' &&
            element.classList &&
            element.classList.contains('_') &&
            Array.from(element.classList).some(cls => /^_(?:\d+[a-z]*|[a-z]+\d*)$/i.test(cls));

        copyComputedStyle(element, clone, scaleFactor, hasTextClass, hasUnderscoreClass, heightScaleDivisor, 4, shouldScaleMargin, scaleFactor);

        if (element.classList && element.classList.contains('pc')) {
            clone.style.setProperty('transform', 'none', 'important');
            clone.style.setProperty('-webkit-transform', 'none', 'important');
            clone.style.setProperty('overflow', 'visible', 'important');
            clone.style.setProperty('max-width', 'none', 'important');
            clone.style.setProperty('max-height', 'none', 'important');
        }

        if (element.childNodes.length === 1 && element.childNodes[0].nodeType === 3) {
            clone.textContent = element.textContent;
        } else {
            element.childNodes.forEach(child => {
                if (child.nodeType === 1) {
                    clone.appendChild(deepCloneWithStyles(child, scaleFactor, heightScaleDivisor, depth + 1));
                } else if (child.nodeType === 3) {
                    clone.appendChild(child.cloneNode(true));
                }
            });
        }
        return clone;
    }

    // Build
    const viewerContainer = document.createElement('div');
    viewerContainer.id = 'clean-viewer-container';

    pages.forEach((page, index) => {
        const pc = page.querySelector('.pc');
        let width = 595.3; //Fallback A4
        let height = 841.9;

        if (pc) {
            const pcStyle = window.getComputedStyle(pc);
            const pcWidth = parseFloat(pcStyle.width);
            const pcHeight = parseFloat(pcStyle.height);

            if (!isNaN(pcWidth) && pcWidth > 0 && !isNaN(pcHeight) && pcHeight > 0) {
                width = pcWidth;
                height = pcHeight;
            } else {
                const rect = pc.getBoundingClientRect();
                if (rect.width > 10 && rect.height > 10) {
                    width = rect.width;
                    height = rect.height;
                }
            }
        }

        const newPage = document.createElement('div');
        newPage.className = 'std-page';
        newPage.id = `page-${index + 1}`;
        newPage.setAttribute('data-page-number', index + 1);

        newPage.style.width = width + 'px';
        newPage.style.height = height + 'px';

        // Layer ảnh
        const originalImg = page.querySelector('img.bi') || page.querySelector('img');
        if (originalImg) {
            const bgLayer = document.createElement('div');
            bgLayer.className = 'layer-bg';
            const imgClone = originalImg.cloneNode(true);
            imgClone.style.cssText = 'width: 100%; height: 100%; object-fit: cover; object-position: top center';
            bgLayer.appendChild(imgClone);
            newPage.appendChild(bgLayer);
        }

        // Layer Text
        const originalPc = page.querySelector('.pc');
        if (originalPc) {
            const textLayer = document.createElement('div');
            textLayer.className = 'layer-text';
            const pcClone = deepCloneWithStyles(originalPc, SCALE_FACTOR, HEIGHT_SCALE_DIVISOR);

            pcClone.querySelectorAll('img').forEach(img => img.style.display = 'none');
            textLayer.appendChild(pcClone);
            newPage.appendChild(textLayer);
        }

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
        window.print();
    }, 1000);
})();
