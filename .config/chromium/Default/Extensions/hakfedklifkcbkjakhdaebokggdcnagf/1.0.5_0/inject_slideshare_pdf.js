(function() {
    function getSlideShareImages() {
        let images = [];
        
        // Cách 1: Quét đệ quy đối tượng __NEXT_DATA__
        try {
            const nextDataEl = document.getElementById('__NEXT_DATA__');
            if (nextDataEl) {
                const data = JSON.parse(nextDataEl.textContent);
                
                // 1. Tìm tổng số slide đệ quy
                let totalSlidesCount = 0;
                function findTotalSlides(obj) {
                    if (!obj || typeof obj !== 'object') return;
                    if (typeof obj.totalSlides === 'number' && obj.totalSlides > 0) {
                        totalSlidesCount = obj.totalSlides;
                        return;
                    }
                    if (typeof obj.total === 'number' && obj.total > 0 && obj.host && obj.imageLocation) {
                        totalSlidesCount = obj.total;
                        return;
                    }
                    for (const k in obj) {
                        if (Object.prototype.hasOwnProperty.call(obj, k)) {
                            findTotalSlides(obj[k]);
                            if (totalSlidesCount > 0) return;
                        }
                    }
                }
                findTotalSlides(data);
                
                // 2. Tìm metadata chứa host và imageLocation
                let metadata = null;
                function findSlidesMetadata(obj) {
                    if (!obj || typeof obj !== 'object') return;
                    if (obj.host && typeof obj.host === 'string' && obj.host.includes('slideshare') && obj.imageLocation) {
                        metadata = obj;
                        return;
                    }
                    for (const k in obj) {
                        if (Object.prototype.hasOwnProperty.call(obj, k)) {
                            findSlidesMetadata(obj[k]);
                            if (metadata) return;
                        }
                    }
                }
                findSlidesMetadata(data);
                
                if (metadata) {
                    const base_url = metadata.host;
                    const loc = metadata.imageLocation;
                    const title = metadata.title || '';
                    const total = totalSlidesCount || metadata.totalSlides || metadata.total || 100;
                    
                    const sizes = metadata.imageSizes || [];
                    if (sizes.length > 0) {
                        sizes.sort((a, b) => b.width - a.width);
                        const bestSize = sizes[0];
                        const quality = bestSize.quality;
                        const width = bestSize.width;
                        
                        for (let i = 1; i <= total; i++) {
                            const imgUrl = `${base_url}/${loc}/${quality}/${title}-${i}-${width}.jpg`;
                            images.push(imgUrl);
                        }
                    }
                }
                
                // 3. Fallback: Nếu không tìm thấy metadata, thu gom bất kỳ link ảnh CDN trực tiếp nào trong JSON
                if (images.length === 0) {
                    let directUrls = new Set();
                    function collectDirectUrls(obj) {
                        if (!obj) return;
                        if (typeof obj === 'string') {
                            if (obj.includes('slidesharecdn.com') && (obj.endsWith('.jpg') || obj.endsWith('.png') || obj.includes('.jpg?') || obj.includes('.png?'))) {
                                directUrls.add(obj);
                            }
                        } else if (typeof obj === 'object') {
                            for (const k in obj) {
                                if (Object.prototype.hasOwnProperty.call(obj, k)) {
                                    collectDirectUrls(obj[k]);
                                }
                            }
                        }
                    }
                    collectDirectUrls(data);
                    if (directUrls.size > 0) {
                        images = Array.from(directUrls);
                        images.sort((a, b) => {
                            const matchA = a.match(/-(\d+)-\d+\.jpg/);
                            const matchB = b.match(/-(\d+)-\d+\.jpg/);
                            if (matchA && matchB) {
                                return parseInt(matchA[1], 10) - parseInt(matchB[1], 10);
                            }
                            return 0;
                        });
                    }
                }
            }
        } catch (e) {
            console.error("Lỗi cào Next.js JSON:", e);
        }
        
        // Cách 2: Cào DOM nâng cao (Bypass lazy loading qua src/srcset/attributes chứa slidesharecdn)
        if (images.length === 0) {
            const pictures = document.querySelectorAll('picture');
            pictures.forEach(pic => {
                const source = pic.querySelector('source');
                let url = null;
                if (source) {
                    const srcset = source.getAttribute('srcset');
                    if (srcset) {
                        const parts = srcset.split(',').map(s => s.trim()).filter(Boolean);
                        let maxWidth = -1;
                        for (const part of parts) {
                            const match = part.match(/^(\S+)\s+(\d+)w$/);
                            if (match) {
                                const w = parseInt(match[2], 10);
                                if (w > maxWidth && match[1].includes('slidesharecdn.com')) {
                                    maxWidth = w;
                                    url = match[1];
                                }
                            } else if (part.includes('slidesharecdn.com')) {
                                url = part;
                            }
                        }
                    }
                }
                if (!url) {
                    const img = pic.querySelector('img');
                    if (img) {
                        const src = img.getAttribute('src') || img.getAttribute('data-src') || img.getAttribute('data-full');
                        if (src && src.includes('slidesharecdn.com')) url = src;
                    }
                }
                if (url) images.push(url);
            });
        }
        
        if (images.length === 0) {
            const imgs = document.querySelectorAll('img');
            imgs.forEach(img => {
                const src = img.getAttribute('src') || 
                            img.getAttribute('data-src') || 
                            img.getAttribute('data-full') || 
                            img.getAttribute('srcset') ||
                            img.getAttribute('data-lazy-src');
                
                if (src && src.includes('slidesharecdn.com')) {
                    if (src.includes(' ')) {
                        const parts = src.split(',').map(s => s.trim()).filter(Boolean);
                        let maxWidth = -1;
                        let bestUrl = null;
                        for (const part of parts) {
                            const match = part.match(/^(\S+)\s+(\d+)w$/);
                            if (match) {
                                const w = parseInt(match[2], 10);
                                if (w > maxWidth) {
                                    maxWidth = w;
                                    bestUrl = match[1];
                                }
                            } else {
                                bestUrl = part;
                            }
                        }
                        if (bestUrl) images.push(bestUrl);
                    } else {
                        images.push(src);
                    }
                }
            });
        }
        
        return Array.from(new Set(images));
    }

    const images = getSlideShareImages();
    if (images.length === 0) {
        alert("⚠️ Không tìm thấy slide nào trên trang SlideShare này.\n(Hãy đảm bảo bạn đang ở trang tài liệu chi tiết!)");
        return;
    }

    const lang = window.__banhmi_lang || 'vi';
    
    const messages = {
        vi: {
            title: `Sẵn sàng tạo PDF cho tài liệu SlideShare gồm ${images.length} slide.`,
            watermark: '📍 Trước khi tải nhớ bấm "DỌN SẠCH" nếu giao diện bị dính quảng cáo.',
            cancel: '❌ Bấm Cancel nếu bạn CHƯA kéo tài liệu xuống cuối cùng (tài liệu sẽ bị trắng nếu chưa được load toàn bộ)',
            ok: '✅ Bấm Ok nếu bạn ĐÃ kéo tài liệu xuống cuối cùng trước khi tải.'
        },
        en: {
            title: `Ready to generate PDF for a ${images.length}-slide SlideShare document.`,
            watermark: '📍 Before downloading, remember to click "CLEAN AD" if the interface has ads.',
            cancel: '❌ Click Cancel if you HAVE NOT scrolled the slides to the bottom (they will be blank if not fully loaded).',
            ok: '✅ Click OK if you HAVE scrolled the slides to the bottom before downloading.'
        },
        es: {
            title: `Listo para generar PDF para un documento SlideShare de ${images.length} diapositivas.`,
            watermark: '📍 Antes de descargar, recuerde hacer clic en "LIMPIAR" si la interfaz tiene anuncios.',
            cancel: '❌ Haga clic en Cancelar si NO HA desplazado las diapositivas hasta el final (estarán en blanco si no están completamente cargadas).',
            ok: '✅ Haga clic en Aceptar si HA desplazado las diapositivas hasta el final antes de descargarlas.'
        },
        id: {
            title: `Siap menghasilkan PDF untuk dokumen SlideShare ${images.length} slide.`,
            watermark: '📍 Sebelum mengunduh, harap klik "BERSIHKAN IKLAN" jika tampilan memiliki iklan.',
            cancel: '❌ Klik Batal (Cancel) jika Anda BELUM menggulir slide ke bagian bawah (slide akan kosong/putih jika tidak dimuat sepenuhnya).',
            ok: '✅ Klik OK jika Anda SUDAH menggulir slide ke bagian bawah sebelum mengunduh.'
        },
        pt: {
            title: `Pronto para gerar PDF para um documento SlideShare de ${images.length} slides.`,
            watermark: '📍 Antes de baixar, lembre-se de clicar em "LIMPAR" se a interface tiver anúncios.',
            cancel: '❌ Clique em Cancelar se você NÃO ROLOU os slides até o final (eles ficarão em branco se não estiverem totalmente carregados).',
            ok: '✅ Clique em OK se você ROLOU os slides até o final antes de baixar.'
        }
    };

    const msg = messages[lang] || messages.vi;
    const confirmMsg = `${msg.title}\n\nLưu ý quan trọng:\n${msg.watermark}\n${msg.cancel}\n${msg.ok}`;

    if (!confirm(confirmMsg)) return;

    const overlayInfo = document.createElement('div');
    overlayInfo.id = "banhmi-overlay-status";
    overlayInfo.style.cssText = "position:fixed; top:20px; right:20px; background:#0077B5; color:white; padding:15px 25px; border-radius:10px; font-family:sans-serif; font-weight:bold; z-index:999999; box-shadow:0 4px 12px rgba(0,0,0,0.2); transition: opacity 0.3s ease;";
    overlayInfo.innerText = "🚀 Đang tự động trích xuất các slide chất lượng cao...";
    document.body.appendChild(overlayInfo);

    const viewerContainer = document.createElement('div');
    viewerContainer.id = 'clean-viewer-container';

    images.forEach((imgUrl, index) => {
        const newPage = document.createElement('div');
        newPage.className = 'slideshare-clean-page';
        newPage.id = `slide-${index + 1}`;
        
        const img = document.createElement('img');
        img.src = imgUrl;
        img.style.cssText = "width: 100%; height: 100%; object-fit: contain;";
        
        newPage.appendChild(img);
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
            padding: 0 !important;
            margin: 0 !important;
            z-index: 999999 !important;
            background: white !important;
        }
        .slideshare-clean-page {
            width: 100vw !important;
            height: 56.25vw !important; /* Tỷ lệ 16:9 chuẩn */
            margin: 0 !important;
            padding: 0 !important;
            display: flex !important;
            justify-content: center !important;
            align-items: center !important;
            background: white !important;
            page-break-after: always !important;
            break-after: always !important;
        }
        @media print {
            @page { 
                margin: 0; 
                size: landscape; 
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
            .slideshare-clean-page {
                width: 100% !important;
                height: 100% !important;
                margin: 0 !important; 
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
