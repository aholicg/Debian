// Status
function updateStatus(msg, isProcessing = false) {
    console.log(msg); // Status UI has been removed
}

let activeTab = null;

// Get target tab (handles normal popup and popped out window)
async function getTargetTab() {
    // Fast path: normal popup mode, query active tab in current window directly
    if (!window.location.search || !window.location.search.includes('windowId')) {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab) return tab;
        } catch (e) {}
    } else {
        // Slow path: Popout mode (parse parameters and query target window)
        const urlParams = new URLSearchParams(window.location.search);
        const windowIdParam = urlParams.get('windowId');
        if (windowIdParam) {
            const windowId = parseInt(windowIdParam, 10);
            try {
                const [tab] = await chrome.tabs.query({ active: true, windowId: windowId });
                if (tab) return tab;
            } catch (e) {}
        }
    }
    
    // Fallback 1: Query active tab in the last focused window
    try {
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (tab && !tab.url.startsWith(chrome.runtime.getURL(""))) {
            return tab;
        }
    } catch (e) {}
    
    // Fallback 2: Query all active tabs and find the one that is not this extension
    try {
        const tabs = await chrome.tabs.query({ active: true });
        const extensionUrlPrefix = chrome.runtime.getURL("");
        const nonExtensionTabs = tabs.filter(t => t.url && !t.url.startsWith(extensionUrlPrefix));
        if (nonExtensionTabs.length > 0) {
            return nonExtensionTabs[0];
        }
    } catch (e) {}
    
    // Final fallback
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
}

// Start tab query immediately (runs in parallel with DOM parsing)
const activeTabPromise = getTargetTab().then(tab => {
    activeTab = tab;
    return tab;
});

async function clearCookiesAndReload(tab, btnElement = null) {
    if (btnElement) {
        btnElement.style.opacity = '0.5';
        btnElement.style.pointerEvents = 'none';
        const heading = btnElement.querySelector('.btn-heading');
        if (heading) heading.innerText = "Đang xử lý...";
    }

    try {
        const allCookies = await chrome.cookies.getAll({});
        for (const cookie of allCookies) {
            if (cookie.domain.includes('studocu')) {
                let cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
                const protocol = cookie.secure ? "https:" : "http:";
                const url = `${protocol}//${cleanDomain}${cookie.path}`;
                await chrome.cookies.remove({ url: url, name: cookie.name, storeId: cookie.storeId });
            }
        }

        // Wait to ensure cookies deletion translates to network
        await new Promise(r => setTimeout(r, 300));

        chrome.tabs.reload(tab.id);

        // Wait a bit and restore button state
        await new Promise(r => setTimeout(r, 1500));
        if (btnElement) {
            btnElement.style.opacity = '1';
            btnElement.style.pointerEvents = 'auto';
            updateDynamicTexts();
        }

    } catch (e) {
        alert("Lỗi: " + e.message);
        if (btnElement) {
            btnElement.style.opacity = '1';
            btnElement.style.pointerEvents = 'auto';
            const heading = btnElement.querySelector('.btn-heading');
            if (heading) heading.innerText = "Xem file & Xóa Watermark";
        }
    }
}

// Deferred initialization of all event listeners & DOM queries to avoid blocking paint
function initEventListeners() {
    // Mở khóa / Xem file & Xóa Watermark click listener
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async (e) => {
            const tab = activeTab || await getTargetTab();
            if (!tab) {
                alert("⚠️ Không thể xác định tab hiện tại.");
                return;
            }
            
            if (tab.url.includes("studocu")) {
                clearCookiesAndReload(tab, e.currentTarget);
            } else if (tab.url.includes("scribd.com")) {
                try {
                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ["inject_scribd_unblur.js"]
                    });
                } catch (err) {
                    alert("⚠️ Lỗi: " + err.message);
                }
            } else if (tab.url.includes("slideshare.net")) {
                try {
                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ["inject_slideshare_unblur.js"]
                    });
                } catch (err) {
                    alert("⚠️ Lỗi: " + err.message);
                }
            } else {
                alert("⚠️ Tính năng này chỉ hoạt động trên trang Studocu, Scribd hoặc SlideShare.");
            }
        });
    }

    // Tải File PDF click listener
    const checkBtn = document.getElementById('checkBtn');
    if (checkBtn) {
        checkBtn.addEventListener('click', async (e) => {
            const tab = activeTab || await getTargetTab();
            if (!tab) {
                alert("⚠️ Không thể xác định tab hiện tại.");
                return;
            }

            if (tab.url.includes("studocu")) {
                try {
                    await chrome.scripting.insertCSS({
                        target: { tabId: tab.id },
                        files: ["viewer_styles.css"]
                    });

                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        func: (lang) => { window.__banhmi_lang = lang; },
                        args: [currentLang]
                    });

                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ["inject_studocu_pdf.js"]
                    });
                } catch (err) {
                    alert("⚠️ Lỗi: " + err.message);
                }
            } else if (tab.url.includes("scribd.com")) {
                try {
                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        func: (lang) => { window.__banhmi_lang = lang; },
                        args: [currentLang]
                    });

                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ["inject_scribd_pdf.js"]
                    });
                } catch (err) {
                    alert("⚠️ Lỗi: " + err.message);
                }
            } else if (tab.url.includes("slideshare.net")) {
                try {
                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        func: (lang) => { window.__banhmi_lang = lang; },
                        args: [currentLang]
                    });

                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ["inject_slideshare_pdf.js"]
                    });
                } catch (err) {
                    alert("⚠️ Lỗi: " + err.message);
                }
            } else {
                alert("⚠️ Tính năng này chỉ hoạt động trên trang Studocu, Scribd hoặc SlideShare.");
            }
        });
    }

    // Language switch click listener
    const langToggleBtn = document.getElementById('langToggleBtn');
    if (langToggleBtn) {
        langToggleBtn.addEventListener('click', () => {
            const currentIndex = LANG_SEQUENCE.indexOf(currentLang);
            const nextIndex = (currentIndex + 1) % LANG_SEQUENCE.length;
            const nextLang = LANG_SEQUENCE[nextIndex];
            applyLanguage(nextLang);
        });
    }

    // QR Modal logic
    const qrPromoBtn = document.getElementById('qrPromoBtn');
    const qrModal = document.getElementById('qrModal');
    const qrClose = document.querySelector('.qr-close');

    if (qrPromoBtn && qrModal && qrClose) {
        qrPromoBtn.addEventListener('click', () => {
            const modalContent = document.getElementById('modalContent');
            if (modalContent) {
                modalContent.innerHTML = getDonateModalHTML(currentLang);
            }
            qrModal.style.display = 'flex';
        });

        qrClose.addEventListener('click', () => {
            qrModal.style.display = 'none';
        });

        qrModal.addEventListener('click', (e) => {
            if (e.target === qrModal) {
                qrModal.style.display = 'none';
            }
        });
    }

    // Support links click listeners
    const studocuBtn = document.getElementById('studocuBtn');
    if (studocuBtn) {
        studocuBtn.addEventListener('click', () => {
            const url = (currentLang === 'vi') ? 'https://www.studocu.vn/vn' : 'https://www.studocu.com/';
            chrome.tabs.create({ url: url });
        });
    }

    const scribdBtn = document.getElementById('scribdBtn');
    if (scribdBtn) {
        scribdBtn.addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://www.scribd.com/' });
        });
    }

    const slideshareBtn = document.getElementById('slideshareBtn');
    if (slideshareBtn) {
        slideshareBtn.addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://www.slideshare.net/' });
        });
    }

    const vpnBtn = document.getElementById('vpnBtn');
    if (vpnBtn) {
        vpnBtn.addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://one.one.one.one/' });
        });
    }

    const guideLinkBtn = document.getElementById('guideLinkBtn');
    if (guideLinkBtn) {
        guideLinkBtn.addEventListener('click', (e) => {
            e.preventDefault();
            chrome.tabs.create({ url: 'https://tinyurl.com/banhmicampha' });
        });
    }

    // Rating click listener
    const rateBtn = document.getElementById('rateBtn');
    if (rateBtn) {
        rateBtn.addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://chromewebstore.google.com/detail/hakfedklifkcbkjakhdaebokggdcnagf?utm_source=item-share-cb' });
        });
    }

    // Popout button standalone logic
    const popoutBtn = document.getElementById('popoutBtn');
    if (popoutBtn) {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('mode') === 'standalone') {
            popoutBtn.style.display = 'none';
        } else {
            popoutBtn.addEventListener('click', async () => {
                const tab = activeTab || await getTargetTab();
                const targetWindowId = tab ? tab.windowId : null;
                
                let url = chrome.runtime.getURL("popup.html?mode=standalone");
                if (targetWindowId) {
                    url += `&windowId=${targetWindowId}`;
                }
                
                chrome.windows.create({
                    url: url,
                    type: "popup",
                    width: 360,
                    height: 640
                });
                window.close(); // Close the dropdown popup
            });
        }
    }
}

// Localization Dictionary
const TRANSLATIONS = {
    vi: {
        mainTitle: "Bánh Mì Cẩm Phả",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Lưu ý:</strong> Hãy cuộn chuột xuống cuối để tải hết trang trước khi Tải PDF, tránh bị trắng trang!</span>',
        supportTitle: "Truy cập & Kết nối",
        studocuTitle: "Studocu VN",
        studocuSub: "Vào trang chủ",
        scribdSub: "Vào trang chủ",
        slideshareSub: "Vào trang chủ",
        vpnTitle: "Tải 1.1.1.1",
        vpnSub: "Vượt chặn mạng",
        vpnGuide: "💡 <strong>Sửa lỗi:</strong> Cài đặt <strong>1.1.1.1 (WARP)</strong> giúp vượt chặn & truy cập Studocu mượt mà khi gặp lỗi kết nối.",
        serviceTitle: "Liên hệ & Dịch vụ SPSS, NCKH",
        serviceSub: "Chạy khảo sát SPSS, xử lý & lọc số liệu uy tín",
        coffeeTitle: "Mời ly cà phê",
        coffeeScanText: "QUÉT MÃ TẠI ĐÂY ➔",
        rateTitle: "Đánh giá 5 sao",
        rateSub: "Ủng hộ tiện ích",
        
        outsideCheckHeading: "Tải File PDF",
        outsideCheckSub: "Hãy mở trang Studocu, Scribd hoặc SlideShare",
        outsideClearHeading: "Mở khóa Tài liệu",
        outsideClearSub: "Hãy mở trang Studocu, Scribd hoặc SlideShare",
        
        studocuCheckHeading: "Tải File PDF",
        studocuCheckSub: "Tự động dàn trang in",
        studocuClearHeading: "Xem file & Xóa Watermark",
        studocuClearSub: "Vượt rào cản tài liệu",
        
        scribdCheckHeading: "Tải PDF Scribd",
        scribdCheckSub: "Tự động tải & unblur PDF",
        scribdClearHeading: "Mở khóa & Xóa Banner",
        scribdClearSub: "Unblur nội dung xem online",
        
        slideshareCheckHeading: "Tải PDF SlideShare",
        slideshareCheckSub: "Tự động tải & dàn trang in slide",
        slideshareClearHeading: "Dọn Sạch Quảng Cáo",
        slideshareClearSub: "Tối ưu giao diện xem online"
    },
    en: {
        mainTitle: "DocuBami",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Note:</strong> Scroll to the bottom to load all pages before downloading to avoid blank pages.</span>',
        supportTitle: "Quick Access & Links",
        studocuTitle: "Studocu.com",
        studocuSub: "Visit website",
        scribdSub: "Visit website",
        slideshareSub: "Visit website",
        vpnTitle: "Download 1.1.1.1",
        vpnSub: "Bypass blocks",
        vpnGuide: "💡 <strong>Fix:</strong> Installing <strong>1.1.1.1 (WARP)</strong> helps bypass network blocks and access Studocu smoothly.",
        serviceTitle: "SPSS & Research Services",
        serviceSub: "Professional SPSS surveys, data processing & analysis",
        coffeeTitle: "Buy me a Coffee",
        coffeeScanText: "DONATE HERE ➔",
        rateTitle: "Rate 5 Stars",
        rateSub: "Support extension",
        
        outsideCheckHeading: "Download PDF",
        outsideCheckSub: "Open Studocu, Scribd or SlideShare",
        outsideClearHeading: "Unlock Document",
        outsideClearSub: "Open Studocu, Scribd or SlideShare",
        
        studocuCheckHeading: "Download PDF",
        studocuCheckSub: "Auto layout for printing",
        studocuClearHeading: "View File & Remove Watermark",
        studocuClearSub: "Bypass document limits",
        
        scribdCheckHeading: "Download Scribd PDF",
        scribdCheckSub: "Auto unblur & download",
        scribdClearHeading: "Unlock & Remove Banners",
        scribdClearSub: "Unblur online reading",
        
        slideshareCheckHeading: "Download SlideShare PDF",
        slideshareCheckSub: "Auto landscape PDF",
        slideshareClearHeading: "Remove Advertisements",
        slideshareClearSub: "Optimize online interface"
    },
    es: {
        mainTitle: "DocuBami",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Nota:</strong> Desplácese al final para cargar todo el documento antes de descargar y evitar páginas en blanco.</span>',
        supportTitle: "Acceso Rápido y Enlaces",
        studocuTitle: "Studocu.com",
        studocuSub: "Visitar sitio",
        scribdSub: "Visitar sitio",
        slideshareSub: "Visitar sitio",
        vpnTitle: "Descargar 1.1.1.1",
        vpnSub: "Evitar bloqueos",
        vpnGuide: "💡 <strong>Solución:</strong> Instalar <strong>1.1.1.1 (WARP)</strong> ayuda a saltarse los bloqueos de red y acceder a Studocu sin problemas.",
        serviceTitle: "Servicios SPSS & Investigación",
        serviceSub: "Análisis y procesamiento de datos SPSS profesionales",
        coffeeTitle: "Invítame a un café",
        coffeeScanText: "DONAR AQUÍ ➔",
        rateTitle: "Calificar 5 Estrellas",
        rateSub: "Apoyar extensión",
        
        outsideCheckHeading: "Descargar PDF",
        outsideCheckSub: "Abra Studocu, Scribd o SlideShare",
        outsideClearHeading: "Desbloquear Documento",
        outsideClearSub: "Abra Studocu, Scribd o SlideShare",
        
        studocuCheckHeading: "Descargar PDF",
        studocuCheckSub: "Diseño automático para impresión",
        studocuClearHeading: "Ver archivo y quitar marca de agua",
        studocuClearSub: "Superar límites del documento",
        
        scribdCheckHeading: "Descargar PDF Scribd",
        scribdCheckSub: "Auto desbloqueo y descarga",
        scribdClearHeading: "Desbloquear y quitar banners",
        scribdClearSub: "Desbloquear lectura en línea",
        
        slideshareCheckHeading: "Descargar PDF SlideShare",
        slideshareCheckSub: "PDF horizontal automático",
        slideshareClearHeading: "Quitar anuncios",
        slideshareClearSub: "Optimizar interfaz en línea"
    },
    id: {
        mainTitle: "DocuBami",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Catatan:</strong> Gulir ke bawah untuk memuat semua halaman sebelum mengunduh agar tidak ada halaman kosong.</span>',
        supportTitle: "Akses Cepat & Tautan",
        studocuTitle: "Studocu.com",
        studocuSub: "Buka situs",
        scribdSub: "Buka situs",
        slideshareSub: "Buka situs",
        vpnTitle: "Unduh 1.1.1.1",
        vpnSub: "Lewati blokir",
        vpnGuide: "💡 <strong>Solusi:</strong> Menginstal <strong>1.1.1.1 (WARP)</strong> membantu melewati blokir internet dan mengakses Studocu dengan lancar.",
        serviceTitle: "Layanan SPSS & Analisis",
        serviceSub: "Pemrosesan & analisis data survei SPSS",
        coffeeTitle: "Traktir Kopi",
        coffeeScanText: "DONASI DI SINI ➔",
        rateTitle: "Beri 5 Bintang",
        rateSub: "Dukung ekstensi",
        
        outsideCheckHeading: "Unduh PDF",
        outsideCheckSub: "Buka Studocu, Scribd, atau SlideShare",
        outsideClearHeading: "Buka Kunci Dokumen",
        outsideClearSub: "Buka Studocu, Scribd, atau SlideShare",
        
        studocuCheckHeading: "Unduh PDF",
        studocuCheckSub: "Tata letak otomatis untuk cetak",
        studocuClearHeading: "Lihat File & Hapus Watermark",
        studocuClearSub: "Lewati batasan dokumen",
        
        scribdCheckHeading: "Unduh PDF Scribd",
        scribdCheckSub: "Buka kunci & unduh otomatis",
        scribdClearHeading: "Buka Kunci & Hapus Banner",
        scribdClearSub: "Buka kunci konten bacaan online",
        
        slideshareCheckHeading: "Unduh PDF SlideShare",
        slideshareCheckSub: "PDF lanskap otomatis",
        slideshareClearHeading: "Hapus Iklan",
        slideshareClearSub: "Optimalkan tampilan online"
    },
    pt: {
        mainTitle: "DocuBami",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Nota:</strong> Role até o final para carregar todo o documento antes de baixar e evitar páginas em branco.</span>',
        supportTitle: "Acesso Rápido & Links",
        studocuTitle: "Studocu.com",
        studocuSub: "Visitar site",
        scribdSub: "Visitar site",
        slideshareSub: "Visitar site",
        vpnTitle: "Baixar 1.1.1.1",
        vpnSub: "Contornar bloqueios",
        vpnGuide: "💡 <strong>Correção:</strong> A instalação do <strong>1.1.1.1 (WARP)</strong> ajuda a contornar bloqueios de rede e acessar o Studocu sem problemas.",
        serviceTitle: "Serviços SPSS & Análise",
        serviceSub: "Processamento e análise de dados SPSS",
        coffeeTitle: "Pague-me um café",
        coffeeScanText: "DOAR AQUI ➔",
        rateTitle: "Avaliar 5 Estrelas",
        rateSub: "Apoiar extensão",
        
        outsideCheckHeading: "Baixar PDF",
        outsideCheckSub: "Abra Studocu, Scribd ou SlideShare",
        outsideClearHeading: "Desbloquear Documento",
        outsideClearSub: "Abra Studocu, Scribd ou SlideShare",
        
        studocuCheckHeading: "Baixar PDF",
        studocuCheckSub: "Layout automático para impressão",
        studocuClearHeading: "Ver Arquivo & Remover Marca d'água",
        studocuClearSub: "Contornar limites do documento",
        
        scribdCheckHeading: "Baixar PDF Scribd",
        scribdCheckSub: "Auto desbloqueio & download",
        scribdClearHeading: "Desbloquear & Remover Banners",
        scribdClearSub: "Desbloquear leitura online",
        
        slideshareCheckHeading: "Baixar PDF SlideShare",
        slideshareCheckSub: "Auto PDF horizontal",
        slideshareClearHeading: "Remover Anúncios",
        slideshareClearSub: "Otimizar interface online"
    },
    fr: {
        mainTitle: "DocuBami",
        tipText: '<svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span class="warning-text"><strong>Remarque :</strong> Faites défiler jusqu\'en bas pour charger tout le document avant de télécharger et éviter les pages blanches.</span>',
        supportTitle: "Accès Rapide & Liens",
        studocuTitle: "Studocu.com",
        studocuSub: "Visiter le site",
        scribdSub: "Visiter le site",
        slideshareSub: "Visiter le site",
        vpnTitle: "Télécharger 1.1.1.1",
        vpnSub: "Contourner les blocages",
        vpnGuide: "💡 <strong>Astuce :</strong> L'installation de <strong>1.1.1.1 (WARP)</strong> aide à contourner les blocages réseau et à accéder à Studocu sans problème.",
        serviceTitle: "Services SPSS & Analyse",
        serviceSub: "Enquêtes SPSS, traitement et analyse de données statistiques",
        coffeeTitle: "M'offrir un café",
        coffeeScanText: "FAIRE UN DON ICI ➔",
        rateTitle: "Noter 5 étoiles",
        rateSub: "Soutenir l'extension",
        
        outsideCheckHeading: "Télécharger le PDF",
        outsideCheckSub: "Ouvrez Studocu, Scribd ou SlideShare",
        outsideClearHeading: "Débloquer le Document",
        outsideClearSub: "Ouvrez Studocu, Scribd ou SlideShare",
        
        studocuCheckHeading: "Télécharger le PDF",
        studocuCheckSub: "Mise en page automatique pour l'impression",
        studocuClearHeading: "Voir le fichier & Retirer filigrane",
        studocuClearSub: "Contourner les limites du document",
        
        scribdCheckHeading: "Télécharger le PDF Scribd",
        scribdCheckSub: "Déblocage et téléchargement auto",
        scribdClearHeading: "Débloquer & Masquer bannières",
        scribdClearSub: "Déflouter la lecture en ligne",
        
        slideshareCheckHeading: "Télécharger le PDF SlideShare",
        slideshareCheckSub: "PDF paysage automatique",
        slideshareClearHeading: "Supprimer les publicités",
        slideshareClearSub: "Optimiser l'interface en ligne"
    }
};

const LANG_SEQUENCE = ['vi', 'en', 'fr', 'es', 'id', 'pt'];
let currentLang = localStorage.getItem('banhmi_lang') || 'vi';

function applyLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('banhmi_lang', lang);
    
    const t = TRANSLATIONS[lang];
    if (!t) return;
    
    const mainTitle = document.getElementById('mainTitle');
    if (mainTitle) mainTitle.innerText = t.mainTitle;
    
    const tipText = document.getElementById('tipText');
    if (tipText) tipText.innerHTML = t.tipText;
    
    const supportTitle = document.getElementById('supportTitle');
    if (supportTitle) supportTitle.innerText = t.supportTitle;
    
    const studocuSub = document.getElementById('studocuSub');
    if (studocuSub) studocuSub.innerText = t.studocuSub;
    
    const studocuBtn = document.getElementById('studocuBtn');
    if (studocuBtn) {
        const heading = studocuBtn.querySelector('.support-btn-heading');
        if (heading) heading.innerText = t.studocuTitle;
    }
    
    const scribdSub = document.getElementById('scribdSub');
    if (scribdSub) scribdSub.innerText = t.scribdSub;
    
    const slideshareSub = document.getElementById('slideshareSub');
    if (slideshareSub) slideshareSub.innerText = t.slideshareSub;
    
    const vpnTitle = document.getElementById('vpnTitle');
    if (vpnTitle) vpnTitle.innerText = t.vpnTitle;
    
    const vpnSub = document.getElementById('vpnSub');
    if (vpnSub) vpnSub.innerText = t.vpnSub;
    
    const vpnGuide = document.getElementById('vpnGuide');
    if (vpnGuide) vpnGuide.innerHTML = t.vpnGuide;
    
    const serviceTitle = document.getElementById('serviceTitle');
    if (serviceTitle) serviceTitle.innerText = t.serviceTitle;
    
    const serviceSub = document.getElementById('serviceSub');
    if (serviceSub) serviceSub.innerText = t.serviceSub;
    
    const coffeeTitle = document.getElementById('coffeeTitle');
    if (coffeeTitle) coffeeTitle.innerText = t.coffeeTitle;
    
    const coffeeScanText = document.getElementById('coffeeScanText');
    if (coffeeScanText) coffeeScanText.innerText = t.coffeeScanText;

    const rateLabel = document.getElementById('rateLabel');
    if (rateLabel) rateLabel.innerText = t.rateTitle;

    // Modal content has been moved to be rendered on demand inside the click listener to improve startup performance

    const langFlag = document.getElementById('langFlag');
    const langText = document.getElementById('langText');
    if (langFlag && langText) {
        if (lang === 'vi') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="30" height="20" fill="#da251d"/><polygon points="15,4 16.17,7.62 20,7.62 16.9,9.88 18.08,13.5 15,11.25 11.92,13.5 13.1,9.88 10,7.62 13.83,7.62" fill="#ffff00"/></svg>`;
            langText.innerText = "VI";
        } else if (lang === 'en') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="30" height="20" fill="#fff"/><rect width="30" height="1.54" y="0" fill="#b22234"/><rect width="30" height="1.54" y="3.08" fill="#b22234"/><rect width="30" height="1.54" y="6.16" fill="#b22234"/><rect width="30" height="1.54" y="9.24" fill="#b22234"/><rect width="30" height="1.54" y="12.32" fill="#b22234"/><rect width="30" height="1.54" y="15.4" fill="#b22234"/><rect width="30" height="1.54" y="18.46" fill="#b22234"/><rect width="12" height="10.8" fill="#3c3b6e"/><circle cx="2" cy="2" r="0.5" fill="#fff"/><circle cx="4" cy="2" r="0.5" fill="#fff"/><circle cx="6" cy="2" r="0.5" fill="#fff"/><circle cx="8" cy="2" r="0.5" fill="#fff"/><circle cx="10" cy="2" r="0.5" fill="#fff"/><circle cx="3" cy="4" r="0.5" fill="#fff"/><circle cx="5" cy="4" r="0.5" fill="#fff"/><circle cx="7" cy="4" r="0.5" fill="#fff"/><circle cx="9" cy="4" r="0.5" fill="#fff"/><circle cx="2" cy="6" r="0.5" fill="#fff"/><circle cx="4" cy="6" r="0.5" fill="#fff"/><circle cx="6" cy="6" r="0.5" fill="#fff"/><circle cx="8" cy="6" r="0.5" fill="#fff"/><circle cx="10" cy="6" r="0.5" fill="#fff"/><circle cx="3" cy="8" r="0.5" fill="#fff"/><circle cx="5" cy="8" r="0.5" fill="#fff"/><circle cx="7" cy="8" r="0.5" fill="#fff"/><circle cx="9" cy="8" r="0.5" fill="#fff"/></svg>`;
            langText.innerText = "EN";
        } else if (lang === 'fr') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="10" height="20" fill="#002654"/><rect width="10" height="20" x="10" fill="#fff"/><rect width="10" height="20" x="20" fill="#ed2939"/></svg>`;
            langText.innerText = "FR";
        } else if (lang === 'es') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="30" height="20" fill="#c60b1e"/><rect width="30" height="10" y="5" fill="#ffc400"/><rect width="2.5" height="4" x="6" y="8" fill="#c60b1e" rx="0.5"/><circle cx="7.25" cy="7" r="1" fill="#ffff00"/></svg>`;
            langText.innerText = "ES";
        } else if (lang === 'id') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="30" height="20" fill="#fff"/><rect width="30" height="10" fill="#e21c21"/></svg>`;
            langText.innerText = "ID";
        } else if (lang === 'pt') {
            langFlag.innerHTML = `<svg class="flag-icon" viewBox="0 0 30 20" width="16" height="11"><rect width="30" height="20" fill="#de1219"/><rect width="12" height="20" fill="#00662f"/><circle cx="12" cy="10" r="3.5" fill="#ffd700"/><rect width="2" height="2.5" x="11" y="8.75" fill="#de1219"/></svg>`;
            langText.innerText = "PT";
        }
    }
    
    updateDynamicTexts();
}

function updateDynamicTexts() {
    const tab = activeTab;
    if (tab) {
        const url = tab.url || "";
        const checkBtn = document.getElementById('checkBtn');
        const clearBtn = document.getElementById('clearBtn');
        if (!checkBtn || !clearBtn) return;
        
        const t = TRANSLATIONS[currentLang];
        if (!t) return;
        
        if (url.includes("scribd.com")) {
            checkBtn.querySelector('.btn-heading').innerText = t.scribdCheckHeading;
            checkBtn.querySelector('.btn-sub').innerText = t.scribdCheckSub;
            clearBtn.querySelector('.btn-heading').innerText = t.scribdClearHeading;
            clearBtn.querySelector('.btn-sub').innerText = t.scribdClearSub;
        } else if (url.includes("studocu")) {
            checkBtn.querySelector('.btn-heading').innerText = t.studocuCheckHeading;
            checkBtn.querySelector('.btn-sub').innerText = t.studocuCheckSub;
            clearBtn.querySelector('.btn-heading').innerText = t.studocuClearHeading;
            clearBtn.querySelector('.btn-sub').innerText = t.studocuClearSub;
        } else if (url.includes("slideshare.net")) {
            checkBtn.querySelector('.btn-heading').innerText = t.slideshareCheckHeading;
            checkBtn.querySelector('.btn-sub').innerText = t.slideshareCheckSub;
            clearBtn.querySelector('.btn-heading').innerText = t.slideshareClearHeading;
            clearBtn.querySelector('.btn-sub').innerText = t.slideshareClearSub;
        } else {
            checkBtn.querySelector('.btn-heading').innerText = t.outsideCheckHeading;
            checkBtn.querySelector('.btn-sub').innerText = t.outsideCheckSub;
            clearBtn.querySelector('.btn-heading').innerText = t.outsideClearHeading;
            clearBtn.querySelector('.btn-sub').innerText = t.outsideClearSub;
        }
    }
}

// Helper to get donate modal HTML content based on language
function getDonateModalHTML(lang) {
    if (lang === 'vi') {
        return `
            <div style="font-family: sans-serif; text-align: center;">
              <h3 style="margin: 0 0 6px 0; font-size: 15px; color: var(--bami-orange);">Mời Tôi Một Ly Cà Phê ☕</h3>
              <img src="https://img.vietqr.io/image/hdbank-291704070007289-compact.png" alt="VietQR HDBank" style="max-width: 185px; width: 185px; height: auto; border-radius: 6px; margin: 0 auto 6px auto; display: block;">
              <div style="background: var(--bami-light); border: 1px dashed #fad1a6; border-radius: 8px; padding: 7px 10px; margin-top: 6px; font-size: 11px; line-height: 1.5; text-align: left;">
                <div>Ngân hàng: <strong style="color: var(--bami-dark);">HDBank</strong></div>
                <div>Số tài khoản: <strong style="font-family: monospace; font-size: 13.5px; color: var(--bami-orange); letter-spacing: 0.5px; user-select: all;">291704070007289</strong></div>
                <div>Chủ tài khoản: <strong style="color: var(--bami-dark);">NGUYỄN NGỌC CHIẾN</strong></div>
              </div>
            </div>
        `;
    }
    
    const donateDetails = {
        es: { 
            title: "Apoyar a DocuBami ☕", 
            desc: "Si DocuBami te resulta útil, considera apoyar su desarrollo y mantenimiento continuo a través de PayPal. ¡Cada café cuenta!", 
            paypalBtn: "Donar con PayPal",
            thanks: "¡Muchas gracias por tu apoyo! ❤️"
        },
        id: { 
            title: "Dukung DocuBami ☕", 
            desc: "Jika DocuBami bermanfaat bagi Anda, silakan dukung pengembangan dan pemeliharaannya melalui PayPal. Terima kasih!", 
            paypalBtn: "Donasi via PayPal",
            thanks: "Terima kasih banyak atas dukungan Anda! ❤️"
        },
        pt: { 
            title: "Apoiar o DocuBami ☕", 
            desc: "Se o DocuBami é útil para você, considere apoiar seu desenvolvimento e manutenção contínua através do PayPal. Todo café ajuda!", 
            paypalBtn: "Doar via PayPal",
            thanks: "Muito obrigado pelo seu apoio! ❤️"
        },
        fr: { 
            title: "Soutenir DocuBami ☕", 
            desc: "Si DocuBami vous est utile, vous pouvez soutenir son développement et sa maintenance via PayPal. Chaque café compte !", 
            paypalBtn: "Faire un don via PayPal",
            thanks: "Merci beaucoup pour votre soutien ! ❤️"
        },
        en: { 
            title: "Support DocuBami ☕", 
            desc: "If you find DocuBami helpful, please consider supporting its development and maintenance via PayPal. Every coffee helps!", 
            paypalBtn: "Donate via PayPal",
            thanks: "Thank you for your generous support! ❤️"
        }
    };
    
    const content = donateDetails[lang] || donateDetails.en;
    
    return `
        <div style="font-family: sans-serif; padding: 8px 4px; max-width: 260px; text-align: center;">
          <h3 style="margin: 0 0 8px 0; font-size: 16px; color: var(--bami-orange); font-weight: 700;">${content.title}</h3>
          <p style="font-size: 11.5px; line-height: 1.5; color: var(--bami-dark); margin: 0 0 16px 0;">
            ${content.desc}
          </p>
          <a href="https://www.paypal.me/bamicampha" target="_blank" style="display: inline-flex; align-items: center; justify-content: center; gap: 8px; width: 100%; box-sizing: border-box; background: #0070ba; color: white; padding: 10px 14px; border-radius: 8px; font-size: 13px; font-weight: bold; text-decoration: none; box-shadow: 0 3px 8px rgba(0,112,186,0.3);">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M7.076 21.337H2.47a.641.641 0 0 1-.633-.74L4.944.901C5.026.382 5.474 0 5.998 0h7.46c2.57 0 4.578.543 5.69 1.81 1.01 1.15 1.304 2.42 1.012 4.287-.023.143-.047.288-.077.437-.983 5.05-4.349 6.797-8.647 6.797h-2.19l-1.42 7.558a.64.64 0 0 1-.63.518l-.12-.07z"/><path fill="#003087" d="M18.89 6.438c-.023.143-.047.288-.077.437-.983 5.05-4.349 6.797-8.647 6.797h-2.19l-1.42 7.558a.64.64 0 0 1-.63.518H2.47a.641.641 0 0 1-.633-.74L4.944.901C5.026.382 5.474 0 5.998 0h7.46c2.57 0 4.578.543 5.69 1.81 1.01 1.15 1.304 2.42 1.012 4.287z" opacity=".2"/><path fill="#0079C1" d="M9.166 13.672l1.096-5.833h3.087c2.329 0 4.145.492 5.15 1.639.914 1.042 1.18 2.192.915 3.882-.89 4.573-3.937 6.155-7.828 6.155h-1.983l-.437 2.328z"/></svg>
            <span>${content.paypalBtn}</span>
          </a>
          <div style="margin-top: 14px; font-size: 11px; color: var(--text-muted); font-weight: 500;">
            ${content.thanks}
          </div>
        </div>
    `;
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    // 1. Bind event listeners immediately (interactivity has zero delay)
    initEventListeners();
    
    // 2. Apply saved language immediately if not Vietnamese
    if (currentLang !== 'vi') {
        applyLanguage(currentLang);
    }
    
    // 3. Update dynamic texts as soon as the tab query resolves
    activeTabPromise.then(() => {
        updateDynamicTexts();
    });
});