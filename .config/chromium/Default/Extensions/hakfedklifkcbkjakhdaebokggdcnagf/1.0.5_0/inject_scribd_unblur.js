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
        alert("⚠️ Không tìm thấy trang tài liệu nào để mở khóa.");
        return;
    }

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

    pages.forEach(cleanPage);

    const globalPromos = [
        '.premium_member_only_experience',
        '.scribd_premium_banner',
        '.doc_paywall',
        '.commercial_promo',
        '.container_with_promo',
        '.blur_container',
        '[class*="paywall"]',
        '[class*="premium-banner"]'
    ];
    globalPromos.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => {
            if (el.classList.contains('container_with_promo') || el.classList.contains('blur_container')) {
                el.classList.remove('container_with_promo', 'blur_container');
            } else {
                el.remove();
            }
        });
    });

    alert("🎉 Đã unblur mở khóa các trang hiện tại! Cuộn chuột để xem tiếp các trang khác.");
})();
