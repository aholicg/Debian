(function() {
    const selectorsToRemove = [
        '.sidebar',
        '#related-slideshows',
        '.ad-banner',
        '.global-ad-slot',
        '.ad-container',
        '.advertisement',
        '[class*="premium-promo"]',
        '[class*="paywall"]',
        'iframe[src*="ad"]',
        'div[class*="ad-"]',
        'div[id*="ad-"]'
    ];
    selectorsToRemove.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => el.remove());
    });
    
    document.querySelectorAll('.blur, .blurred').forEach(el => {
        el.classList.remove('blur', 'blurred');
    });
    
    alert("🎉 Đã dọn sạch quảng cáo và tối ưu giao diện xem online SlideShare!");
})();
