/* Pass a fresh EMPEDIAcaptcha proof to the WooCommerce Checkout block's Store API request. */
(function () {
    'use strict';

    var pending = false;
    var resuming = false;

    document.addEventListener('click', function (event) {
        var button = event.target.closest && event.target.closest('.wc-block-components-checkout-place-order-button');
        if (!button) { return; }
        var widget = document.querySelector('.wc-block-checkout .empedia-captcha');
        if (!widget) { return; }

        if (resuming) { return; }
        event.preventDefault();
        event.stopImmediatePropagation();
        if (pending || button.disabled) { return; }

        pending = true;
        if (!window.EmpediaCaptcha || !window.wp || !window.wp.data) { pending = false; return; }
        window.EmpediaCaptcha.reset(widget);
        window.EmpediaCaptcha.execute(widget).then(function (token) {
            window.wp.data.dispatch('wc/store/checkout').setExtensionData('empedia-shield', { token: token });
            pending = false;
            resuming = true;
            try { button.click(); } finally { resuming = false; }
        }, function () { pending = false; });
    }, true);
})();
