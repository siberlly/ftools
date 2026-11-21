/* Form ergonomics: Enter submits the active filter/search form exactly once. */
(function () {
  "use strict";

  var lastSubmit = new WeakMap();

  function submitForm(form) {
    var now = Date.now();
    var previous = lastSubmit.get(form) || 0;
    if (now - previous < 500) return;
    lastSubmit.set(form, now);
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else if (form.dispatchEvent) {
      form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
    }
  }

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Enter" || event.isComposing) return;
    var target = event.target;
    if (!target || !target.closest) return;
    if (target.tagName === "TEXTAREA" || target.tagName === "BUTTON") return;
    if (target.type === "checkbox" || target.type === "radio") return;
    var form = target.closest("form[data-search-form]");
    if (!form) return;
    event.preventDefault();
    submitForm(form);
  });

  // A submit that starts while another is still in flight is ignored, which
  // avoids duplicate HTMX requests from repeated Enter presses.
  document.addEventListener("htmx:beforeRequest", function (event) {
    var form = event.target && event.target.closest
      ? event.target.closest("form[data-search-form]")
      : null;
    if (!form) return;
    var submit = form.querySelector("[data-search-submit]");
    if (submit) submit.setAttribute("aria-busy", "true");
  });
  document.addEventListener("htmx:afterRequest", function (event) {
    var form = event.target && event.target.closest
      ? event.target.closest("form[data-search-form]")
      : null;
    if (!form) return;
    var submit = form.querySelector("[data-search-submit]");
    if (submit) submit.removeAttribute("aria-busy");
  });
})();
