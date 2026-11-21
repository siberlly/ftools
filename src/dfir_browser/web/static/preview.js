/* Read-only file preview: rendering, search, clipboard and registry hand-off.
 *
 * Evidence content is already server-escaped inside <pre>. This file never
 * assigns evidence text to innerHTML; highlights are built with text nodes and
 * <mark> elements only.
 */
(function () {
  "use strict";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function cardOf(node) {
    return node.closest("[data-preview-card]");
  }

  function slotOf(card) {
    return card ? card.querySelector("[data-preview-slot]") : null;
  }

  function loadPreview(card, opts) {
    var slot = slotOf(card);
    if (!slot) return;
    var evidence = card.getAttribute("data-preview-evidence");
    var entry = card.getAttribute("data-preview-entry");
    var fallbackLimit = card.getAttribute("data-preview-default-limit") || "";
    var mode = (opts && opts.mode) || "auto";
    var offset = (opts && opts.offset) || 0;
    var limit = (opts && opts.limit) || fallbackLimit;
    var params = new URLSearchParams();
    params.set("offset", String(offset));
    params.set("mode", mode);
    if (limit) params.set("limit", String(limit));
    var url =
      "/evidence/" +
      encodeURIComponent(evidence) +
      "/entries/" +
      encodeURIComponent(entry) +
      "/preview/panel?" +
      params.toString();

    slot.textContent = "";
    slot.appendChild(el("p", "muted small-note", "Loading preview…"));
    slot.setAttribute("aria-busy", "true");
    fetch(url, { headers: { Accept: "text/html" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.text();
      })
      .then(function (html) {
        var template = document.createElement("template");
        template.innerHTML = html;
        slot.textContent = "";
        slot.appendChild(template.content);
        slot.removeAttribute("aria-busy");
        if (window.htmx && typeof window.htmx.process === "function") {
          window.htmx.process(slot);
        }
        var pre = slot.querySelector("[data-preview-content]");
        if (pre) pre.setAttribute("data-preview-ready", "1");
      })
      .catch(function (err) {
        slot.removeAttribute("aria-busy");
        slot.textContent = "";
        var box = el("div", "alert error");
        box.appendChild(el("strong", null, "Preview failed. "));
        box.appendChild(el("span", null, err.message));
        slot.appendChild(box);
      });
  }

  /* --- content search (safe: text nodes plus <mark> only) ------------- */
  function highlight(content, query) {
    if (!content.__pvOriginal && content.__pvOriginal !== "") {
      content.__pvOriginal = content.textContent || "";
    }
    var original = content.__pvOriginal;
    content.textContent = "";
    if (!query) {
      content.textContent = original;
      return 0;
    }
    var lower = original.toLowerCase();
    var needle = query.toLowerCase();
    var index = 0;
    var count = 0;
    var fragment = document.createDocumentFragment();
    while (true) {
      var hit = lower.indexOf(needle, index);
      if (hit < 0) {
        fragment.appendChild(document.createTextNode(original.slice(index)));
        break;
      }
      if (hit > index) {
        fragment.appendChild(
          document.createTextNode(original.slice(index, hit))
        );
      }
      var mark = document.createElement("mark");
      mark.textContent = original.slice(hit, hit + needle.length);
      fragment.appendChild(mark);
      count += 1;
      index = hit + needle.length;
      if (count >= 5000) {
        fragment.appendChild(document.createTextNode(original.slice(index)));
        break;
      }
    }
    content.appendChild(fragment);
    return count;
  }

  function copyText(text, button) {
    if (!text) return;
    var done = function () {
      if (!button) return;
      var previous = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(function () {
        button.textContent = previous;
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    }
  }

  /* --- main tab activation for registry hand-off ---------------------- */
  function activateMainTab(tabId) {
    var list = document.querySelector("[data-tablist]");
    if (!list) return;
    var tabs = Array.prototype.slice.call(
      list.querySelectorAll('[role="tab"]')
    );
    var target = document.getElementById(tabId);
    if (!target) return;
    tabs.forEach(function (tab) {
      var active = tab === target;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.classList.toggle("active", active);
      tab.tabIndex = active ? 0 : -1;
    });
    var panel = document.getElementById("tab-content");
    if (panel) {
      panel.setAttribute("aria-labelledby", tabId);
      panel.setAttribute("data-active-tab", tabId);
    }
  }

  function swapPanel(url) {
    if (!window.htmx || typeof window.htmx.ajax !== "function") {
      window.location.href = url;
      return;
    }
    window.htmx.ajax("GET", url, {
      target: "#tab-content",
      swap: "innerHTML",
    });
  }

  document.addEventListener("click", function (event) {
    var load = event.target.closest("[data-preview-load]");
    if (load) {
      event.preventDefault();
      var card = cardOf(load);
      loadPreview(card, {
        mode: load.getAttribute("data-preview-mode") || "auto",
        limit: load.getAttribute("data-preview-limit") || null,
        offset: 0,
      });
      return;
    }

    var goto = event.target.closest("[data-preview-goto]");
    if (goto) {
      event.preventDefault();
      var wrap = goto.closest("[data-preview-card]");
      loadPreview(wrap, {
        mode: goto.getAttribute("data-preview-mode") || "auto",
        offset: goto.getAttribute("data-preview-goto") || 0,
      });
      return;
    }

    var toggle = event.target.closest("[data-preview-toggle]");
    if (toggle) {
      event.preventDefault();
      var body = document.getElementById(
        toggle.getAttribute("aria-controls")
      );
      if (!body) return;
      var collapsed = body.hasAttribute("hidden");
      if (collapsed) {
        body.removeAttribute("hidden");
        toggle.textContent = "Collapse";
        toggle.setAttribute("aria-expanded", "true");
      } else {
        body.setAttribute("hidden", "");
        toggle.textContent = "Expand";
        toggle.setAttribute("aria-expanded", "false");
      }
      return;
    }

    var copyAll = event.target.closest("[data-preview-copy-all]");
    if (copyAll) {
      event.preventDefault();
      var panel = copyAll.closest(".preview-wrap");
      var pre = panel ? panel.querySelector("[data-preview-content]") : null;
      if (pre) copyText(pre.textContent || "", copyAll);
      return;
    }

    var copySel = event.target.closest("[data-preview-copy-selection]");
    if (copySel) {
      event.preventDefault();
      var selection = window.getSelection
        ? String(window.getSelection())
        : "";
      copyText(selection, copySel);
      return;
    }

    var openHive = event.target.closest("[data-open-registry-hive]");
    if (openHive) {
      event.preventDefault();
      var hiveId = openHive.getAttribute("data-open-registry-hive");
      activateMainTab("tab-registry");
      swapPanel("/registry/hives/" + encodeURIComponent(hiveId));
      return;
    }

    var openTab = event.target.closest("[data-open-registry-tab]");
    if (openTab) {
      event.preventDefault();
      var evidence = openTab.getAttribute("data-open-registry-tab");
      var entry = openTab.getAttribute("data-registry-entry") || "";
      activateMainTab("tab-registry");
      swapPanel(
        "/evidence/" +
          encodeURIComponent(evidence) +
          "/registry?highlight=" +
          encodeURIComponent(entry)
      );
      return;
    }
  });

  document.addEventListener("input", function (event) {
    var input = event.target.closest("[data-preview-search]");
    if (!input) return;
    var panel = input.closest(".preview-wrap");
    if (!panel) return;
    var content = panel.querySelector("[data-preview-content]");
    if (!content) return;
    var count = highlight(content, input.value.trim());
    var counter = panel.querySelector("[data-preview-match-count]");
    if (counter) {
      counter.textContent = input.value.trim()
        ? count + " match(es)"
        : "";
    }
  });

  /* Keep the Registry tab visually in sync with registry panel loads. */
  document.addEventListener("htmx:beforeRequest", function (event) {
    var detail = event.detail || {};
    var target = detail.target;
    var request = detail.requestConfig || detail.elt;
    var url = "";
    if (detail.requestConfig && detail.requestConfig.path) {
      url = detail.requestConfig.path;
    } else if (detail.pathInfo && detail.pathInfo.requestPath) {
      url = detail.pathInfo.requestPath;
    }
    if (!target || target.id !== "tab-content" || !url) return;
    if (/^\/registry\/hives\//.test(url) || /\/registry(\?|$)/.test(url)) {
      activateMainTab("tab-registry");
    }
  });

  document.addEventListener("htmx:afterSwap", function (event) {
    var target = event.detail && event.detail.target;
    if (!target || target.id !== "tab-content") return;
    var row = document.getElementById("registry-focus-row");
    if (row && typeof row.scrollIntoView === "function") {
      row.scrollIntoView({ block: "center" });
    }
  });

  /* Clear stale preview content when the selected entry changes. */
  document.addEventListener("htmx:beforeSwap", function (event) {
    var target = event.detail && event.detail.target;
    if (!target) return;
    if (target.id === "tree-detail" || target.id === "detail") {
      target.querySelectorAll("[data-preview-slot]").forEach(function (slot) {
        slot.textContent = "";
      });
    }
  });
})();
