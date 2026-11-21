/* Browser artifact helpers: server-rendered fragments only, no evidence HTML. */
(function () {
  "use strict";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function explorer() {
    return document.querySelector("[data-browser-explorer]");
  }

  function recordsRegion() {
    return document.getElementById("browser-records");
  }

  function detailRegion() {
    return document.getElementById("browser-detail");
  }

  function clearDetail(message) {
    var region = detailRegion();
    if (!region) return;
    region.textContent = "";
    var placeholder = el("div", "tree-placeholder");
    placeholder.appendChild(el("h3", null, "Record detail"));
    placeholder.appendChild(
      el(
        "p",
        "muted small-note",
        message || "Choose a record to see its structured fields."
      )
    );
    region.appendChild(placeholder);
  }

  function loadHtml(container, url, fallback) {
    if (!container) return;
    var holder = el("p", "muted", "Loading…");
    container.textContent = "";
    container.appendChild(holder);
    fetch(url, { headers: { Accept: "text/html" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.text();
      })
      .then(function (html) {
        var template = document.createElement("template");
        template.innerHTML = html;
        container.textContent = "";
        container.appendChild(template.content);
        if (window.htmx && typeof window.htmx.process === "function") {
          window.htmx.process(container);
        }
      })
      .catch(function (err) {
        container.textContent = "";
        container.appendChild(
          el("p", "muted", (fallback || "Could not load this view") + ": " + err.message)
        );
      });
  }

  var VIEWS = {
    downloads: "/browser/downloads",
    history: "/browser/history",
    cache: "/browser/cache",
    profiles: "/browser/profiles",
    search: "/browser/search",
  };

  function stripInitialLoad(panel) {
    if (!panel || panel.getAttribute("data-load-consumed") === "1") return;
    panel.removeAttribute("hx-get");
    panel.removeAttribute("hx-trigger");
    panel.setAttribute("data-load-consumed", "1");
  }

  function openView(name) {
    var root = explorer();
    var region = recordsRegion();
    if (!root || !region) return;
    stripInitialLoad(region);
    var evidenceId = root.getAttribute("data-evidence-id");
    var artifactId = root.getAttribute("data-artifact-id");
    var path = VIEWS[name];
    if (!path) return;
    var url = "/evidence/" + encodeURIComponent(evidenceId) + path;
    if (name !== "profiles") {
      url += "?artifact_id=" + encodeURIComponent(artifactId);
    }
    var panel = document.getElementById("browser-records");
    if (panel) {
      panel.setAttribute("aria-labelledby", "btab-" + name);
    }
    clearDetail();
    loadHtml(region, url, "Could not load " + name);
  }

  function activateTab(target) {
    var list = target.closest("[data-browser-tablist]");
    if (!list) return;
    list.querySelectorAll("[data-browser-tab]").forEach(function (tab) {
      var active = tab === target;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
    });
  }

  document.addEventListener("click", function (event) {
    var tab = event.target.closest("[data-browser-tab]");
    if (tab) {
      event.preventDefault();
      activateTab(tab);
      openView(tab.getAttribute("data-browser-tab"));
      return;
    }

    var record = event.target.closest("[data-browser-record]");
    if (record) {
      event.preventDefault();
      var kind = record.getAttribute("data-browser-record");
      var id = record.getAttribute("data-browser-id");
      var region = detailRegion();
      if (region) {
        region.setAttribute("data-current", kind + ":" + id);
      }
      loadHtml(
        region,
        "/browser/records/" + encodeURIComponent(kind) + "/" + encodeURIComponent(id),
        "Could not load record"
      );
      return;
    }

    var copy = event.target.closest("[data-copy-value]");
    if (copy) {
      event.preventDefault();
      var block = copy.closest("dd");
      var code = block ? block.querySelector("code") : null;
      if (code && navigator.clipboard) {
        navigator.clipboard.writeText(code.textContent || "").then(
          function () {
            copy.textContent = "Copied";
            window.setTimeout(function () {
              copy.textContent = "Copy";
            }, 1500);
          },
          function () {}
        );
      }
      return;
    }
  });

  document.addEventListener("keydown", function (event) {
    var tab = event.target.closest("[data-browser-tab]");
    if (!tab) return;
    var list = tab.closest("[data-browser-tablist]");
    if (!list) return;
    var tabs = Array.prototype.slice.call(
      list.querySelectorAll("[data-browser-tab]")
    );
    var index = tabs.indexOf(tab);
    var next = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      next = tabs[(index + 1) % tabs.length];
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      next = tabs[(index - 1 + tabs.length) % tabs.length];
    } else if (event.key === "Home") {
      next = tabs[0];
    } else if (event.key === "End") {
      next = tabs[tabs.length - 1];
    }
    if (next) {
      event.preventDefault();
      next.focus();
      activateTab(next);
      openView(next.getAttribute("data-browser-tab"));
    }
  });

  /* Enter submits the server-rendered filter forms exactly once. */
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Enter") return;
    var input = event.target.closest("[data-browser-filter] input");
    if (!input) return;
    var form = input.closest("[data-browser-filter]");
    if (!form) return;
    event.preventDefault();
    form.requestSubmit ? form.requestSubmit() : form.submit();
  }, true);
})();
