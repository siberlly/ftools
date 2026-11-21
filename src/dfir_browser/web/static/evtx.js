/* Event Log explorer helpers: server-rendered fragments only, no evidence HTML. */
(function () {
  "use strict";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function explorer() {
    return document.querySelector(".evtx-explorer");
  }

  function detailRegion() {
    return document.getElementById("evtx-detail");
  }

  function resultsRegion() {
    return document.getElementById("evtx-results");
  }

  function loadInto(container, url) {
    if (!container) return;
    container.textContent = "";
    container.appendChild(el("p", "muted", "Loading…"));
    fetch(url, { headers: { Accept: "text/html" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.text();
      })
      .then(function (html) {
        container.innerHTML = "";
        var template = document.createElement("template");
        template.innerHTML = html;
        container.appendChild(template.content);
        if (window.htmx && typeof window.htmx.process === "function") {
          window.htmx.process(container);
        }
      })
      .catch(function (err) {
        container.textContent = "Could not load this view: " + err.message;
      });
  }

  function currentLog() {
    var root = explorer();
    return root ? root.getAttribute("data-log-id") : null;
  }

  /* Clear detail whenever the log changes or results are replaced. */
  function clearDetail(message) {
    var region = detailRegion();
    if (!region) return;
    region.textContent = "";
    var placeholder = el("div", "tree-placeholder");
    placeholder.appendChild(el("h3", null, "Event detail"));
    placeholder.appendChild(
      el("p", "muted small-note", message || "Choose an event to see its detail.")
    );
    region.appendChild(placeholder);
    region.setAttribute("data-record-id", "");
  }

  function handleDetailClick(event) {
    var target = event.target.closest ? event.target.closest("[data-evtx-detail], [data-evtx-raw], [data-evtx-context]") : null;
    if (!target) return;
    var logId = currentLog();
    if (!logId) return;
    event.preventDefault();
    var recordId = target.getAttribute("data-evtx-detail") ||
      target.getAttribute("data-evtx-raw") ||
      target.getAttribute("data-evtx-context");
    var region = detailRegion();
    if (!region) return;
    if (target.hasAttribute("data-evtx-context")) {
      var wrapper = el("div", "evtx-context-wrapper");
      loadInto(wrapper, "/event-logs/" + logId + "/events/" + recordId + "/context");
      region.textContent = "";
      region.appendChild(wrapper);
      region.setAttribute("data-record-id", recordId);
      return;
    }
    var url = "/event-logs/" + logId + "/events/" + recordId;
    if (target.hasAttribute("data-evtx-raw")) url += "?raw=1";
    loadInto(region, url);
    region.setAttribute("data-record-id", recordId);
  }

  function handleSearchClick(event) {
    var target = event.target.closest ? event.target.closest("[data-evtx-find]") : null;
    if (!target) return;
    var hint = target.getAttribute("data-evtx-find") || "";
    event.preventDefault();
    if (!hint) {
      window.alert("This event has no clear executable or path field.");
      return;
    }
    var searchTab = document.getElementById("tab-tree");
    var searchInput = document.querySelector(
      '#tab-content input[name="q"], #tab-content .search-form input[name="q"]'
    );
    if (searchTab && !document.querySelector("#tab-content .search-form")) {
      // Fall back to the global search tab when the explorer has no search box.
      var tab = document.getElementById("tab-search");
      if (tab) tab.click();
      window.setTimeout(function () {
        var input = document.querySelector('.search-form input[name="q"]');
        if (input) {
          input.value = hint;
          input.focus();
        }
      }, 400);
      void searchInput;
      return;
    }
    if (searchInput) {
      searchInput.value = hint;
      searchInput.focus();
    }
    void searchTab;
  }

  function handlePagination(event) {
    var target = event.target.closest ? event.target.closest("[data-evtx-page]") : null;
    if (!target) return;
    var form = document.querySelector(".evtx-filter-form");
    if (!form) return;
    event.preventDefault();
    var params = new URLSearchParams(new FormData(form));
    params.set("page", target.getAttribute("data-evtx-page"));
    var action = form.getAttribute("hx-get") || form.getAttribute("action");
    loadInto(resultsRegion(), action + "?" + params.toString());
    clearDetail("Page changed; choose an event again.");
    var region = resultsRegion();
    if (region) region.scrollIntoView({ block: "nearest" });
  }

  function updateFromResults() {
    var region = resultsRegion();
    if (!region) return;
    var logId = currentLog();
    if (region.getAttribute("data-log-id") !== logId) {
      region.setAttribute("data-log-id", logId || "");
      clearDetail("Choose an event to see its detail.");
    }
  }

  document.addEventListener("click", function (event) {
    handleDetailClick(event);
    handleSearchClick(event);
    handlePagination(event);
  });

  document.addEventListener("htmx:afterSwap", function (event) {
    var target = event.target;
    if (!target) return;
    if (target.id === "evtx-results" || (target.closest && target.closest(".evtx-explorer"))) {
      if (target.id !== "evtx-detail") {
        clearDetail("Results updated; choose an event.");
      }
      updateFromResults();
    }
  });

  document.addEventListener("htmx:beforeRequest", function (event) {
    var form = event.target && event.target.closest
      ? event.target.closest("form.evtx-filter-form")
      : null;
    if (!form) return;
    clearDetail("Query running…");
  });

  function boot() {
    var root = explorer();
    if (!root || root.dataset.evtxBooted === "1") return;
    root.dataset.evtxBooted = "1";
    var results = resultsRegion();
    if (results && !results.getAttribute("data-log-id")) {
      results.setAttribute("data-log-id", root.getAttribute("data-log-id") || "");
    }
    clearDetail("Choose an event to see its detail.");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
  document.addEventListener("htmx:afterSettle", boot);
})();
