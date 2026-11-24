/* ShellBags explorer helpers: server-rendered fragments only. */
(function () {
  "use strict";

  function copy(path, button) {
    if (!path || !navigator.clipboard) return;
    navigator.clipboard.writeText(path).then(function () {
      var previous = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(function () { button.textContent = previous; }, 1500);
    }, function () {});
  }

  document.addEventListener("click", function (event) {
    var copyBtn = event.target.closest("[data-shellbag-copy-path]");
    if (copyBtn) {
      event.preventDefault();
      copy(copyBtn.getAttribute("data-shellbag-copy-path"), copyBtn);
      return;
    }
    var registry = event.target.closest("[data-shellbag-open-registry]");
    if (registry) {
      // Activate the Registry tab so the swapped key panel is not visually
      // attributed to the ShellBags tab.
      var list = document.querySelector("[data-tablist]");
      var tab = document.getElementById("tab-registry");
      if (list && tab) {
        list.querySelectorAll('[role="tab"]').forEach(function (item) {
          var active = item === tab;
          item.setAttribute("aria-selected", active ? "true" : "false");
          item.classList.toggle("active", active);
          item.tabIndex = active ? 0 : -1;
        });
        var panel = document.getElementById("tab-content");
        if (panel) panel.setAttribute("aria-labelledby", "tab-registry");
      }
    }
  });

  /* Clear a stale detail panel when the tree/search replaces its own view. */
  document.addEventListener("htmx:beforeSwap", function (event) {
    var target = event.detail && event.detail.target;
    if (!target) return;
    if (target.id === "shellbags-tree" || target.id === "shellbags-results") {
      var detail = document.getElementById("shellbags-detail");
      if (detail) {
        detail.textContent = "";
        var placeholder = document.createElement("div");
        placeholder.className = "tree-placeholder";
        var heading = document.createElement("h3");
        heading.textContent = "Shellbag detail";
        var note = document.createElement("p");
        note.className = "muted small-note";
        note.textContent = "Choose a folder or device to see its registry source.";
        placeholder.appendChild(heading);
        placeholder.appendChild(note);
        detail.appendChild(placeholder);
      }
    }
  });

  /* Enter submits the ShellBags search exactly once. */
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Enter") return;
    var input = event.target.closest("[data-shellbags-search] input");
    if (!input) return;
    var form = input.closest("[data-shellbags-search]");
    if (!form) return;
    event.preventDefault();
    form.requestSubmit ? form.requestSubmit() : form.submit();
  }, true);
})();
