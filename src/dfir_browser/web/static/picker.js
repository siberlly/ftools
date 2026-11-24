/* Evidence file picker: server-rendered listings, no client paths. */
(function () {
  "use strict";

  function dialog() {
    return document.querySelector("[data-picker-dialog]");
  }

  function content() {
    return document.getElementById("picker-content");
  }

  function load(url) {
    var box = content();
    if (!box) return;
    box.textContent = "";
    var note = document.createElement("p");
    note.className = "muted small-note";
    note.textContent = "Loading folders…";
    box.appendChild(note);
    fetch(url, { headers: { Accept: "text/html" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.text();
      })
      .then(function (html) {
        var template = document.createElement("template");
        template.innerHTML = html;
        box.textContent = "";
        box.appendChild(template.content);
      })
      .catch(function (err) {
        box.textContent = "";
        var box2 = document.createElement("p");
        box2.className = "badge deleted";
        box2.textContent = "Could not load folders: " + err.message;
        box.appendChild(box2);
      });
  }

  function open() {
    var root = dialog();
    if (!root) return;
    if (typeof root.showModal === "function") root.showModal();
    else root.setAttribute("open", "open");
    load("/picker");
  }

  function close() {
    var root = dialog();
    if (!root) return;
    if (typeof root.close === "function") root.close();
    else root.removeAttribute("open");
  }

  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-picker-open]")) {
      event.preventDefault();
      open();
      return;
    }
    if (event.target.closest("[data-picker-close]")) {
      event.preventDefault();
      close();
      return;
    }
    var nav = event.target.closest("[data-picker-go]");
    if (nav) {
      event.preventDefault();
      var path = nav.getAttribute("data-picker-go") || "";
      load("/picker" + (path ? "?path=" + encodeURIComponent(path) : ""));
      return;
    }
    var file = event.target.closest("[data-picker-file]");
    if (file) {
      event.preventDefault();
      var input = document.getElementById("path");
      if (input) {
        input.value = file.getAttribute("data-picker-file") || "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
      }
      close();
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    var root = dialog();
    if (root && root.hasAttribute("open")) close();
  });
})();
