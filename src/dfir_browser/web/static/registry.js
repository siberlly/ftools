/* Lazy registry key tree. Server-rendered panels are escaped by Jinja; node
 * labels are inserted with textContent only. */
(function () {
  "use strict";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function integer(value) {
    var n = Number(value);
    return Number.isInteger(n) && n > 0 ? n : null;
  }

  function RegistryTree(root) {
    this.root = root;
    this.hiveId = root.getAttribute("data-hive-id");
    this.rootKeyId = integer(root.getAttribute("data-root-key-id"));
    this.tree = root.querySelector("[data-registry-tree]");
    this.detail = root.querySelector("#registry-detail");
    this.scroll = root.querySelector("[data-registry-scroll]");
    this.breadcrumb = root.querySelector("[data-registry-breadcrumb]");
    this.filterInput = root.querySelector("[data-registry-filter]");
    this.cache = new Map();
    this.pending = new Map();
    this.selectedId = null;
    this.filterText = "";
    this.bind();
    this.loadChildren(this.rootKeyId);
  }

  RegistryTree.prototype.bind = function () {
    var self = this;
    this.root.querySelectorAll("[data-registry-action]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var action = btn.getAttribute("data-registry-action");
        if (action === "collapse") self.collapseAll();
        if (action === "root") self.selectNode(self.rootKeyId, { scroll: true });
      });
    });
    if (this.filterInput) {
      this.filterInput.addEventListener("input", function () {
        self.filterText = self.filterInput.value.trim().toLowerCase();
        self.applyFilter();
      });
    }
    this.tree.addEventListener("mousedown", function (event) {
      if (event.target.closest("[data-registry-row]")) event.preventDefault();
    });
    this.tree.addEventListener("keydown", function (event) {
      var item = event.target.closest('[role="treeitem"]');
      if (item) self.onKeydown(event, item);
    });
    this.bindSplitter();
    this.registerNode(this.nodeById(this.rootKeyId));
    document.addEventListener("click", function (event) {
      var target = event.target.closest
        ? event.target.closest("[data-registry-reveal]")
        : null;
      if (!target) return;
      event.preventDefault();
      self.revealKey(integer(target.getAttribute("data-registry-reveal")));
    });
  };

  RegistryTree.prototype.bindSplitter = function () {
    var split = this.root.querySelector(".registry-split");
    var resizer = this.root.querySelector("[data-registry-resizer]");
    if (!split || !resizer) return;
    var dragging = false;
    function setWidth(px) {
      var max = Math.max(260, split.clientWidth - 280);
      split.style.setProperty(
        "--tree-width",
        Math.max(220, Math.min(px, max)) + "px"
      );
    }
    resizer.addEventListener("pointerdown", function (event) {
      dragging = true;
      if (resizer.setPointerCapture) resizer.setPointerCapture(event.pointerId);
      document.body.classList.add("tree-resizing");
      event.preventDefault();
    });
    window.addEventListener("pointermove", function (event) {
      if (!dragging) return;
      var rect = split.getBoundingClientRect();
      setWidth(event.clientX - rect.left);
    });
    window.addEventListener("pointerup", function () {
      dragging = false;
      document.body.classList.remove("tree-resizing");
    });
  };

  RegistryTree.prototype.nodeById = function (id) {
    var result = null;
    this.tree.querySelectorAll("[data-key-id]").forEach(function (node) {
      if (node.getAttribute("data-key-id") === String(id)) result = node;
    });
    return result;
  };

  RegistryTree.prototype.registerNode = function (node) {
    if (!node || node.dataset.bound === "1") return;
    node.dataset.bound = "1";
    var self = this;
    var row = node.querySelector("[data-registry-row]");
    var chevron = node.querySelector("[data-registry-chevron]");
    if (chevron) {
      chevron.addEventListener("click", function (event) {
        event.stopPropagation();
        self.toggle(node);
      });
    }
    if (row) {
      row.addEventListener("click", function (event) {
        if (event.target.closest("[data-registry-chevron]")) return;
        var id = integer(node.getAttribute("data-key-id"));
        if (id !== null) self.selectNode(id, { scroll: false });
      });
      row.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          var id = integer(node.getAttribute("data-key-id"));
          if (id !== null) self.selectNode(id, { scroll: false });
        }
      });
    }
  };

  RegistryTree.prototype.setExpanded = function (node, expanded) {
    if (!node) return;
    var group = node.querySelector("[data-registry-group]");
    var chevron = node.querySelector("[data-registry-chevron]");
    node.setAttribute("aria-expanded", expanded ? "true" : "false");
    if (group) group.hidden = !expanded;
    if (chevron) {
      var name = node.querySelector("[data-registry-name]");
      chevron.setAttribute(
        "aria-label",
        (expanded ? "Collapse " : "Expand ") +
          (name ? name.textContent : "key")
      );
      var glyph = chevron.querySelector(".chevron-glyph");
      if (glyph) glyph.textContent = expanded ? "\u25BE" : "\u25B8";
    }
  };

  RegistryTree.prototype.toggle = function (node) {
    var expanded = node.getAttribute("aria-expanded") === "true";
    if (expanded) {
      this.setExpanded(node, false);
    } else {
      this.setExpanded(node, true);
      this.loadChildren(integer(node.getAttribute("data-key-id")));
    }
  };

  RegistryTree.prototype.loadChildren = function (keyId, page, append) {
    if (!keyId) return Promise.resolve(null);
    page = page || 1;
    var cacheKey = keyId + ":" + page;
    if (this.cache.has(cacheKey) && !append) {
      this.renderChildren(keyId, this.cache.get(cacheKey));
      return Promise.resolve(this.cache.get(cacheKey));
    }
    if (this.pending.has(cacheKey)) return this.pending.get(cacheKey);
    var node = this.nodeById(keyId);
    if (!node) return Promise.resolve(null);
    var group = node.querySelector("[data-registry-group]");
    var self = this;
    if (group && page === 1) {
      group.setAttribute("aria-busy", "true");
      group.textContent = "";
      group.appendChild(el("div", "tree-loading", "Loading keys…"));
    }
    var url =
      "/registry/hives/" + this.hiveId + "/keys?parent_key_id=" + keyId +
      "&page=" + page + "&page_size=100";
    var promise = fetch(url, { headers: { Accept: "application/json" } })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data.ok) {
            throw new Error((data.error && data.error.message) || "load failed");
          }
          return data;
        });
      })
      .then(function (data) {
        self.cache.set(cacheKey, data);
        self.renderChildren(keyId, data, append);
        return data;
      })
      .catch(function (err) {
        if (group) {
          group.removeAttribute("aria-busy");
          group.textContent = "";
          var box = el("div", "tree-error");
          box.setAttribute("role", "alert");
          box.appendChild(el("strong", null, "Could not load registry keys."));
          box.appendChild(el("p", null, err.message));
          var retry = el("button", "tree-btn", "Retry");
          retry.type = "button";
          retry.addEventListener("click", function () {
            self.pending.delete(cacheKey);
            self.loadChildren(keyId, page, append);
          });
          box.appendChild(retry);
          group.appendChild(box);
        }
        return null;
      })
      .finally(function () {
        self.pending.delete(cacheKey);
      });
    this.pending.set(cacheKey, promise);
    return promise;
  };

  RegistryTree.prototype.renderChildren = function (keyId, data, append) {
    var node = this.nodeById(keyId);
    if (!node) return;
    var group = node.querySelector("[data-registry-group]");
    if (!group) return;
    group.removeAttribute("aria-busy");
    var more = group.querySelector("[data-registry-more]");
    if (more) more.remove();
    if (!append) group.textContent = "";
    var parentLevel = Number(node.getAttribute("aria-level") || 1);
    (data.items || []).forEach(function (item) {
      if (group.querySelector('[data-key-id="' + item.key_id + '"]')) return;
      group.appendChild(this.buildNode(item, parentLevel + 1));
    }, this);
    var loaded = group.querySelectorAll(":scope > [data-key-id]").length;
    if (data.total > loaded) {
      var button = el(
        "button",
        "tree-load-more",
        "Load more (" + (data.total - loaded) + " remaining)"
      );
      button.type = "button";
      button.setAttribute("data-registry-more", String(keyId));
      button.addEventListener("click", function () {
        button.disabled = true;
        this.loadChildren(keyId, Math.floor(loaded / 100) + 1, true);
      }.bind(this));
      group.appendChild(button);
    }
    if (!(data.items || []).length) {
      group.appendChild(el("div", "tree-empty", "No subkeys"));
    }
    this.applyFilter();
  };

  RegistryTree.prototype.buildNode = function (item, level) {
    var node = el("div", "tree-node");
    node.setAttribute("role", "treeitem");
    node.setAttribute("data-key-id", String(item.key_id));
    node.setAttribute("data-key-path", item.key_path);
    node.setAttribute("data-has-children", item.has_children ? "1" : "0");
    node.setAttribute("aria-level", String(level));
    node.setAttribute("aria-selected", "false");
    node.setAttribute("aria-expanded", "false");
    node.setAttribute(
      "aria-label",
      item.name + " registry key, " + item.value_count + " values"
    );
    var row = el("div", "tree-row");
    row.setAttribute("data-registry-row", "");
    row.tabIndex = -1;
    var chevron = el("button", "tree-chevron");
    chevron.type = "button";
    chevron.setAttribute("data-registry-chevron", "");
    chevron.tabIndex = -1;
    if (item.has_children) {
      chevron.setAttribute("aria-label", "Expand " + item.name);
      var glyph = el("span", "chevron-glyph");
      glyph.setAttribute("aria-hidden", "true");
      glyph.textContent = "\u25B8";
      chevron.appendChild(glyph);
    } else {
      chevron.classList.add("tree-chevron-spacer");
      chevron.disabled = true;
      chevron.setAttribute("aria-hidden", "true");
    }
    row.appendChild(chevron);
    var icon = el("span", "tree-icon", "\uD83D\uDD11");
    icon.setAttribute("aria-hidden", "true");
    row.appendChild(icon);
    var name = el("button", "tree-name", item.name);
    name.type = "button";
    name.setAttribute("data-registry-name", "");
    name.title = item.key_path + "\nValues: " + item.value_count;
    row.appendChild(name);
    var badges = el("span", "tree-badges");
    badges.appendChild(el("span", "badge kind", item.value_count + " val"));
    row.appendChild(badges);
    node.appendChild(row);
    var group = el("div", "tree-group");
    group.setAttribute("role", "group");
    group.setAttribute("data-registry-group", "");
    group.hidden = true;
    node.appendChild(group);
    this.registerNode(node);
    return node;
  };

  RegistryTree.prototype.selectNode = function (keyId, options) {
    options = options || {};
    var node = this.nodeById(keyId);
    if (!node) return;
    this.tree.querySelectorAll('[aria-selected="true"]').forEach(function (item) {
      item.setAttribute("aria-selected", "false");
      item.classList.remove("selected");
    });
    node.setAttribute("aria-selected", "true");
    node.classList.add("selected");
    this.selectedId = keyId;
    this.updateBreadcrumb(node);
    if (options.scroll) {
      var row = node.querySelector("[data-registry-row]");
      if (row && this.scroll) {
        var rr = row.getBoundingClientRect();
        var sr = this.scroll.getBoundingClientRect();
        if (rr.top < sr.top) this.scroll.scrollTop -= sr.top - rr.top + 6;
        else if (rr.bottom > sr.bottom) this.scroll.scrollTop += rr.bottom - sr.bottom + 6;
      }
    }
    var row = node.querySelector("[data-registry-row]");
    if (row) row.focus({ preventScroll: true });
    this.loadKey(keyId);
  };

  RegistryTree.prototype.updateBreadcrumb = function (node) {
    if (!this.breadcrumb) return;
    var chain = [];
    var current = node;
    while (current && current !== this.tree) {
      if (current.getAttribute && current.getAttribute("data-key-id")) {
        chain.unshift(current);
      }
      current = current.parentElement;
    }
    this.breadcrumb.textContent = "";
    chain.forEach(function (item, index) {
      if (index > 0) this.breadcrumb.appendChild(el("span", "sep", "\\"));
      var nameEl = item.querySelector("[data-registry-name]");
      var label = nameEl ? nameEl.textContent : "(key)";
      if (index === chain.length - 1) {
        this.breadcrumb.appendChild(el("span", "current", label));
      } else {
        var id = integer(item.getAttribute("data-key-id"));
        var button = el("button", "link", label);
        button.type = "button";
        var self = this;
        button.addEventListener("click", function () {
          self.selectNode(id, { scroll: true });
        });
        this.breadcrumb.appendChild(button);
      }
    }, this);
  };

  RegistryTree.prototype.loadKey = function (keyId) {
    if (!this.detail) return;
    var self = this;
    this.detail.textContent = "";
    var placeholder = el("div", "tree-placeholder");
    placeholder.appendChild(el("p", "muted", "Loading key values…"));
    this.detail.appendChild(placeholder);
    fetch(
      "/registry/hives/" + this.hiveId + "/key/" + keyId + "?preview=64",
      { headers: { Accept: "text/html" } }
    )
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.text();
      })
      .then(function (html) {
        self.detail.innerHTML = "";
        var template = document.createElement("template");
        template.innerHTML = html;
        self.detail.appendChild(template.content);
        if (window.htmx && typeof window.htmx.process === "function") {
          window.htmx.process(self.detail);
        }
      })
      .catch(function (err) {
        self.detail.textContent = "";
        var box = el("div", "tree-error");
        box.setAttribute("role", "alert");
        box.textContent = "Could not load key values: " + err.message;
        self.detail.appendChild(box);
      });
  };

  RegistryTree.prototype.revealKey = function (keyId) {
    if (!keyId) return;
    var self = this;
    fetch(
      "/registry/hives/" + this.hiveId + "/reveal?key_id=" + keyId,
      { headers: { Accept: "application/json" } }
    )
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data.ok) {
            throw new Error((data.error && data.error.message) || "reveal failed");
          }
          return data;
        });
      })
      .then(function (data) {
        var chain = Promise.resolve();
        (data.ancestors || []).forEach(function (ancestor) {
          chain = chain.then(function () {
            return self.openNode(ancestor.key_id);
          });
        });
        return chain.then(function () {
          return self.openNode(keyId);
        }).then(function () {
          self.selectNode(keyId, { scroll: true });
        });
      })
      .catch(function (err) {
        self.detail.textContent = "Could not reveal key: " + err.message;
      });
  };

  RegistryTree.prototype.openNode = function (keyId) {
    var node = this.nodeById(keyId);
    if (!node) return Promise.resolve();
    this.setExpanded(node, true);
    return this.loadChildren(keyId);
  };

  RegistryTree.prototype.collapseAll = function () {
    this.tree.querySelectorAll('[role="treeitem"]').forEach(function (node) {
      if (node.getAttribute("data-key-id") === String(this.rootKeyId)) return;
      this.setExpanded(node, false);
    }, this);
    this.selectNode(this.rootKeyId, { scroll: true });
  };

  RegistryTree.prototype.applyFilter = function () {
    var filter = this.filterText;
    var nodes = this.tree.querySelectorAll("[data-key-id]");
    nodes.forEach(function (node) {
      if (node.getAttribute("data-key-id") === String(this.rootKeyId)) return;
      var nameEl = node.querySelector("[data-registry-name]");
      var name = nameEl ? nameEl.textContent.toLowerCase() : "";
      var path = (node.getAttribute("data-key-path") || "").toLowerCase();
      var match = !filter || name.indexOf(filter) !== -1 || path.indexOf(filter) !== -1;
      node.classList.toggle("tree-filtered-out", !match && !!filter);
    }, this);
  };

  RegistryTree.prototype.visibleNodes = function () {
    var result = [];
    this.tree.querySelectorAll('[role="treeitem"]').forEach(function (node) {
      if (node.classList.contains("tree-filtered-out")) return;
      var current = node;
      var visible = true;
      while (current && current !== this.tree) {
        if (current.hidden) {
          visible = false;
          break;
        }
        current = current.parentElement;
      }
      if (visible) result.push(node);
    }, this);
    return result;
  };

  RegistryTree.prototype.onKeydown = function (event, item) {
    var nodes = this.visibleNodes();
    var index = nodes.indexOf(item);
    var id = integer(item.getAttribute("data-key-id"));
    var expanded = item.getAttribute("aria-expanded") === "true";
    switch (event.key) {
      case "ArrowDown":
        if (index >= 0 && index + 1 < nodes.length) this.focusNode(nodes[index + 1]);
        event.preventDefault();
        break;
      case "ArrowUp":
        if (index > 0) this.focusNode(nodes[index - 1]);
        event.preventDefault();
        break;
      case "ArrowRight":
        if (!expanded) this.openNode(id);
        else if (index >= 0 && index + 1 < nodes.length) {
          this.focusNode(nodes[index + 1]);
        }
        event.preventDefault();
        break;
      case "ArrowLeft":
        if (expanded) {
          this.setExpanded(item, false);
        } else {
          var parent = item.parentElement
            ? item.parentElement.closest("[data-key-id]")
            : null;
          if (parent) this.focusNode(parent);
        }
        event.preventDefault();
        break;
      case "Home":
        if (nodes.length) this.focusNode(nodes[0]);
        event.preventDefault();
        break;
      case "End":
        if (nodes.length) this.focusNode(nodes[nodes.length - 1]);
        event.preventDefault();
        break;
      case "Enter":
        if (id !== null) this.selectNode(id, { scroll: false });
        event.preventDefault();
        break;
      case " ":
        if (id !== null) this.selectNode(id, { scroll: false });
        event.preventDefault();
        break;
      default:
        break;
    }
  };

  RegistryTree.prototype.focusNode = function (node) {
    if (!node) return;
    var row = node.querySelector("[data-registry-row]");
    if (row) row.focus({ preventScroll: true });
  };

  function boot() {
    document.querySelectorAll(".registry-explorer").forEach(function (root) {
      if (root.dataset.registryBooted === "1") return;
      root.dataset.registryBooted = "1";
      root.__registryTree = new RegistryTree(root);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
  document.addEventListener("htmx:afterSwap", boot);
  document.addEventListener("htmx:afterSettle", boot);
})();
