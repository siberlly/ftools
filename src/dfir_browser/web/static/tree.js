/* Lazy, accessible evidence filesystem tree.
 * Values are inserted with textContent; only server-rendered, Jinja-escaped
 * panels use innerHTML. Evidence strings are never parsed as HTML. */
(function () {
  "use strict";

  var STATE_PREFIX = "dfir.tree.v2.";
  var PAGE_SIZE_MAX = 500;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function statusOf(obj) {
    if (obj.deleted) return "deleted";
    if (obj.allocated) return "allocated";
    return "unallocated";
  }

  function makeIcon(kind) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    var path = document.createElementNS(ns, "path");
    if (kind === "volume") {
      path.setAttribute("d", "M1.5 3.5h13v5h-13zM3.5 10h9v3h-9z");
    } else if (kind === "directory") {
      path.setAttribute("d", "M1.5 3.5h5l1.2 1.6h6.8v7.4H1.5z");
    } else {
      path.setAttribute("d", "M3 1.5h7l3 3v10H3zM10 1.5v3.2h3");
    }
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1.3");
    svg.appendChild(path);
    return svg;
  }

  function parseInteger(value) {
    var n = Number(value);
    return Number.isInteger(n) && n >= 0 ? n : null;
  }

  function Tree(root) {
    this.root = root;
    this.evidenceId = root.getAttribute("data-evidence-id");
    this.tree = root.querySelector('[role="tree"]');
    this.detail = root.querySelector("#tree-detail");
    this.breadcrumb = root.querySelector("[data-tree-breadcrumb]");
    this.filterInput = root.querySelector("[data-tree-filter]");
    this.includeDeleted = root.getAttribute("data-include-deleted") === "1";
    this.directoriesOnly =
      root.getAttribute("data-directories-only") === "1";
    this.selectedId = null;
    this.filterText = "";
    this.openIds = new Set([0]);
    this.cache = new Map();
    this.pending = new Map();
    this.stateKey = STATE_PREFIX + this.evidenceId;
    this.restoreState();
    this.bind();
    var initial = parseInteger(root.getAttribute("data-selected-id"));
    var self = this;
    this.loadChildren(0).then(function () {
      if (initial) {
        return self.revealEntry(initial).then(function () {
          return self.restoreOpenNodes();
        }).then(function () {
          self.restoreSelection();
        });
      }
      return self.restoreOpenNodes().then(function () {
        self.restoreSelection();
      });
    });
  }

  Tree.prototype.storage = function () {
    try {
      return window.sessionStorage;
    } catch (err) {
      return null;
    }
  };

  Tree.prototype.alive = function () {
    return !!(this.root && this.root.isConnected);
  };

  Tree.prototype.saveState = function () {
    if (!this.alive()) return;
    var store = this.storage();
    if (!store) return;
    try {
      store.setItem(
        this.stateKey,
        JSON.stringify({
          open: Array.from(this.openIds),
          selected: this.selectedId,
          includeDeleted: this.includeDeleted,
          directoriesOnly: this.directoriesOnly,
        })
      );
    } catch (err) {
      /* storage unavailable */
    }
    var url = new URL(window.location.href);
    if (this.selectedId !== null && this.selectedId !== undefined && this.selectedId > 0) {
      url.searchParams.set("entry", String(this.selectedId));
    } else {
      url.searchParams.delete("entry");
    }
    if (this.includeDeleted) url.searchParams.delete("include_deleted");
    else url.searchParams.set("include_deleted", "0");
    if (this.directoriesOnly) url.searchParams.set("directories_only", "1");
    else url.searchParams.delete("directories_only");
    try {
      window.history.replaceState({}, "", url.toString());
    } catch (err) {
      /* ignore */
    }
  };

  Tree.prototype.restoreState = function () {
    var store = this.storage();
    if (!store) return;
    var raw = null;
    try {
      raw = store.getItem(this.stateKey);
    } catch (err) {
      return;
    }
    if (!raw) return;
    try {
      var data = JSON.parse(raw);
      if (typeof data.includeDeleted === "boolean") {
        this.includeDeleted = data.includeDeleted;
        var toggle = this.root.querySelector(
          '[data-tree-toggle="include-deleted"]'
        );
        if (toggle) toggle.checked = this.includeDeleted;
      }
      if (typeof data.directoriesOnly === "boolean") {
        this.directoriesOnly = data.directoriesOnly;
        var dirToggle = this.root.querySelector(
          '[data-tree-toggle="directories-only"]'
        );
        if (dirToggle) dirToggle.checked = this.directoriesOnly;
      }
      if (Array.isArray(data.open)) {
        data.open.forEach((id) => {
          if (Number.isInteger(id) && id > 0) this.openIds.add(id);
        });
      }
      if (Number.isInteger(data.selected) && data.selected >= 0) {
        this.selectedId = data.selected;
      }
    } catch (err) {
      /* ignore corrupt state */
    }
  };

  Tree.prototype.bind = function () {
    var self = this;
    this.root.querySelectorAll("[data-tree-action]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var action = btn.getAttribute("data-tree-action");
        if (action === "collapse-all") self.collapseAll();
        else if (action === "root") self.goToRoot();
        else if (action === "toggle-sidebar") self.toggleSidebar(btn);
      });
    });
    if (this.filterInput) {
      this.filterInput.addEventListener("input", function () {
        self.filterText = self.filterInput.value.trim().toLowerCase();
        self.applyFilter();
      });
    }
    this.root.querySelectorAll("[data-tree-toggle]").forEach(function (input) {
      input.addEventListener("change", function () {
        var which = input.getAttribute("data-tree-toggle");
        if (which === "include-deleted") self.includeDeleted = input.checked;
        else if (which === "directories-only") {
          self.directoriesOnly = input.checked;
        }
        self.reloadTree();
      });
    });
    this.bindSplitter();
    this.bindKeyboard();
    this.registerNode(this.nodeById(0));
  };

  Tree.prototype.toggleSidebar = function (button) {
    var pane = this.root.querySelector("#tree-pane");
    if (!pane) return;
    var hidden = pane.classList.toggle("tree-pane-hidden");
    button.setAttribute("aria-expanded", hidden ? "false" : "true");
  };

  Tree.prototype.bindSplitter = function () {
    var split = this.root.querySelector("[data-tree-split]");
    var resizer = this.root.querySelector("[data-tree-resizer]");
    if (!split || !resizer) return;
    function setWidth(px) {
      var max = Math.max(260, split.clientWidth - 280);
      var value = Math.max(220, Math.min(px, max));
      split.style.setProperty("--tree-width", value + "px");
    }
    var dragging = false;
    resizer.addEventListener("pointerdown", function (event) {
      dragging = true;
      if (resizer.setPointerCapture) {
        resizer.setPointerCapture(event.pointerId);
      }
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
    resizer.addEventListener("keydown", function (event) {
      var current =
        parseInt(split.style.getPropertyValue("--tree-width"), 10) || 300;
      if (event.key === "ArrowLeft") {
        setWidth(current - 20);
        event.preventDefault();
      } else if (event.key === "ArrowRight") {
        setWidth(current + 20);
        event.preventDefault();
      }
    });
  };

  Tree.prototype.bindKeyboard = function () {
    var self = this;
    // Prevent the browser from focusing (and page-scrolling to) the inner
    // name/chevron buttons. Focus is moved to the tree row with preventScroll.
    this.tree.addEventListener("mousedown", function (event) {
      if (event.target.closest("[data-tree-row]")) {
        event.preventDefault();
      }
    });
    this.tree.addEventListener("keydown", function (event) {
      var item = event.target.closest('[role="treeitem"]');
      if (!item) return;
      self.onKeydown(event, item);
    });
  };

  Tree.prototype.nodeById = function (id) {
    var target = String(id);
    var nodes = this.tree.querySelectorAll("[data-entry-id]");
    for (var i = 0; i < nodes.length; i += 1) {
      if (nodes[i].getAttribute("data-entry-id") === target) return nodes[i];
    }
    return null;
  };

  Tree.prototype.rowOf = function (node) {
    return node ? node.querySelector("[data-tree-row]") : null;
  };

  Tree.prototype.focusNode = function (node) {
    var row = this.rowOf(node);
    if (row) row.focus({ preventScroll: true });
  };

  Tree.prototype.registerNode = function (node) {
    if (!node || node.dataset.bound === "1") return;
    node.dataset.bound = "1";
    var self = this;
    var row = node.querySelector("[data-tree-row]");
    var chevron = node.querySelector("[data-tree-chevron]");
    if (chevron && !chevron.disabled) {
      chevron.addEventListener("click", function (event) {
        event.stopPropagation();
        self.toggleNode(node);
      });
    }
    if (row) {
      row.addEventListener("click", function (event) {
        if (event.target.closest("[data-tree-chevron]")) return;
        var id = parseInteger(node.getAttribute("data-entry-id"));
        if (id === null) return;
        self.selectNode(id, { scroll: false, panel: true });
      });
      row.addEventListener("dblclick", function (event) {
        if (event.target.closest("[data-tree-chevron]")) return;
        if (node.getAttribute("data-entry-type") === "directory") {
          self.toggleNode(node);
        }
      });
      row.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          var id = parseInteger(node.getAttribute("data-entry-id"));
          if (id === null) return;
          self.selectNode(id, { scroll: false, panel: true });
          if (event.key === "Enter" &&
              node.getAttribute("data-entry-type") === "directory") {
            self.toggleNode(node);
          }
        }
      });
    }
  };

  Tree.prototype.setExpanded = function (node, expanded) {
    if (!node || node.getAttribute("data-entry-type") !== "directory") return;
    var group = node.querySelector("[data-tree-group]");
    var chevron = node.querySelector("[data-tree-chevron]");
    var name = node.querySelector("[data-tree-name]");
    node.setAttribute("aria-expanded", expanded ? "true" : "false");
    if (group) group.hidden = !expanded;
    if (chevron) {
      chevron.setAttribute(
        "aria-label",
        (expanded ? "Collapse " : "Expand ") +
          (name ? name.textContent : "directory")
      );
      var glyph = chevron.querySelector(".chevron-glyph");
      if (glyph) glyph.textContent = expanded ? "\u25BE" : "\u25B8";
    }
    var id = parseInteger(node.getAttribute("data-entry-id"));
    if (id === null) return;
    if (expanded) this.openIds.add(id);
    else this.openIds.delete(id);
  };

  Tree.prototype.toggleNode = function (node) {
    var id = parseInteger(node.getAttribute("data-entry-id"));
    if (id === null) return;
    if (node.getAttribute("aria-expanded") === "true") {
      this.setExpanded(node, false);
      this.saveState();
      return;
    }
    this.openNode(id);
  };

  Tree.prototype.openNode = function (id) {
    var node = this.nodeById(id);
    if (!node) return Promise.resolve();
    this.setExpanded(node, true);
    this.saveState();
    return this.loadChildren(id);
  };

  Tree.prototype.reloadTree = function () {
    this.cache.clear();
    this.pending.clear();
    this.tree.querySelectorAll('[data-entry-id]:not([data-entry-id="0"])').forEach(function (node) {
      node.remove();
    });
    var root = this.nodeById(0);
    var group = root ? root.querySelector("[data-tree-group]") : null;
    if (group) {
      group.textContent = "";
      group.hidden = false;
    }
    if (root) root.setAttribute("aria-expanded", "true");
    this.openIds = new Set([0]);
    this.saveState();
    var self = this;
    this.loadChildren(0).then(function () {
      return self.restoreOpenNodes();
    }).then(function () {
      self.restoreSelection();
    });
  };

  Tree.prototype.collapseAll = function () {
    this.tree.querySelectorAll('[role="treeitem"]').forEach((node) => {
      if (node.getAttribute("data-entry-id") === "0") return;
      this.setExpanded(node, false);
    });
    this.openIds = new Set([0]);
    this.saveState();
    this.focusNode(this.nodeById(0));
  };

  Tree.prototype.goToRoot = function () {
    var self = this;
    this.openNode(0).then(function () {
      self.selectNode(0, { scroll: true, panel: true });
    });
  };

  Tree.prototype.childrenUrl = function (id, page, pageSize) {
    var params = new URLSearchParams();
    params.set("parent_id", String(id));
    params.set("include_deleted", this.includeDeleted ? "1" : "0");
    params.set("directories_only", this.directoriesOnly ? "1" : "0");
    params.set("page", String(page || 1));
    params.set("page_size", String(pageSize || 100));
    return (
      "/evidence/" + this.evidenceId + "/tree/children?" + params.toString()
    );
  };

  Tree.prototype.fetchChildren = function (id, page, pageSize) {
    var url = this.childrenUrl(id, page, pageSize);
    return fetch(url, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data.ok) {
          throw new Error(
            (data.error && data.error.message) || "HTTP " + response.status
          );
        }
        return data;
      });
    });
  };

  Tree.prototype.loadChildren = function (id, options) {
    if (!this.alive()) return Promise.resolve(null);
    options = options || {};
    var page = options.page || 1;
    var pageSize = options.pageSize || 100;
    var key = id + ":" + page;
    if (this.cache.has(key) && !options.force) {
      this.renderChildren(id, this.cache.get(key), options);
      return Promise.resolve(this.cache.get(key));
    }
    if (this.pending.has(key)) return this.pending.get(key);
    var node = this.nodeById(id);
    if (!node) return Promise.resolve(null);
    var group = node.querySelector("[data-tree-group]");
    var self = this;
    if (group && page === 1) {
      group.setAttribute("aria-busy", "true");
      group.textContent = "";
      group.appendChild(el("div", "tree-loading", "Loading children…"));
    }
    var promise = this.fetchChildren(id, page, pageSize)
      .then(function (data) {
        self.cache.set(key, data);
        self.renderChildren(id, data, options);
        return data;
      })
      .catch(function (err) {
        if (group) {
          group.removeAttribute("aria-busy");
          group.textContent = "";
          var box = el("div", "tree-error");
          box.setAttribute("role", "alert");
          box.appendChild(el("strong", null, "Could not load children."));
          box.appendChild(el("p", null, err.message));
          var retry = el("button", "tree-btn", "Retry");
          retry.type = "button";
          retry.addEventListener("click", function () {
            self.pending.delete(key);
            self.loadChildren(id, { force: true });
          });
          box.appendChild(retry);
          group.appendChild(box);
        }
        return null;
      })
      .finally(function () {
        self.pending.delete(key);
      });
    this.pending.set(key, promise);
    return promise;
  };

  Tree.prototype.renderChildren = function (id, data, options) {
    if (!this.alive()) return;
    var node = this.nodeById(id);
    if (!node) return;
    var group = node.querySelector("[data-tree-group]");
    if (!group) return;
    group.removeAttribute("aria-busy");
    if (!(options && options.append)) group.textContent = "";
    var existingMore = group.querySelector("[data-tree-more]");
    if (existingMore) existingMore.remove();
    var pageSize = data.page_size || 100;
    var rendered = (data.children || []).length;
    var already = options && options.append ? group.querySelectorAll("[data-entry-id]").length : 0;
    (data.children || []).forEach(function (child) {
      if (!group.querySelector('[data-entry-id="' + String(child.entry_id) + '"]')) {
        group.appendChild(this.buildNode(child, node));
      }
    }, this);
    if (already + rendered === 0 && !(data.children || []).length) {
      group.appendChild(el("div", "tree-empty", "Empty directory"));
    }
    var loadedCount = group.querySelectorAll("[data-entry-id]").length;
    if (data.total > loadedCount) {
      var more = el(
        "button",
        "tree-load-more",
        "Load more (" + (data.total - loadedCount) + " remaining)"
      );
      more.type = "button";
      more.setAttribute("data-tree-more", String(id));
      var nextPage = Math.floor(loadedCount / pageSize) + 1;
      more.addEventListener("click", function () {
        more.disabled = true;
        more.textContent = "Loading…";
        this.loadChildren(id, {
          page: nextPage,
          pageSize: pageSize,
          append: true,
        }).then(function (result) {
          if (!result) {
            more.disabled = false;
            more.textContent = "Retry load more";
          }
        });
      }.bind(this));
      group.appendChild(more);
    }
    this.applyFilter();
    this.restoreOpenStateForGroup(group);
    this.applySelectionToDom();
  };

  Tree.prototype.buildNode = function (child, parentNode) {
    var type = child.type === "directory" ? "directory" : "file";
    var parentId = parseInteger(parentNode.getAttribute("data-entry-id")) || 0;
    var level = (parseInteger(parentNode.getAttribute("aria-level")) || 1) + 1;
    var node = el("div", "tree-node");
    node.setAttribute("role", "treeitem");
    node.setAttribute("data-entry-id", String(child.entry_id));
    node.setAttribute("data-entry-type", type);
    node.setAttribute("data-has-children", child.has_children ? "1" : "0");
    node.setAttribute("data-path", child.path);
    node.setAttribute("data-parent-id", String(parentId));
    node.setAttribute("aria-level", String(level));
    node.setAttribute("aria-selected", "false");
    if (type === "directory") {
      node.setAttribute("aria-expanded", "false");
    }
    node.setAttribute(
      "aria-label",
      child.name + " " + type + " " + statusOf(child)
    );

    var row = el("div", "tree-row");
    row.setAttribute("data-tree-row", "");
    row.tabIndex = -1;

    var chevron = el("button", "tree-chevron");
    chevron.type = "button";
    chevron.tabIndex = -1;
    if (type === "directory") {
      chevron.setAttribute("data-tree-chevron", "");
      chevron.setAttribute("aria-label", "Expand " + child.name);
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

    var icon = el("span", "tree-icon");
    icon.appendChild(makeIcon(type));
    icon.setAttribute("aria-hidden", "true");
    row.appendChild(icon);

    var name = el("button", "tree-name", child.name);
    name.type = "button";
    name.setAttribute("data-tree-name", "");
    name.title =
      child.path +
      "\nMFT entry: " +
      (child.mft === null || child.mft === undefined ? "unknown" : child.mft) +
      "\nStatus: " +
      statusOf(child);
    row.appendChild(name);

    var badges = el("span", "tree-badges");
    badges.appendChild(
      el(
        "span",
        "badge " +
          (child.deleted ? "deleted" : child.allocated ? "ok" : "unalloc"),
        statusOf(child)
      )
    );
    if (child.triage && child.triage.job_id) {
      var active = child.triage.status === "queued" || child.triage.status === "running";
      var triageBadge = el(
        "button",
        "badge triaged" + (child.triage.status === "failed" ? " triage-failed" : ""),
        active ? "triaging" : "triaged"
      );
      triageBadge.type = "button";
      triageBadge.title =
        "Latest static triage: " +
        child.triage.status +
        ". Click to open the result. A job is not a malware verdict.";
      triageBadge.addEventListener("click", function (event) {
        event.stopPropagation();
        this.fetchPanel("/triage/jobs/" + child.triage.job_id);
      }.bind(this));
      badges.appendChild(triageBadge);
    }
    row.appendChild(badges);
    node.appendChild(row);

    if (type === "directory") {
      var group = el("div", "tree-group");
      group.setAttribute("role", "group");
      group.setAttribute("data-tree-group", "");
      group.hidden = true;
      node.appendChild(group);
    }
    this.registerNode(node);
    return node;
  };

  Tree.prototype.restoreOpenStateForGroup = function (group) {
    var self = this;
    group.querySelectorAll(':scope > [data-entry-id]').forEach(function (node) {
      var id = parseInteger(node.getAttribute("data-entry-id"));
      if (id === null) return;
      if (self.openIds.has(id) && !node.dataset.opened) {
        self.setExpanded(node, true);
        node.dataset.opened = "1";
        self.loadChildren(id);
      }
    });
  };

  Tree.prototype.restoreSelection = function () {
    if (this.selectedId === null || this.selectedId === undefined) return null;
    var node = this.nodeById(this.selectedId);
    if (node) {
      this.selectNode(this.selectedId, { scroll: true, panel: true });
      return Promise.resolve();
    }
    return this.revealEntry(this.selectedId);
  };

  Tree.prototype.applySelectionToDom = function () {
    if (!this.selectedId) return;
    var self = this;
    this.tree.querySelectorAll('[role="treeitem"]').forEach(function (node) {
      var match =
        node.getAttribute("data-entry-id") === String(self.selectedId);
      node.setAttribute("aria-selected", match ? "true" : "false");
      node.classList.toggle("selected", match);
    });
  };

  Tree.prototype.restoreOpenNodes = function () {
    var ids = Array.from(this.openIds).filter((id) => id > 0);
    ids.sort(function (a, b) { return a - b; });
    var self = this;
    var chain = Promise.resolve();
    ids.forEach(function (id) {
      chain = chain.then(function () {
        if (!self.nodeById(id)) return null;
        return self.openNode(id);
      });
    });
    return chain;
  };

  Tree.prototype.applyFilter = function () {
    var filter = this.filterText;
    var nodes = this.tree.querySelectorAll('[data-entry-id]:not([data-entry-id="0"])');
    var visible = 0;
    nodes.forEach(function (node) {
      var nameEl = node.querySelector("[data-tree-name]");
      var name = nameEl ? nameEl.textContent.toLowerCase() : "";
      var path = (node.getAttribute("data-path") || "").toLowerCase();
      var match = !filter || name.indexOf(filter) !== -1 || path.indexOf(filter) !== -1;
      node.classList.toggle("tree-filtered-out", !match && !!filter);
      if (match) visible += 1;
    });
    var empty = this.tree.querySelector("[data-tree-filter-empty]");
    if (filter && visible === 0) {
      if (!empty) {
        empty = el("div", "tree-empty", "No loaded nodes match this filter.");
        empty.setAttribute("data-tree-filter-empty", "");
        this.tree.appendChild(empty);
      }
    } else if (empty) {
      empty.remove();
    }
  };

  Tree.prototype.updateBreadcrumb = function (node) {
    if (!this.breadcrumb) return;
    var chain = [];
    var current = node;
    while (current && current !== this.tree) {
      if (current.getAttribute && current.getAttribute("data-entry-id") !== null) {
        chain.unshift(current);
      }
      current = current.parentElement;
    }
    this.breadcrumb.textContent = "";
    chain.forEach(function (item, index) {
      if (index > 0) {
        this.breadcrumb.appendChild(el("span", "sep", "/"));
      }
      var nameEl = item.querySelector("[data-tree-name]");
      var label = nameEl ? nameEl.textContent : "?";
      if (index === chain.length - 1) {
        this.breadcrumb.appendChild(el("span", "current", label));
      } else {
        var id = parseInteger(item.getAttribute("data-entry-id"));
        var button = el("button", "link", label);
        button.type = "button";
        var self = this;
        button.addEventListener("click", function () {
          self.selectNode(id, { scroll: true, panel: true });
        });
        this.breadcrumb.appendChild(button);
      }
    }, this);
  };

  Tree.prototype.scrollRowIntoTree = function (row) {
    if (!row) return;
    var container = this.root.querySelector("[data-tree-scroll]");
    if (!container) {
      // Fall back to nearest-block scrolling when the wrapper is absent.
      if (row.scrollIntoView) row.scrollIntoView({ block: "nearest" });
      return;
    }
    // Only the tree pane may scroll; the page must not jump.
    var rowRect = row.getBoundingClientRect();
    var boxRect = container.getBoundingClientRect();
    if (rowRect.top < boxRect.top) {
      container.scrollTop -= boxRect.top - rowRect.top + 6;
    } else if (rowRect.bottom > boxRect.bottom) {
      container.scrollTop += rowRect.bottom - boxRect.bottom + 6;
    }
  };

  Tree.prototype.rowIsVisible = function (row) {
    if (!row) return false;
    var container = this.root.querySelector("[data-tree-scroll]");
    if (!container) return true;
    var rowRect = row.getBoundingClientRect();
    var boxRect = container.getBoundingClientRect();
    return rowRect.top >= boxRect.top - 1 && rowRect.bottom <= boxRect.bottom + 1;
  };

  Tree.prototype.selectNode = function (id, options) {
    if (!this.alive()) return;
    options = options || {};
    var node = this.nodeById(id);
    if (!node) return;
    this.tree.querySelectorAll('[aria-selected="true"]').forEach(function (item) {
      item.setAttribute("aria-selected", "false");
      item.classList.remove("selected");
    });
    node.setAttribute("aria-selected", "true");
    node.classList.add("selected");
    this.selectedId = id;
    this.updateBreadcrumb(node);
    if (options.scroll) {
      this.scrollRowIntoTree(this.rowOf(node));
    }
    this.focusNode(node);
    this.saveState();
    if (options.panel !== false) this.loadPanel(id);
  };

  Tree.prototype.clearPanel = function (message) {
    if (!this.detail) return;
    this.detail.textContent = "";
    var placeholder = el("div", "tree-placeholder");
    placeholder.appendChild(el("p", "muted", message || "Loading selected node…"));
    this.detail.appendChild(placeholder);
  };

  Tree.prototype.loadPanel = function (id) {
    if (!this.detail) return;
    var params = new URLSearchParams({
      include_deleted: this.includeDeleted ? "1" : "0",
      directories_only: this.directoriesOnly ? "1" : "0",
    });
    this.fetchPanel(
      "/evidence/" + this.evidenceId + "/entry/" + id + "?" + params.toString()
    );
  };

  Tree.prototype.fetchPanel = function (url) {
    if (!this.alive()) return;
    var self = this;
    this.clearPanel();
    fetch(url, {
      headers: { Accept: "text/html" },
      credentials: "same-origin",
    })
      .then(function (response) {
        return response.text().then(function (text) {
          if (!response.ok) throw new Error(text || "HTTP " + response.status);
          return text;
        });
      })
      .then(function (html) {
        self.detail.innerHTML = "";
        var template = document.createElement("template");
        template.innerHTML = html;
        self.detail.appendChild(template.content);
        self.detail.scrollTop = 0;
        if (window.htmx && typeof window.htmx.process === "function") {
          window.htmx.process(self.detail);
        }
        self.bindPanel();
      })
      .catch(function (err) {
        self.detail.textContent = "";
        var box = el("div", "tree-error");
        box.setAttribute("role", "alert");
        box.appendChild(el("strong", null, "Could not load node details."));
        box.appendChild(el("p", null, err.message));
        var retry = el("button", "tree-btn", "Retry");
        retry.type = "button";
        retry.addEventListener("click", function () {
          self.fetchPanel(url);
        });
        box.appendChild(retry);
        self.detail.appendChild(box);
      });
  };

  Tree.prototype.bindPanel = function () {
    var self = this;
    if (!this.detail) return;
    this.detail.querySelectorAll("[data-tree-open-id]").forEach(function (button) {
      button.addEventListener("click", function () {
        var id = parseInteger(button.getAttribute("data-tree-open-id"));
        if (id === null) return;
        var node = self.nodeById(id);
        var isDir = node && node.getAttribute("data-entry-type") === "directory";
        var action = isDir ? self.openNode(id) : Promise.resolve();
        action.then(function () {
          self.selectNode(id, { scroll: true, panel: true });
        });
      });
    });
    this.detail.querySelectorAll("[data-tree-sort]").forEach(function (button) {
      button.addEventListener("click", function () {
        if (!self.selectedId) return;
        var params = new URLSearchParams({
          include_deleted: self.includeDeleted ? "1" : "0",
          directories_only: self.directoriesOnly ? "1" : "0",
          sort: button.getAttribute("data-tree-sort") || "path",
          sort_dir: button.getAttribute("data-sort-dir") || "asc",
        });
        self.fetchPanel(
          "/evidence/" +
            self.evidenceId +
            "/entry/" +
            self.selectedId +
            "?" +
            params.toString()
        );
      });
    });
    this.detail.querySelectorAll("[data-tree-nav]").forEach(function (button) {
      button.addEventListener("click", function () {
        self.fetchPanel(button.getAttribute("data-tree-nav"));
      });
    });
    var form = this.detail.querySelector("[data-tree-extract-form]");
    if (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var resultBox = self.detail.querySelector("[data-tree-extract-result]");
        if (resultBox) resultBox.textContent = "Extracting…";
        fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { Accept: "text/html", "HX-Request": "true" },
        })
          .then(function (response) {
            return response.text().then(function (text) {
              if (!response.ok && response.status !== 400 && response.status !== 200) {
                throw new Error("HTTP " + response.status);
              }
              return text;
            });
          })
          .then(function (html) {
            if (!resultBox) return;
            resultBox.innerHTML = "";
            var template = document.createElement("template");
            template.innerHTML = html;
            resultBox.appendChild(template.content);
            if (window.htmx && typeof window.htmx.process === "function") {
              window.htmx.process(resultBox);
            }
          })
          .catch(function (err) {
            if (resultBox) resultBox.textContent = "Extraction failed: " + err.message;
          });
      });
    }
  };

  Tree.prototype.revealEntry = function (entryId) {
    if (!this.alive()) return Promise.resolve();
    var self = this;
    return fetch(
      "/evidence/" + this.evidenceId + "/tree/reveal?entry_id=" + entryId,
      { headers: { Accept: "application/json" } }
    )
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data.ok) {
            throw new Error(
              (data.error && data.error.message) || "reveal failed"
            );
          }
          return data;
        });
      })
      .then(function (data) {
        var steps = data.steps || [];
        var chain = Promise.resolve();
        steps.forEach(function (step) {
          chain = chain.then(function () {
            return self.openNode(step.parent_id).then(function () {
              return self.ensureChildLoaded(
                step.parent_id,
                step.child_id,
                step.page,
                step.page_size
              );
            });
          });
        });
        return chain.then(function () {
          var node = self.nodeById(entryId);
          if (!node) {
            self.clearPanel(
              data.warning ||
                "Entry found in the index but not reachable through the loaded tree."
            );
            return;
          }
          self.selectNode(entryId, { scroll: false, panel: true });
          // Wait one frame so the lazily inserted ancestors are laid out
          // before measuring the target row, then scroll the tree pane only.
          return new Promise(function (resolve) {
            window.requestAnimationFrame(function () {
              window.requestAnimationFrame(function () {
                self.scrollRowIntoTree(self.rowOf(node));
                self.focusNode(node);
                resolve();
              });
            });
          });
        }).then(function () {
          if (data.warning && self.detail) {
            var notice = el("div", "alert warn tree-reveal-warning");
            notice.setAttribute("role", "status");
            notice.textContent = data.warning;
            self.detail.insertBefore(notice, self.detail.firstChild);
          }
        });
      })
      .catch(function (err) {
        self.clearPanel("Could not reveal entry: " + err.message);
      });
  };

  Tree.prototype.ensureChildLoaded = function (parentId, childId, page, pageSize) {
    if (this.nodeById(childId)) return Promise.resolve();
    var size = Math.max(pageSize || 100, 1);
    var start = page || 1;
    var self = this;
    function attempt(currentPage) {
      return self
        .loadChildren(parentId, {
          page: currentPage,
          pageSize: size,
          append: currentPage > 1,
        })
        .then(function (data) {
          if (!data) return null;
          if (self.nodeById(childId)) return null;
          if (currentPage * size < (data.total || 0)) {
            return attempt(currentPage + 1);
          }
          return null;
        });
    }
    return attempt(start);
  };

  Tree.prototype.visibleNodes = function () {
    var result = [];
    var nodes = this.tree.querySelectorAll('[role="treeitem"]');
    nodes.forEach(function (node) {
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

  Tree.prototype.onKeydown = function (event, item) {
    var nodes = this.visibleNodes();
    var index = nodes.indexOf(item);
    var id = parseInteger(item.getAttribute("data-entry-id"));
    var type = item.getAttribute("data-entry-type");
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
        if (type === "directory") {
          if (!expanded) this.openNode(id);
          else if (index >= 0 && index + 1 < nodes.length) {
            var next = nodes[index + 1];
            if (next.getAttribute("data-parent-id") === String(id)) {
              this.focusNode(next);
            }
          }
        }
        event.preventDefault();
        break;
      case "ArrowLeft":
        if (type === "directory" && expanded) {
          this.setExpanded(item, false);
          this.saveState();
        } else {
          var parentId = item.getAttribute("data-parent-id");
          if (parentId !== null) this.focusNode(this.nodeById(Number(parentId)));
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
        if (id !== null) {
          this.selectNode(id, { scroll: false, panel: true });
          if (type === "directory") this.toggleNode(item);
        }
        event.preventDefault();
        break;
      case " ":
        if (id !== null) this.selectNode(id, { scroll: false, panel: true });
        event.preventDefault();
        break;
      default:
        break;
    }
  };

  function boot() {
    document.querySelectorAll(".tree-explorer").forEach(function (root) {
      if (root.dataset.treeBooted === "1") return;
      root.dataset.treeBooted = "1";
      root.__dfirTree = new Tree(root);
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

/* ARIA tablist with roving tabindex for the browser views. */
(function () {
  "use strict";

  function setupTablist(list) {
    if (list.dataset.tablistBound === "1") return;
    list.dataset.tablistBound = "1";
    var tabs = Array.prototype.slice.call(
      list.querySelectorAll('[role="tab"]')
    );
    if (!tabs.length) return;

    function labelPanel(tab) {
      var panel = document.getElementById(
        tab.getAttribute("aria-controls") || "tab-content"
      );
      if (!panel) return;
      if (tab.id) panel.setAttribute("aria-labelledby", tab.id);
      panel.setAttribute("data-active-tab", tab.id || "");
    }

    function select(tab, focus) {
      tabs.forEach(function (item) {
        var active = item === tab;
        item.setAttribute("aria-selected", active ? "true" : "false");
        item.classList.toggle("active", active);
        item.tabIndex = active ? 0 : -1;
      });
      labelPanel(tab);
      if (focus) tab.focus();
    }

    // The panel is labelled by whichever tab is actually selected, not by a
    // hard-coded Browse reference.
    var initial =
      tabs.filter(function (tab) {
        return tab.getAttribute("aria-selected") === "true";
      })[0] || tabs[0];
    labelPanel(initial);

    tabs.forEach(function (tab, index) {
      tab.addEventListener("click", function () {
        select(tab, false);
      });
      tab.addEventListener("keydown", function (event) {
        var next = null;
        if (event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
        else if (event.key === "ArrowLeft") {
          next = tabs[(index - 1 + tabs.length) % tabs.length];
        } else if (event.key === "Home") next = tabs[0];
        else if (event.key === "End") next = tabs[tabs.length - 1];
        if (next) {
          event.preventDefault();
          select(next, true);
        }
      });
    });
  }

  function relabelActivePanel() {
    document.querySelectorAll("[data-tablist]").forEach(function (list) {
      var active = list.querySelector('[role="tab"][aria-selected="true"]');
      var panel = document.getElementById("tab-content");
      if (active && panel && active.id) {
        panel.setAttribute("aria-labelledby", active.id);
        panel.setAttribute("data-active-tab", active.id);
      }
    });
  }

  function boot() {
    document.querySelectorAll("[data-tablist]").forEach(setupTablist);
    relabelActivePanel();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
  document.addEventListener("htmx:afterSwap", boot);
})();

/* "Reveal in tree" from Search / Deleted results. */
(function () {
  "use strict";

  function reveal(target) {
    var entryId = target.getAttribute("data-reveal-entry");
    if (!entryId) return;
    var tab = document.getElementById("tab-tree");
    if (tab && tab.click) tab.click();
    var slot = document.querySelector("#tab-content .tree-explorer");
    if (slot && slot.__dfirTree) {
      slot.__dfirTree.revealEntry(Number(entryId));
      return;
    }
    var treeTab = document.getElementById("tab-tree");
    if (!treeTab) return;
    var poll = window.setInterval(function () {
      var root = document.querySelector("#tab-content .tree-explorer");
      if (root && root.__dfirTree) {
        window.clearInterval(poll);
        root.__dfirTree.revealEntry(Number(entryId));
      }
    }, 100);
    window.setTimeout(function () {
      window.clearInterval(poll);
    }, 8000);
  }

  document.addEventListener("click", function (event) {
    var target = event.target.closest && event.target.closest("[data-reveal-entry]");
    if (!target) return;
    event.preventDefault();
    reveal(target);
  });
})();
