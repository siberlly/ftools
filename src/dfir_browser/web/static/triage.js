/* Static triage UI helpers: copy buttons, live tree badges, no evidence HTML. */
(function () {
  "use strict";

  function copyValue(value, button) {
    var done = function () {
      if (!button) return;
      var original = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(function () {
        button.textContent = original;
      }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () {
        window.prompt("Copy value", value);
      });
    } else {
      window.prompt("Copy value", value);
    }
  }

  function updateBadge(result) {
    var entryId = result.getAttribute("data-entry-id");
    var jobId = result.getAttribute("data-job-id");
    var status = result.getAttribute("data-status");
    if (!entryId || !jobId) return;
    var node = document.querySelector(
      '[role="treeitem"][data-entry-id="' + entryId + '"]'
    );
    if (!node) return;
    var badges = node.querySelector(":scope > [data-tree-row] .tree-badges");
    if (!badges) return;
    var existing = badges.querySelector(".badge.triaged");
    if (status !== "complete" && status !== "partial") {
      if (existing && status === "failed") {
        existing.textContent = "triage failed";
        existing.className = "badge triaged triage-failed";
      }
      return;
    }
    var badge;
    if (existing) {
      badge = existing;
    } else {
      badge = document.createElement("button");
      badge.type = "button";
      badge.className = "badge triaged";
      badge.addEventListener("click", function (event) {
        event.stopPropagation();
        var treeRoot = document.querySelector(".tree-explorer");
        var tree = treeRoot && treeRoot.__dfirTree;
        if (tree) tree.fetchPanel("/triage/jobs/" + jobId);
      });
      badges.appendChild(badge);
    }
    badge.textContent = "triaged";
    badge.title =
      "Latest static triage: " +
      status +
      ". Click to open the result. A job is not a malware verdict.";
    badge.setAttribute("data-triage-job", jobId);
  }

  document.addEventListener("click", function (event) {
    var target =
      event.target.closest && event.target.closest("[data-copy-value]");
    if (!target) return;
    event.preventDefault();
    copyValue(target.getAttribute("data-copy-value") || "", target);
  });

  function afterSwap() {
    document.querySelectorAll(".triage-result[data-entry-id]").forEach(updateBadge);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", afterSwap);
  } else {
    afterSwap();
  }
  document.addEventListener("htmx:afterSwap", afterSwap);
  document.addEventListener("htmx:afterSettle", afterSwap);
})();
