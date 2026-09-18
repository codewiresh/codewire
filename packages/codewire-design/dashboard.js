const app = document.querySelector("[data-dashboard-app]");

(() => {
  "use strict";
  // Native dialogs own focus trapping and Escape. Keep only presentation state
  // here: no form values, credentials, terminal output or capabilities.
  const dialogOpeners = new WeakMap();
  const dialogReturnFocus = new WeakMap();
  const initializedDialogs = new WeakSet();
  const dialogVersions = new WeakMap();
  const dialogRequests = new WeakMap();
  const dialogRequestSequences = new WeakMap();
  const currentDialogRequest = (request) => request?.dialog.open
    && dialogVersions.get(request.dialog) === request.version
    && dialogRequestSequences.get(request.target) === request.sequence;
  const guardedControls = (dialog) => Array.from(dialog.querySelectorAll("form[data-dirty-guard] input, form[data-dirty-guard] textarea, form[data-dirty-guard] select"))
    .filter((control) => !control.disabled && !control.readOnly
      && !["hidden", "submit", "button", "reset"].includes(control.type));
  // Reset only a detached select, never the owner's form or authority fields.
  // Native reset handles implicit first options, optgroups and single/multiple.
  const defaultSelect = (control) => {
    const copy = control.cloneNode(true);
    const form = document.createElement("form");
    form.append(copy);
    form.reset();
    return copy;
  };
  const isDirty = (dialog) => guardedControls(dialog).some((control) => {
    if (control instanceof HTMLSelectElement) {
      const baseline = defaultSelect(control);
      return Array.from(control.options).some((option, index) => option.selected !== baseline.options[index].selected);
    }
    if (["checkbox", "radio"].includes(control.type)) return control.checked !== control.defaultChecked;
    return control.value !== control.defaultValue;
  });
  const discardEdits = (dialog) => guardedControls(dialog).forEach((control) => {
    if (control instanceof HTMLSelectElement) {
      const baseline = defaultSelect(control);
      Array.from(control.options).forEach((option, index) => { option.selected = baseline.options[index].selected; });
    } else if (["checkbox", "radio"].includes(control.type)) control.checked = control.defaultChecked;
    else control.value = control.defaultValue;
  });
  let discardPrompt;
  let pendingDiscard;
  const clearPrivate = (dialog) => dialog.querySelectorAll("[data-dialog-private]").forEach((control) => {
    if (control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement) {
      control.value = "";
      control.defaultValue = "";
    }
  });
  const cancelDiscard = () => {
    const pending = pendingDiscard;
    pendingDiscard = null;
    pending?.observer.disconnect();
    if (discardPrompt?.open) discardPrompt.close();
    if (pending?.owner.open && pending.focus instanceof HTMLElement && pending.focus.isConnected) {
      pending.focus.focus({ preventScroll: true });
    }
  };
  const replacesDraft = (owner, records) => !owner.isConnected
    || records.some((record) => owner.contains(record.target));
  const guardClose = (owner, perform) => {
    if (!isDirty(owner)) { perform(); return; }
    if (pendingDiscard) return;
    if (!discardPrompt) {
      discardPrompt = document.createElement("dialog");
      discardPrompt.className = "cw-dialog cw-discard-dialog";
      discardPrompt.setAttribute("aria-label", "Discard changes?");
      const header = document.createElement("header");
      header.className = "cw-dialog-header";
      const title = document.createElement("h2");
      title.textContent = "Discard changes?";
      header.append(title);
      const description = document.createElement("p");
      description.className = "cw-dialog-body";
      description.textContent = "Your unsaved changes will be lost. Keep editing to return to the form.";
      const actions = document.createElement("footer");
      actions.className = "cw-dialog-actions";
      const keep = document.createElement("button");
      keep.type = "button";
      keep.className = "cw-button cw-button--outline";
      keep.textContent = "Keep editing";
      keep.autofocus = true;
      const discard = document.createElement("button");
      discard.type = "button";
      discard.className = "cw-button cw-danger-button";
      discard.textContent = "Discard changes";
      const keepEditing = cancelDiscard;
      keep.addEventListener("click", keepEditing);
      discardPrompt.addEventListener("cancel", (event) => { event.preventDefault(); keepEditing(); });
      let backdropPress = false;
      const outside = (event) => {
        const bounds = discardPrompt.getBoundingClientRect();
        return event.target === discardPrompt && (event.clientX < bounds.left || event.clientX > bounds.right
          || event.clientY < bounds.top || event.clientY > bounds.bottom);
      };
      discardPrompt.addEventListener("pointerdown", (event) => { backdropPress = outside(event); });
      discardPrompt.addEventListener("click", (event) => {
        if (backdropPress && outside(event)) keepEditing();
        backdropPress = false;
      });
      discard.addEventListener("click", () => {
        const pending = pendingDiscard;
        // HTMX may replace the inner form while confirmation is open. Never
        // apply an old dismissal decision to the new form or its field errors.
        if (!pending || replacesDraft(pending.owner, pending.observer.takeRecords())) {
          cancelDiscard();
          return;
        }
        pendingDiscard = null;
        pending.observer.disconnect();
        discardPrompt.close();
        if (pending?.owner.isConnected && pending.owner.open) {
          discardEdits(pending.owner);
          pending.perform();
        }
      });
      actions.append(keep, discard);
      discardPrompt.append(header, description, actions);
      document.body.append(discardPrompt);
    }
    const observer = new MutationObserver((records) => {
      if (pendingDiscard?.owner === owner && replacesDraft(owner, records)) cancelDiscard();
    });
    pendingDiscard = { owner, perform, focus: document.activeElement, observer };
    observer.observe(document.body, { childList: true, subtree: true });
    discardPrompt.showModal();
  };
  const closeDialog = (dialog) => guardClose(dialog, () => { clearPrivate(dialog); dialog.close(); });
  const openDialog = (dialog, opener = document.activeElement) => {
    if (!(dialog instanceof HTMLDialogElement) || dialog.open) return;
    const previous = opener instanceof Element ? opener.closest("dialog[data-dialog]") : null;
    const originalOpener = previous ? dialogOpeners.get(previous) : opener;
    const show = () => {
      const returnFocus = dialogReturnFocus.get(dialog);
      if (previous?.open) {
        dialogReturnFocus.set(previous, opener);
        clearPrivate(previous);
        previous.close();
      }
      dialogOpeners.set(dialog, originalOpener);
      dialogVersions.set(dialog, (dialogVersions.get(dialog) || 0) + 1);
      dialog.showModal();
      if (opener instanceof Element && opener.matches("[data-dialog-back]")
        && returnFocus instanceof HTMLElement && dialog.contains(returnFocus)) {
        returnFocus.focus({ preventScroll: true });
      }
      dialog.dispatchEvent(new Event("codewire:dialog-open", { bubbles: true }));
    };
    if (previous?.open) guardClose(previous, show);
    else show();
  };

  const initializeDialogs = (root = document) => {
    const dialogs = Array.from(root.querySelectorAll?.("dialog[data-dialog]") || []);
    if (root instanceof HTMLDialogElement && root.matches("[data-dialog]")) dialogs.unshift(root);
    dialogs.forEach((dialog) => {
      if (initializedDialogs.has(dialog)) return;
      initializedDialogs.add(dialog);
      let backdropPress = false;
      const outside = (event) => {
        const bounds = dialog.getBoundingClientRect();
        return event.target === dialog && (event.clientX < bounds.left || event.clientX > bounds.right
          || event.clientY < bounds.top || event.clientY > bounds.bottom);
      };
      dialog.addEventListener("pointerdown", (event) => { backdropPress = outside(event); });
      dialog.addEventListener("click", (event) => {
        // Dragging from a form field onto the backdrop must not discard a form.
        if (backdropPress && outside(event)) closeDialog(dialog);
        backdropPress = false;
      });
      dialog.addEventListener("cancel", (event) => { event.preventDefault(); closeDialog(dialog); });
      dialog.addEventListener("close", () => {
        if (dialog.open) return;
        if (pendingDiscard?.owner === dialog) cancelDiscard();
        dialogVersions.set(dialog, (dialogVersions.get(dialog) || 0) + 1);
        clearPrivate(dialog);
        const opener = dialogOpeners.get(dialog);
        dialogOpeners.delete(dialog);
        // A chooser may have switched directly to another dialog. Do not steal
        // focus from that dialog when the queued close event is delivered.
        if (!document.querySelector("dialog:modal") && opener instanceof HTMLElement && opener.isConnected) {
          opener.focus({ preventScroll: true });
        }
      });
      if (dialog.hasAttribute("data-dialog-auto-open") && !document.querySelector("dialog:modal")) openDialog(dialog);
    });
  };

  const stopMetadata = (trigger) => {
    const { environmentId, environmentName, listSearch = "", listState = "" } = trigger.dataset;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(environmentId || "")
      || !environmentName || environmentName.length > 512
      || /[\u0000-\u001f\u007f]/.test(environmentName + listSearch)
      || Array.from(listSearch).length > 128
      || !["", "all", "running", "stopped", "pending", "creating", "starting", "stopping", "error", "destroyed"].includes(listState)) return null;
    return { environment_id: environmentId, name: environmentName, list_search: listSearch, list_state: listState };
  };
  const initializeStopButtons = (root = document) => {
    const dialog = document.querySelector("[data-inventory-stop-dialog]");
    if (!(dialog instanceof HTMLDialogElement)) return;
    root.querySelectorAll?.("[data-inventory-stop]").forEach((trigger) => {
      if (!(trigger instanceof HTMLButtonElement) || !stopMetadata(trigger)) return;
      trigger.hidden = false;
      const fallback = trigger.parentElement?.querySelector("[data-inventory-stop-fallback]");
      if (fallback) fallback.hidden = true;
    });
  };
  initializeDialogs();
  initializeStopButtons();
  // Navigation (including a successful native POST) must not leave write-only
  // values in a retained BFCache document. Do not clear them on failed submits.
  window.addEventListener("pagehide", () => {
    cancelDiscard();
    document.querySelectorAll("dialog[data-dialog]").forEach(clearPrivate);
  });
  document.addEventListener("htmx:beforeRequest", (event) => {
    const dialog = event.detail?.target?.closest("dialog[data-dialog]");
    if (!(dialog instanceof HTMLDialogElement)) return;
    const target = event.detail.target;
    const sequence = (dialogRequestSequences.get(target) || 0) + 1;
    dialogRequestSequences.set(target, sequence);
    dialogRequests.set(event.detail.xhr, { dialog, target, sequence, version: dialogVersions.get(dialog) });
    // Keep Close available, but don't allow stale forms to submit while their
    // fresh state or a mutation acknowledgement is still in flight.
    target.inert = true;
    target.setAttribute("aria-busy", "true");
    const error = dialog.querySelector("[data-dialog-load-error]");
    if (error) error.hidden = true;
  });
  document.addEventListener("htmx:beforeSwap", (event) => {
    const request = dialogRequests.get(event.detail?.xhr);
    if (request && !currentDialogRequest(request)) {
      event.detail.shouldSwap = false;
    }
  });
  document.addEventListener("htmx:beforeOnLoad", (event) => {
    const request = dialogRequests.get(event.detail?.xhr);
    if (request && !currentDialogRequest(request)) {
      // HTMX handles redirect/refresh headers before beforeSwap. A late response
      // for a dismissed dialog must not navigate or replace this document.
      event.preventDefault();
    }
  });
  document.addEventListener("htmx:afterRequest", (event) => {
    const request = dialogRequests.get(event.detail?.xhr);
    if (!currentDialogRequest(request)) return;
    request.target.removeAttribute("aria-busy");
    const status = event.detail.xhr.status;
    request.target.inert = !((status >= 200 && status < 300) || status === 422);
  });
  const dialogRequestError = (event) => {
    const request = dialogRequests.get(event.detail?.xhr);
    if (!currentDialogRequest(request)) return;
    const error = request.dialog.querySelector("[data-dialog-load-error]");
    if (error) error.hidden = false;
  };
  document.addEventListener("htmx:sendError", dialogRequestError);
  document.addEventListener("htmx:responseError", dialogRequestError);
  document.addEventListener("htmx:timeout", dialogRequestError);
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const stopTrigger = target?.closest("[data-inventory-stop]");
    if (stopTrigger instanceof HTMLButtonElement) {
      const dialog = document.querySelector("[data-inventory-stop-dialog]");
      if (!(dialog instanceof HTMLDialogElement) || dialog.open) return;
      const metadata = stopMetadata(stopTrigger);
      if (!metadata) return;
      const form = dialog.querySelector("form");
      const name = dialog.querySelector("[data-inventory-stop-name]");
      const controls = ["environment_id", "list_search", "list_state"].map((key) => form?.elements.namedItem(key));
      if (!name || !controls.every((control) => control instanceof HTMLInputElement)) return;
      event.preventDefault();
      controls.forEach((control) => { control.value = metadata[control.name]; });
      name.textContent = metadata.name;
      openDialog(dialog, stopTrigger);
      return;
    }
    const trigger = target?.closest("[data-dialog-open]");
    if (trigger instanceof HTMLButtonElement) {
      const dialog = document.getElementById(trigger.dataset.dialogOpen);
      if (dialog?.matches("dialog[data-dialog]")) {
        event.preventDefault();
        openDialog(dialog, trigger);
      }
    } else if (target?.closest("[data-dialog-close]")) {
      const dialog = target.closest("dialog[data-dialog]");
      if (dialog instanceof HTMLDialogElement) {
        event.preventDefault();
        closeDialog(dialog);
      }
    }
  });
  document.addEventListener("htmx:afterSwap", (event) => {
    const root = event.target instanceof Element ? event.target : document;
    initializeDialogs(root);
    initializeStopButtons(root);
  });
})();

const nameToSlug = (name) => name
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, "-")
  .replace(/^-+|-+$/g, "")
  .slice(0, 48);

const initializeSlugSuggestion = (root = document) => {
  const source = root.querySelector?.("[data-slug-source]");
  const target = root.querySelector?.("[data-slug-target]");
  if (source && target) target.dataset.suggested = nameToSlug(source.value);
};

initializeSlugSuggestion();

document.addEventListener("input", (event) => {
  const target = event.target instanceof HTMLInputElement ? event.target : null;
  if (target?.matches("[data-slug-source]")) {
    const slug = document.querySelector("[data-slug-target]");
    if (!(slug instanceof HTMLInputElement)) return;
    const previous = slug.dataset.suggested || "";
    const suggested = nameToSlug(target.value);
    if (!slug.value || slug.value === previous) slug.value = suggested;
    slug.dataset.suggested = suggested;
  } else if (target?.matches("[data-slug-target]")) {
    target.value = target.value.toLowerCase();
  }
});

document.addEventListener("htmx:afterSwap", (event) => {
  const target = event.target instanceof Element ? event.target : document;
  initializeSlugSuggestion(target);
});

if (app) {
  const closeSidebar = () => app.setAttribute("data-mobile-open", "false");
  const currentDrawer = () => document.querySelector("[data-drawer]");

  const drawerPathMatches = (drawer) => {
    const createUrl = drawer?.getAttribute("data-create-url");
    // A rejected native form submission renders the open drawer at its POST URL.
    // Keep that response visible, including when background fragments refresh.
    const actionUrl = drawer?.querySelector("form")?.getAttribute("action");
    return [createUrl, actionUrl].some((url) => {
      if (!url) return false;
      const target = new URL(url, window.location.origin);
      return target.pathname === window.location.pathname && target.search === window.location.search;
    });
  };

  const focusDrawer = (drawer) => {
    const panel = drawer?.querySelector("[data-drawer-panel]");
    const target = panel?.querySelector("#environment-name")
      || panel?.querySelector("input:not([type='hidden']):not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled), a[href]");
    if (target instanceof HTMLElement) target.focus({ preventScroll: true });
    else if (panel instanceof HTMLElement) panel.focus({ preventScroll: true });
  };

  const setDrawerOpen = (open, focus = true) => {
    const drawer = currentDrawer();
    if (!(drawer instanceof HTMLElement)) return;
    drawer.hidden = !open;
    drawer.dataset.open = String(open);
    drawer.setAttribute("aria-hidden", String(!open));
    document.body.toggleAttribute("data-drawer-open", open);
    if (open && focus) window.requestAnimationFrame(() => focusDrawer(drawer));
  };

  const openDrawer = (href) => {
    const drawer = currentDrawer();
    if (!drawer) return false;
    const target = new URL(href || drawer.getAttribute("data-create-url"), window.location.origin);
    const rendered = new URL(drawer.getAttribute("data-create-url"), window.location.origin);
    // A different form needs fresh server-rendered selection and concurrency metadata.
    if (target.pathname !== rendered.pathname || target.search !== rendered.search) return false;
    setDrawerOpen(true);
    if (target.pathname !== window.location.pathname || target.search !== window.location.search) {
      window.history.pushState({ codewireDrawer: true }, "", `${target.pathname}${target.search}${target.hash}`);
    }
    return true;
  };

  const closeDrawer = () => {
    const drawer = currentDrawer();
    if (!drawer || drawer.hidden) return false;
    if (window.history.state?.codewireDrawer) {
      window.history.back();
    } else {
      const closeUrl = new URL(drawer.getAttribute("data-close-url") || window.location.pathname, window.location.origin);
      window.history.replaceState(null, "", `${closeUrl.pathname}${closeUrl.search}${closeUrl.hash}`);
      setDrawerOpen(false, false);
    }
    return true;
  };

  const openQuickSearch = () => {
    const dialog = document.querySelector("[data-quick-search]");
    if (!(dialog instanceof HTMLDialogElement)) return;
    if (!dialog.open) dialog.showModal();
    const input = dialog.querySelector("[data-quick-search-input]");
    if (input instanceof HTMLInputElement) {
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
    }
  };

  const menuSelector = ".cw-org-details[open], .cw-action-menu[open], .cw-filter-menu[open], .cw-row-menu[open], .cw-menu-resize[open], .cw-menu-destroy[open]";
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    // A dialog's close/backdrop event can reach here after it has closed.
    // Preserve the underlying menus so its original opener stays focusable.
    if (target?.closest("dialog") || document.querySelector("dialog:modal")) return;
    document.querySelectorAll(menuSelector).forEach((details) => {
      if (target && !details.contains(target)) details.removeAttribute("open");
    });
    const drawerTrigger = target?.closest("[data-drawer-trigger]");
    if (drawerTrigger instanceof HTMLAnchorElement && openDrawer(drawerTrigger.href)) {
      event.preventDefault();
      return;
    }
    if (target?.closest("[data-drawer-close]")) {
      event.preventDefault();
      closeDrawer();
      return;
    }
    if (target?.closest("[data-sidebar-toggle]")) {
      const open = app.getAttribute("data-mobile-open") === "true";
      app.setAttribute("data-mobile-open", String(!open));
      return;
    }
    if (target?.closest("[data-quick-search-open]")) {
      openQuickSearch();
      return;
    }
    if (target?.closest("[data-sidebar-close], .cw-mobile-drawer a")) {
      closeSidebar();
    }
  });

  document.addEventListener("keydown", (event) => {
    // Native modal dialogs own Escape, focus and keyboard interaction above a
    // drawer. Do not close the underlying Create Sandbox draft as well.
    if (document.querySelector("dialog:modal")) return;
    const target = event.target instanceof HTMLElement ? event.target : null;
    const isEditing = target?.matches("input, textarea, select, [contenteditable='true']");
    if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey && !isEditing) {
      event.preventDefault();
      openQuickSearch();
      return;
    }
    const openDetails = target?.closest(menuSelector) || Array.from(document.querySelectorAll(menuSelector)).at(-1);
    if (event.key === "Escape" && openDetails) {
      openDetails.removeAttribute("open");
      openDetails.querySelector(":scope > summary")?.focus({ preventScroll: true });
      event.preventDefault();
      return;
    }
    if (event.key === "Escape" && closeDrawer()) {
      event.preventDefault();
      return;
    }
    if (event.key === "Escape") {
      closeSidebar();
    }
  });

  document.addEventListener("input", (event) => {
    const input = event.target instanceof HTMLInputElement ? event.target : null;
    if (!input?.matches("[data-quick-search-input]")) return;
    const dialog = input.closest("[data-quick-search]");
    if (!dialog) return;
    const query = input.value.trim().toLowerCase();
    let visible = 0;
    dialog.querySelectorAll("[data-search-item]").forEach((item) => {
      const matches = !query || (item.getAttribute("data-search-text") || item.textContent || "")
        .toLowerCase()
        .includes(query);
      const result = item.closest("li") || item;
      result.toggleAttribute("hidden", !matches);
      if (matches) visible += 1;
    });
    const empty = dialog.querySelector("[data-quick-search-empty]");
    if (empty instanceof HTMLElement) empty.hidden = visible !== 0;
  });

  window.addEventListener("popstate", () => setDrawerOpen(drawerPathMatches(currentDrawer())));
  document.addEventListener("codewire:drawer-replaced", () => setDrawerOpen(true));
  document.addEventListener("htmx:afterSwap", () => setDrawerOpen(drawerPathMatches(currentDrawer()), false));
  document.addEventListener("keydown", (event) => {
    if (document.querySelector("dialog:modal")) return;
    if (event.key !== "Tab") return;
    const drawer = currentDrawer();
    if (!drawer || drawer.hidden) return;
    const panel = drawer.querySelector("[data-drawer-panel]");
    if (!panel) return;
    const focusable = Array.from(panel.querySelectorAll("a[href], button:not(:disabled), input:not([type='hidden']):not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])"))
      .filter((element) => element instanceof HTMLElement && element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  setDrawerOpen(drawerPathMatches(currentDrawer()));
}
