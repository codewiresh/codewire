const app = document.querySelector("[data-dashboard-app]");

(() => {
  "use strict";
  document.addEventListener("submit", (event) => {
    if (!(event.target instanceof HTMLFormElement) || !event.target.matches("form#sign-out, form[data-sign-out-current], form[data-sign-out]")) return;
    try {
      const storage = window.sessionStorage;
      const keys = [];
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (key?.startsWith("codewire.create-selections.v1:")) keys.push(key);
      }
      keys.forEach((key) => storage.removeItem(key));
      storage.removeItem("codewire.create-draft-actor.v1");
    } catch { /* Signing out must remain possible when storage is denied. */ }
  }, true);
  // An acknowledged Create lands on the Sandboxes list or on the new
  // Sandbox's page with ?message=environment-created. Remove exactly the
  // draft whose submission environments.js marked, and nothing else.
  (() => {
    if (new URLSearchParams(window.location.search).get("message") !== "environment-created") return;
    const prefix = "codewire.create-selections.v1:";
    const pendingKey = `${prefix}pending-create`;
    try {
      const storage = window.sessionStorage;
      const marker = JSON.parse(storage.getItem(pendingKey) || "null");
      storage.removeItem(pendingKey);
      const exact = marker && typeof marker === "object" && !Array.isArray(marker) && Object.keys(marker).length === 3
        && ["key", "slug", "at"].every((key) => Object.hasOwn(marker, key));
      if (exact && typeof marker.key === "string" && marker.key.startsWith(prefix) && marker.key !== pendingKey
          && /^[a-z0-9][a-z0-9-]{0,62}$/.test(marker.slug)
          && Number.isSafeInteger(marker.at) && marker.at <= Date.now() && Date.now() - marker.at < 60 * 60 * 1000
          && new RegExp(`^/${marker.slug}/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/)?$`).test(window.location.pathname)) {
        storage.removeItem(marker.key);
      }
    } catch { /* A failed cleanup cannot change the acknowledged Create result. */ }
  })();
  const fieldHelp = (trigger) => {
    if (!(trigger instanceof HTMLButtonElement)) return null;
    const target = document.getElementById(trigger.getAttribute("popovertarget") || "");
    return target instanceof HTMLElement && target.matches("[data-field-help-popover]") ? target : null;
  };
  // Help triggers need no id: remember each open help's trigger by reference.
  const fieldHelpTriggers = new WeakMap();
  const positionFieldHelp = (trigger, help) => {
    const bounds = trigger.getBoundingClientRect();
    const width = Math.min(288, window.innerWidth - 16);
    help.style.left = `${Math.max(8, Math.min(bounds.left, window.innerWidth - width - 8))}px`;
    help.style.top = `${bounds.bottom + 8}px`;
    if (help.matches(":popover-open")) {
      const height = help.getBoundingClientRect().height;
      if (bounds.bottom + 8 + height > window.innerHeight - 8) {
        help.style.top = `${Math.max(8, bounds.top - height - 8)}px`;
      }
    }
  };
  const showFieldHelp = (trigger) => {
    const help = fieldHelp(trigger);
    if (!help || typeof help.showPopover !== "function") return;
    fieldHelpTriggers.set(help, trigger);
    positionFieldHelp(trigger, help);
    if (!help.matches(":popover-open")) help.showPopover();
    positionFieldHelp(trigger, help);
  };
  let fieldHelpHideTimer;
  const hideFieldHelpAfterPointerExit = (help) => {
    window.clearTimeout(fieldHelpHideTimer);
    fieldHelpHideTimer = window.setTimeout(() => {
      const trigger = fieldHelpTriggers.get(help);
      if (help.matches(":popover-open") && !help.matches(":hover") &&
          !trigger?.matches(":hover") && !trigger?.matches(":focus-visible")) help.hidePopover();
    }, 120);
  };
  document.addEventListener("pointerover", (event) => {
    if (event.pointerType !== "mouse" || !(event.target instanceof Element)) return;
    const trigger = event.target.closest("[data-field-help-trigger]");
    if (trigger && !(event.relatedTarget instanceof Node && trigger.contains(event.relatedTarget))) showFieldHelp(trigger);
  });
  document.addEventListener("pointerout", (event) => {
    if (event.pointerType !== "mouse" || !(event.target instanceof Element)) return;
    const target = event.target.closest("[data-field-help-trigger], [data-field-help-popover]");
    const help = target?.matches("[data-field-help-trigger]") ? fieldHelp(target) : target;
    if (help && !(event.relatedTarget instanceof Node && target.contains(event.relatedTarget))) hideFieldHelpAfterPointerExit(help);
  });
  document.addEventListener("focusin", (event) => {
    const trigger = event.target instanceof Element && event.target.closest("[data-field-help-trigger]");
    if (trigger?.matches(":focus-visible")) showFieldHelp(trigger);
  });
  document.addEventListener("focusout", (event) => {
    const trigger = event.target instanceof Element && event.target.closest("[data-field-help-trigger]");
    const help = fieldHelp(trigger);
    if (help) hideFieldHelpAfterPointerExit(help);
  });
  document.addEventListener("click", (event) => {
    const trigger = event.target instanceof Element && event.target.closest("[data-field-help-trigger]");
    const help = fieldHelp(trigger);
    if (!help) return;
    fieldHelpTriggers.set(help, trigger);
    positionFieldHelp(trigger, help);
    window.requestAnimationFrame(() => { if (help.matches(":popover-open")) positionFieldHelp(trigger, help); });
  });
  document.addEventListener("scroll", () => {
    const help = document.querySelector("[data-field-help-popover]:popover-open");
    if (!help) return;
    const trigger = fieldHelpTriggers.get(help);
    if (trigger?.getClientRects().length) positionFieldHelp(trigger, help);
    else help.hidePopover();
  }, true);
  // Native dialogs own focus trapping and Escape. Keep only presentation state
  // here: no form values, credentials, terminal output or capabilities.
  const dialogOpeners = new WeakMap();
  const dialogReturnFocus = new WeakMap();
  const initializedDialogs = new WeakSet();
  const dialogVersions = new WeakMap();
  const dialogRequests = new WeakMap();
  const dialogRequestSequences = new WeakMap();
  const structuralEdits = new WeakSet();
  const submittedForms = new WeakSet();
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
  const isDirty = (dialog) => Array.from(dialog.querySelectorAll("form[data-dirty-guard]")).some((form) => structuralEdits.has(form)) || guardedControls(dialog).some((control) => {
    if (control instanceof HTMLSelectElement) {
      const baseline = defaultSelect(control);
      return Array.from(control.options).some((option, index) => option.selected !== baseline.options[index].selected);
    }
    if (["checkbox", "radio"].includes(control.type)) return control.checked !== control.defaultChecked;
    return control.value !== control.defaultValue;
  });
  const discardEdits = (dialog, preserveDraft = false) => {
    // Invalidate asynchronous Restore/autosave before making the DOM pristine.
    dialog.dispatchEvent(new CustomEvent("codewire:discard-edits", { bubbles: true, detail: { preserveDraft } }));
    const affectedDialogs = Array.from(dialog.querySelectorAll("dialog[data-dialog]"));
    if (dialog instanceof HTMLDialogElement) affectedDialogs.push(dialog);
    affectedDialogs.forEach((owner) => dialogVersions.set(owner, (dialogVersions.get(owner) || 0) + 1));
    guardedControls(dialog).forEach((control) => {
      if (control instanceof HTMLSelectElement) {
        const baseline = defaultSelect(control);
        Array.from(control.options).forEach((option, index) => { option.selected = baseline.options[index].selected; });
      } else if (["checkbox", "radio"].includes(control.type)) control.checked = control.name === "confirm_reconnect" ? false : control.defaultChecked;
      else control.value = control.defaultValue;
    });
    dialog.querySelectorAll("form[data-dirty-guard]").forEach((form) => structuralEdits.delete(form));
    // Removed rows cannot be reconstructed without keeping private snapshots.
    // The next Create opener must fetch a fresh authoritative form instead.
    if (dialog.matches("[data-drawer]")) dialog.dataset.formDiscarded = "true";
  };
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
    if (pending?.owner.isConnected && (pending.owner.open || pending.owner.matches("[data-drawer]:not([hidden])"))
      && pending.focus instanceof HTMLElement && pending.focus.isConnected) {
      pending.focus.focus({ preventScroll: true });
    }
  };
  const draftNodes = "form, input, textarea, select, option, optgroup";
  const replacesDraft = (owner, records) => !owner.isConnected
    || records.some((record) => owner.contains(record.target)
      && [...record.addedNodes, ...record.removedNodes].some((node) => node instanceof Element
        && (node.matches(draftNodes) || node.querySelector(draftNodes))));
  // keepDraft is null for an ordinary form. A dirty Create whose draft is saved
  // in this tab passes { incomplete, detour }: leaving can keep that draft or
  // discard it. A Settings detour carries the draft handle, so it only keeps.
  const guardClose = (owner, perform, keepDraft = null) => {
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
      const save = document.createElement("button");
      save.type = "button";
      save.className = "cw-button";
      save.dataset.saveDraft = "";
      save.hidden = true;
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
      const leave = (preserveDraft) => {
        const pending = pendingDiscard;
        // HTMX may replace the form or its controls while confirmation is
        // open. Never apply an old dismissal decision to that new draft.
        // Autosave/status text updates do not replace the user's draft.
        if (!pending || replacesDraft(pending.owner, pending.observer.takeRecords())) {
          cancelDiscard();
          return;
        }
        pendingDiscard = null;
        pending.observer.disconnect();
        discardPrompt.close();
        if (pending?.owner.isConnected && (pending.owner.open || pending.owner.matches("[data-drawer]:not([hidden])"))) {
          discardEdits(pending.owner, preserveDraft);
          pending.perform();
        }
      };
      discard.addEventListener("click", () => leave(false));
      save.addEventListener("click", () => leave(true));
      actions.append(keep, discard, save);
      discardPrompt.append(header, description, actions);
      document.body.append(discardPrompt);
    }
    const title = discardPrompt.querySelector(".cw-dialog-header h2");
    const description = discardPrompt.querySelector(".cw-dialog-body");
    const discard = discardPrompt.querySelector(".cw-danger-button");
    const save = discardPrompt.querySelector("[data-save-draft]");
    const heading = keepDraft ? "Leave Create Sandbox?" : "Discard changes?";
    discardPrompt.setAttribute("aria-label", heading);
    if (title) title.textContent = heading;
    if (description) description.textContent = !keepDraft
      ? "Your changes will be discarded. Keep editing to return to the form."
      : keepDraft.incomplete
        ? "Your draft is saved in this tab, except a repository URL that may contain credentials. You will need to re-enter that URL when you return."
        : keepDraft.detour
          ? "Your draft is saved in this tab. Return here to restore it after managing settings."
          : "Your draft is saved in this tab and comes back when you open Create Sandbox again.";
    if (discard) {
      discard.hidden = !!keepDraft?.detour;
      discard.textContent = keepDraft ? "Discard draft" : "Discard changes";
    }
    if (save) {
      save.hidden = !keepDraft;
      save.textContent = keepDraft?.incomplete ? "Leave without repository URL" : "Save draft and leave";
    }
    const observer = new MutationObserver((records) => {
      if (pendingDiscard?.owner === owner && replacesDraft(owner, records)) cancelDiscard();
    });
    pendingDiscard = { owner, perform, focus: document.activeElement, observer };
    observer.observe(document.body, { childList: true, subtree: true });
    discardPrompt.showModal();
  };
  const closeDialog = (dialog) => guardClose(dialog, () => { clearPrivate(dialog); dialog.close(); });
  const navigationEligible = (owner) => owner?.isConnected
    && owner.getAttribute("aria-busy") !== "true"
    && !Array.from(owner.querySelectorAll("form[data-dirty-guard]")).some((form) => submittedForms.has(form));
  const navigationOwner = () => {
    const owners = document.querySelectorAll("dialog[data-dialog][open], [data-drawer]:not([hidden])");
    return Array.from(owners).find((owner) => navigationEligible(owner) && isDirty(owner));
  };
  document.addEventListener("codewire:form-structure-edited", (event) => {
    const form = event.target instanceof Element ? event.target.closest("form[data-dirty-guard]") : null;
    if (form) structuralEdits.add(form);
  });
  document.addEventListener("codewire:dirty-navigation-query", (event) => {
    const owner = event.detail?.owner || navigationOwner();
    if (navigationEligible(owner) && isDirty(owner)) event.preventDefault();
  });
  document.addEventListener("codewire:guard-navigation", (event) => {
    const owner = event.detail?.owner || navigationOwner();
    if (navigationEligible(owner) && isDirty(owner)) {
      event.preventDefault();
      // Create saves its draft in this tab as it changes, so every way out of
      // a dirty Create (Close, Escape, Back, a link) can keep that draft.
      const detour = !!event.detail?.preserveCreateDraft;
      const save = { saved: false };
      if (owner.querySelector("[data-environment-form]"))
        owner.dispatchEvent(new CustomEvent("codewire:save-create-draft", { bubbles: true, detail: save }));
      if (detour && !save.saved) return;
      guardClose(owner, event.detail.perform, save.saved ? { incomplete: !!save.incomplete, detour } : null);
    }
  });
  document.addEventListener("submit", (event) => {
    if (event.target instanceof HTMLFormElement && event.target.matches("[data-dirty-guard]")) submittedForms.add(event.target);
  }, true);
  document.addEventListener("htmx:afterRequest", (event) => {
    const form = event.detail?.elt?.closest("form");
    if (form) submittedForms.delete(form);
  });
  window.addEventListener("beforeunload", (event) => {
    if (!navigationOwner()) return;
    event.preventDefault();
    event.returnValue = "";
  });
  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!(link instanceof HTMLAnchorElement) || event.defaultPrevented || event.button !== 0
      || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.hasAttribute("download")
      || (link.target && link.target !== "_self") || link.matches("[data-drawer-close]")) return;
    if (link.matches("[data-drawer-trigger]")) {
      const drawer = document.querySelector("[data-drawer]");
      const rendered = drawer?.getAttribute("data-create-url");
      if (rendered && drawer.dataset.formDiscarded !== "true") {
        const local = new URL(rendered, location.origin);
        const requested = new URL(link.href, location.origin);
        if (local.pathname === requested.pathname && local.search === requested.search) return;
      }
    }
    const target = new URL(link.href, location.href);
    if (!["http:", "https:"].includes(target.protocol)
      || (target.hash && target.origin === location.origin && target.pathname === location.pathname && target.search === location.search)) return;
    if (!document.dispatchEvent(new CustomEvent("codewire:guard-navigation", {
      cancelable: true, detail: { perform: () => location.assign(target.href), preserveCreateDraft: link.hasAttribute("data-create-draft-setup") },
    }))) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, true);
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

// The Sandbox rail is rendered twice, in the desktop sidebar and in the
// mobile drawer, and CSS shows at most one. Only the copy on screen refreshes,
// every 10 seconds while the tab is visible, so a page makes one rail request
// per interval instead of one per copy. A copy that is still loading, or out
// of date when the drawer opens or the tab returns, refreshes at once.
(() => {
  "use strict";
  const RAIL_INTERVAL_MS = 10000;
  const rails = () => Array.from(document.querySelectorAll("[data-sandbox-rail]"));
  // A copy rendered loading has no refresh time, so it is due at once.
  const due = (rail) => Date.now() - Number(rail.dataset.railRefreshedAt || 0) >= RAIL_INTERVAL_MS - 250;
  let timer = 0;
  const refreshShown = () => {
    if (document.hidden) return;
    let refreshed = false;
    for (const rail of rails()) {
      if (rail.getClientRects().length === 0 || !due(rail)) continue;
      rail.dataset.railRefreshedAt = String(Date.now());
      rail.dispatchEvent(new CustomEvent("sandbox-rail-refresh"));
      refreshed = true;
    }
    // A refresh restarts the interval, so a copy refreshed when the drawer
    // opens or the tab returns refreshes again a whole interval later, not at
    // the next tick of the old schedule, which it would skip as not yet due.
    if (refreshed) {
      window.clearInterval(timer);
      timer = window.setInterval(refreshShown, RAIL_INTERVAL_MS);
    }
  };
  // htmx binds the rail's trigger on DOMContentLoaded before this listener runs.
  document.addEventListener("DOMContentLoaded", () => {
    const now = String(Date.now());
    for (const rail of rails()) {
      if (rail.dataset.railLoading !== "true") rail.dataset.railRefreshedAt = now;
    }
    refreshShown();
    if (!timer) timer = window.setInterval(refreshShown, RAIL_INTERVAL_MS);
  });
  document.addEventListener("visibilitychange", refreshShown);
  if (app) {
    new MutationObserver(refreshShown).observe(app, { attributes: true, attributeFilter: ["data-mobile-open", "data-sidebar-collapsed"] });
  }
})();

if (app) {
  const closeSidebar = () => app.setAttribute("data-mobile-open", "false");
  // The desktop sidebar collapses to a rail and expands again. The choice is
  // this browser's own, kept in a cookie so every page renders it at once.
  const setSidebarCollapsed = (collapsed) => {
    app.setAttribute("data-sidebar-collapsed", String(collapsed));
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = collapsed
      ? `codewire.sidebar=collapsed; Path=/; Max-Age=31536000; SameSite=Lax${secure}`
      : `codewire.sidebar=; Path=/; Max-Age=0; SameSite=Lax${secure}`;
    app.querySelector(`.cw-sidebar-slot ${collapsed ? "[data-sidebar-expand]" : "[data-sidebar-close]"}`)?.focus();
  };
  const currentDrawer = () => document.querySelector("[data-drawer]");
  let historyIndex = 0;
  let historyRollback = null;
  let allowedTraversal = null;
  const ownedIndex = (state) => Number.isSafeInteger(state?.codewireDrawerIndex) ? state.codewireDrawerIndex : null;
  // Tag only this document's current entry; preserve other history metadata.
  window.history.replaceState({ ...(window.history.state || {}), codewireDrawerIndex: historyIndex }, "");
  const guardDrawerNavigation = (drawer, perform) => {
    if (document.dispatchEvent(new CustomEvent("codewire:guard-navigation", {
      cancelable: true, detail: { owner: drawer, perform },
    }))) perform();
  };

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
    if (!drawer || drawer.dataset.formDiscarded === "true") return false;
    const target = new URL(href || drawer.getAttribute("data-create-url"), window.location.origin);
    const rendered = new URL(drawer.getAttribute("data-create-url"), window.location.origin);
    // A different form needs fresh server-rendered selection and concurrency metadata.
    if (target.pathname !== rendered.pathname || target.search !== rendered.search) return false;
    setDrawerOpen(true);
    if (target.pathname !== window.location.pathname || target.search !== window.location.search) {
      historyIndex += 1;
      window.history.pushState({ codewireDrawer: true, codewireDrawerIndex: historyIndex }, "", `${target.pathname}${target.search}${target.hash}`);
    }
    return true;
  };

  const closeDrawer = () => {
    const drawer = currentDrawer();
    if (!drawer || drawer.hidden) return false;
    if (historyRollback) return true;
    guardDrawerNavigation(drawer, () => {
      if (window.history.state?.codewireDrawer) {
        allowedTraversal = historyIndex - 1;
        window.history.back();
      } else {
        const closeUrl = new URL(drawer.getAttribute("data-close-url") || window.location.pathname, window.location.origin);
        window.history.replaceState({ ...(window.history.state || {}), codewireDrawerIndex: historyIndex }, "", `${closeUrl.pathname}${closeUrl.search}${closeUrl.hash}`);
        setDrawerOpen(false, false);
      }
    });
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

  // Every shared menu, and disclosures nested inside one, closes on an outside click.
  const menuSelector = ".cw-menu[open], .cw-menu-panel details[open], .cw-org-details[open]";
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
    if (target?.closest(".cw-sidebar-slot [data-sidebar-close], .cw-sidebar-slot [data-sidebar-expand]")) {
      setSidebarCollapsed(!!target.closest("[data-sidebar-close]"));
      return;
    }
    if (target?.closest("[data-sidebar-close], .cw-mobile-drawer a")) {
      closeSidebar();
    }
  });

  // A menu marked data-menu-close-on-action closes once one of its actions has
  // run, as a desktop menu does, and returns focus to its own button. An
  // action that opens a dialog (aria-haspopup) leaves it open so the dialog
  // can return focus to that action.
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const action = target?.closest("button:not([aria-haspopup])");
    const menu = action?.closest("details[data-menu-close-on-action][open]");
    if (!menu || action.closest("summary") || !menu.querySelector(":scope > .cw-menu-panel")?.contains(action)) return;
    menu.removeAttribute("open");
    menu.querySelector(":scope > summary")?.focus({ preventScroll: true });
  });

  document.addEventListener("keydown", (event) => {
    // Native modal dialogs own Escape, focus and keyboard interaction above a
    // drawer. Do not close the underlying Create Sandbox draft as well.
    if (document.querySelector("dialog:modal")) return;
    if (event.key === "Escape" && document.querySelector("[data-field-help-popover]:popover-open")) return;
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

  window.addEventListener("popstate", (event) => {
    const drawer = currentDrawer();
    const next = ownedIndex(event.state);
    if (historyRollback) {
      if (next !== historyRollback.from) return;
      const rollback = historyRollback;
      historyRollback = null;
      guardDrawerNavigation(drawer, () => {
        allowedTraversal = rollback.to;
        window.history.go(rollback.to - rollback.from);
      });
      return;
    }
    if (next === allowedTraversal) allowedTraversal = null;
    else if (drawer && !drawer.hidden && !drawerPathMatches(drawer) && next !== null
      && historyIndex !== null && next !== historyIndex
      && !document.dispatchEvent(new CustomEvent("codewire:dirty-navigation-query", { cancelable: true, detail: { owner: drawer } }))) {
      // popstate cannot be cancelled. Reconcile an app-owned entry first,
      // keeping the actual form visible, then ask before the intended traversal.
      historyRollback = { from: historyIndex, to: next };
      window.history.go(historyIndex - next);
      return;
    }
    historyIndex = next;
    if (drawer?.dataset.formDiscarded === "true" && drawerPathMatches(drawer)) {
      // Forward must honor the same fresh-form policy as a Create opener.
      window.location.replace(window.location.href);
      return;
    }
    setDrawerOpen(drawerPathMatches(drawer));
  });
  document.addEventListener("codewire:drawer-replaced", () => setDrawerOpen(true));
  document.addEventListener("htmx:afterSwap", () => {
    if (!historyRollback && allowedTraversal === null && !document.querySelector('dialog.cw-discard-dialog[open]')) setDrawerOpen(drawerPathMatches(currentDrawer()), false);
  });
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

// Provider device authorization runs inside its Credentials dialog: the form
// asks for enrollment events, shows the one-time code while the provider waits
// for approval, and reloads Credentials once the connection is saved. Without
// JavaScript the same form opens the streamed fallback page.
(() => {
  "use strict";
  const running = new WeakMap();
  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const reset = (dialog) => {
    running.get(dialog)?.abort();
    running.delete(dialog);
    dialog.querySelector(".cw-device-enrollment")?.remove();
    delete dialog.dataset.enrollmentState;
    const submit = dialog.querySelector('.cw-dialog-actions [type="submit"]');
    if (submit instanceof HTMLButtonElement) submit.disabled = false;
  };
  const view = (dialog, state, ...children) => {
    dialog.querySelector(".cw-device-enrollment")?.remove();
    const section = element("section", "cw-device-enrollment");
    section.setAttribute("aria-live", "polite");
    section.append(...children);
    dialog.querySelector(".cw-dialog-body")?.append(section);
    dialog.dataset.enrollmentState = state;
    return section;
  };
  const svgIcon = (name) => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "cw-icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `/assets/codewire/icons-v2.svg#${name}`);
    svg.append(use);
    return svg;
  };
  // The service reports "YYYY-MM-DD HH:MM UTC"; show it in the viewer's time.
  const localTime = (text) => {
    const parts = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}) UTC$/.exec(text || "");
    if (!parts) return text;
    const [, year, month, day, hour, minute] = parts.map(Number);
    return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" })
      .format(new Date(Date.UTC(year, month - 1, day, hour, minute)));
  };
  // The Clipboard API exists only in secure contexts. Elsewhere the code is
  // selected and copied; when that fails it stays selected for the keyboard.
  const copyText = async (text, node) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(node);
    selection?.removeAllRanges();
    selection?.addRange(range);
    if (!document.execCommand("copy")) throw new Error("copy unavailable");
    selection?.removeAllRanges();
  };
  const showChallenge = (dialog, form, challenge) => {
    let url;
    try { url = new URL(challenge.verificationUrl); } catch { url = null; }
    if (!url || url.protocol !== "https:" || typeof challenge.userCode !== "string") return false;
    const code = element("div", "cw-copy-code");
    const copy = element("button", "cw-icon-button");
    copy.type = "button";
    copy.setAttribute("aria-label", "Copy code");
    copy.append(svgIcon("icon-copy"));
    const value = element("code", "", challenge.userCode);
    copy.addEventListener("click", () => {
      copyText(challenge.userCode, value).then(() => {
        copy.replaceChildren(svgIcon("icon-check"));
        copy.setAttribute("aria-label", "Code copied");
        window.setTimeout(() => {
          copy.replaceChildren(svgIcon("icon-copy"));
          copy.setAttribute("aria-label", "Copy code");
        }, 1600);
      }, () => {});
    });
    code.append(value, copy);
    const open = element("a", "cw-button", `Open ${challenge.provider}`);
    open.href = url.href;
    open.target = "_blank";
    open.rel = "noopener noreferrer";
    const again = element("button", "cw-link-button", "Get a new code");
    again.type = "button";
    again.addEventListener("click", () => { void enroll(form, dialog); });
    const footer = element("div", "cw-device-footer");
    footer.append(element("p", "cw-device-status", `Waiting for approval. The code expires at ${localTime(challenge.expires)}.`), again);
    view(dialog, "waiting",
      element("p", "", `Enter this code in ${challenge.provider} to approve the connection.`),
      code,
      open,
      footer);
    open.focus({ preventScroll: true });
    return true;
  };
  const showFailure = (dialog, message, uncertain) => {
    const again = element("button", "cw-button cw-button--outline", "Try again");
    again.type = "button";
    again.addEventListener("click", () => reset(dialog));
    view(dialog, "failed",
      element("p", "cw-alert cw-alert--error", message),
      ...(uncertain ? [element("p", "cw-device-status", "It may already be saved. Check Credentials before connecting again.")] : []),
      again);
    dialog.querySelector(".cw-alert--error")?.setAttribute("role", "alert");
  };
  const handle = (dialog, form, name, data) => {
    if (name === "challenge") return showChallenge(dialog, form, data) ? "continue" : "invalid";
    if (name === "connected" && typeof data.location === "string" && data.location.startsWith("/settings/credentials/")) {
      view(dialog, "connected", element("p", "cw-alert cw-alert--success", "Connected. Updating Credentials…"));
      window.location.assign(data.location);
      return "done";
    }
    if (name === "failed" && typeof data.message === "string") {
      showFailure(dialog, data.message, data.uncertain === true);
      return "done";
    }
    return "invalid";
  };
  const enroll = async (form, dialog) => {
    reset(dialog);
    const controller = new AbortController();
    running.set(dialog, controller);
    view(dialog, "starting", element("p", "cw-device-status", "Requesting a sign-in code…"));
    const submit = dialog.querySelector('.cw-dialog-actions [type="submit"]');
    if (submit instanceof HTMLButtonElement) submit.disabled = true;
    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new URLSearchParams(new FormData(form)),
        headers: { Accept: "text/event-stream" },
        credentials: "same-origin",
        signal: controller.signal,
      });
      // Validation and session failures answer with the page itself.
      if (!response.body || !(response.headers.get("content-type") || "").startsWith("text/event-stream")) {
        window.location.assign(response.url);
        return;
      }
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let boundary;
        while ((boundary = buffer.indexOf("\n\n")) >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const name = /^event: (.+)$/m.exec(frame)?.[1];
          const data = /^data: (.+)$/m.exec(frame)?.[1];
          if (!name || !data) continue;
          const outcome = handle(dialog, form, name, JSON.parse(data));
          if (outcome === "done") return;
          if (outcome === "invalid") throw new Error("invalid enrollment event");
        }
      }
      throw new Error("enrollment ended without an outcome");
    } catch {
      if (controller.signal.aborted) return;
      showFailure(dialog, "The connection ended before Codewire confirmed it.", true);
    }
  };
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("form[data-device-enrollment]")) return;
    const dialog = form.closest("dialog");
    if (!(dialog instanceof HTMLDialogElement) || typeof TextDecoderStream !== "function" || event.defaultPrevented) return;
    event.preventDefault();
    if (!dialog.dataset.enrollmentWired) {
      dialog.dataset.enrollmentWired = "true";
      dialog.addEventListener("close", () => reset(dialog));
    }
    // The submitted values now belong to the running connection, so closing
    // the dialog cancels it instead of asking to discard edits.
    form.querySelectorAll("input, textarea").forEach((control) => { control.defaultValue = control.value; });
    void enroll(form, dialog);
  });
})();

// Date picker: our calendar over a native datetime-local input. The input stays
// the submitted value, keeps keyboard entry and is the no-script fallback. The
// value is UTC wall-clock time, so every calculation here uses UTC.
(() => {
  "use strict";
  if (typeof HTMLElement.prototype.showPopover !== "function") return;
  const DAY_MS = 86400000;
  const pad = (number) => String(number).padStart(2, "0");
  const monthLabel = new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric", timeZone: "UTC" });
  const dayLabel = new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeZone: "UTC" });
  const weekdayShort = new Intl.DateTimeFormat(undefined, { weekday: "short", timeZone: "UTC" });
  const weekdayLong = new Intl.DateTimeFormat(undefined, { weekday: "long", timeZone: "UTC" });
  const date = (day) => new Date(day);
  const today = () => {
    const now = new Date();
    return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  };
  const parse = (value) => {
    const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value || "");
    return parts ? { day: Date.UTC(Number(parts[1]), Number(parts[2]) - 1, Number(parts[3])), time: `${parts[4]}:${parts[5]}` } : null;
  };
  const isoDay = (day) => `${date(day).getUTCFullYear()}-${pad(date(day).getUTCMonth() + 1)}-${pad(date(day).getUTCDate())}`;
  const weekStart = (day) => day - ((date(day).getUTCDay() + 6) % 7) * DAY_MS;
  const addMonths = (day, count) => {
    const value = date(day);
    const first = Date.UTC(value.getUTCFullYear(), value.getUTCMonth() + count, 1);
    const last = date(Date.UTC(date(first).getUTCFullYear(), date(first).getUTCMonth() + 1, 0)).getUTCDate();
    return Date.UTC(date(first).getUTCFullYear(), date(first).getUTCMonth(), Math.min(value.getUTCDate(), last));
  };
  // Fixtures serve the sprite from a relative path; reuse whatever the page uses.
  const sprite = () => document.querySelector("svg.cw-icon use")?.getAttribute("href")?.split("#")[0] || "/assets/codewire/icons-v2.svg";
  const icon = (name) => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "cw-icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `${sprite()}#${name}`);
    svg.append(use);
    return svg;
  };
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  let sequence = 0;

  const enhance = (input) => {
    if (input.dataset.datePickerReady) return;
    input.dataset.datePickerReady = "true";
    const id = `cw-date-picker-${sequence += 1}`;
    const group = make("div", "cw-input-group cw-date-field");
    input.before(group);
    const toggle = make("button", "cw-icon-button");
    toggle.type = "button";
    toggle.setAttribute("aria-label", "Choose date and time");
    toggle.setAttribute("aria-haspopup", "dialog");
    toggle.setAttribute("aria-controls", id);
    toggle.setAttribute("aria-expanded", "false");
    toggle.append(icon("icon-calendar"));
    group.append(input, toggle);

    const picker = make("div", "cw-date-picker");
    picker.id = id;
    picker.popover = "auto";
    picker.setAttribute("role", "dialog");
    picker.setAttribute("aria-label", `Choose ${(input.labels?.[0]?.textContent || "date").trim()}`);
    const heading = make("h2");
    heading.id = `${id}-month`;
    heading.setAttribute("aria-live", "polite");
    const step = (name, label) => {
      const button = make("button", "cw-icon-button");
      button.type = "button";
      button.setAttribute("aria-label", label);
      button.append(icon(name));
      return button;
    };
    const previous = step("icon-chevron-left", "Previous month");
    const next = step("icon-chevron-right", "Next month");
    const header = make("div", "cw-date-picker-header");
    header.append(previous, heading, next);
    const grid = make("table");
    grid.setAttribute("role", "grid");
    grid.setAttribute("aria-labelledby", heading.id);
    const weekdays = make("tr");
    for (let index = 0; index < 7; index += 1) {
      const monday = Date.UTC(2024, 0, 1 + index);
      const cell = make("th", "", weekdayShort.format(date(monday)).slice(0, 2));
      cell.scope = "col";
      cell.abbr = weekdayLong.format(date(monday));
      weekdays.append(cell);
    }
    const head = make("thead");
    head.append(weekdays);
    const body = make("tbody");
    grid.append(head, body);
    const timeRow = make("div", "cw-date-picker-time");
    const timeLabel = make("label", "", "Time (UTC)");
    const time = make("input", "cw-input cw-mono");
    time.id = `${id}-time`;
    timeLabel.htmlFor = time.id;
    time.inputMode = "numeric";
    time.placeholder = "HH:MM";
    time.maxLength = 5;
    time.autocomplete = "off";
    timeRow.append(timeLabel, time);
    const clear = make("button", "cw-link-button", "Clear");
    clear.type = "button";
    const done = make("button", "cw-button cw-button--small", "Done");
    done.type = "button";
    const footer = make("div", "cw-date-picker-footer");
    footer.append(clear, done);
    picker.append(header, grid, timeRow, footer);
    group.after(picker);

    let selected = null;
    let focusDay = today();
    let month = focusDay;
    const write = () => {
      input.value = selected === null ? "" : `${isoDay(selected)}T${time.value || "00:00"}`;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const render = () => {
      heading.textContent = monthLabel.format(date(month));
      const first = Date.UTC(date(month).getUTCFullYear(), date(month).getUTCMonth(), 1);
      const current = date(first).getUTCMonth();
      const floor = today();
      const rows = [];
      for (let start = weekStart(first); date(start).getUTCMonth() === current || start < first; start += 7 * DAY_MS) {
        const row = make("tr");
        for (let offset = 0; offset < 7; offset += 1) {
          const day = start + offset * DAY_MS;
          const cell = make("td");
          if (date(day).getUTCMonth() === current) {
            const button = make("button", "cw-date-picker-day", String(date(day).getUTCDate()));
            button.type = "button";
            button.dataset.day = String(day);
            button.setAttribute("aria-label", dayLabel.format(date(day)));
            button.tabIndex = day === focusDay ? 0 : -1;
            button.disabled = day < floor;
            if (day === floor) button.setAttribute("aria-current", "date");
            cell.setAttribute("aria-selected", String(day === selected));
            cell.append(button);
          }
          row.append(cell);
        }
        rows.push(row);
      }
      body.replaceChildren(...rows);
      previous.disabled = first <= Date.UTC(date(floor).getUTCFullYear(), date(floor).getUTCMonth(), 1);
    };
    const focusGrid = () => body.querySelector(`[data-day="${focusDay}"]`)?.focus();
    const moveTo = (day) => {
      focusDay = Math.max(day, today());
      month = focusDay;
      render();
      focusGrid();
    };
    const choose = (day) => {
      selected = day;
      focusDay = day;
      if (!time.value) time.value = "00:00";
      time.removeAttribute("aria-invalid");
      render();
      write();
      focusGrid();
    };
    const place = () => {
      const bounds = group.getBoundingClientRect();
      const width = picker.getBoundingClientRect().width;
      const height = picker.getBoundingClientRect().height;
      picker.style.left = `${Math.max(8, Math.min(bounds.left, window.innerWidth - width - 8))}px`;
      const below = bounds.bottom + 6;
      picker.style.top = `${below + height > window.innerHeight - 8 ? Math.max(8, bounds.top - height - 6) : below}px`;
    };
    const open = () => {
      const value = parse(input.value);
      selected = value?.day ?? null;
      time.value = value?.time ?? "";
      time.removeAttribute("aria-invalid");
      focusDay = Math.max(selected ?? today(), today());
      month = focusDay;
      render();
      picker.showPopover();
      place();
      focusGrid();
    };

    toggle.addEventListener("click", () => (picker.matches(":popover-open") ? picker.hidePopover() : open()));
    picker.addEventListener("toggle", (event) => {
      const opened = event.newState === "open";
      toggle.setAttribute("aria-expanded", String(opened));
      if (!opened && picker.contains(document.activeElement)) toggle.focus();
    });
    previous.addEventListener("click", () => { month = addMonths(month, -1); focusDay = Math.max(month, today()); render(); });
    next.addEventListener("click", () => { month = addMonths(month, 1); focusDay = month; render(); });
    body.addEventListener("click", (event) => {
      const button = event.target instanceof Element ? event.target.closest("button[data-day]") : null;
      if (button && !button.disabled) choose(Number(button.dataset.day));
    });
    body.addEventListener("keydown", (event) => {
      const moves = {
        ArrowLeft: () => focusDay - DAY_MS,
        ArrowRight: () => focusDay + DAY_MS,
        ArrowUp: () => focusDay - 7 * DAY_MS,
        ArrowDown: () => focusDay + 7 * DAY_MS,
        Home: () => weekStart(focusDay),
        End: () => weekStart(focusDay) + 6 * DAY_MS,
        PageUp: () => addMonths(focusDay, -1),
        PageDown: () => addMonths(focusDay, 1),
      };
      if (moves[event.key]) {
        event.preventDefault();
        moveTo(moves[event.key]());
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        choose(focusDay);
      }
    });
    time.addEventListener("change", () => {
      const valid = /^([01]\d|2[0-3]):[0-5]\d$/.test(time.value);
      if (valid || time.value === "") time.removeAttribute("aria-invalid");
      else time.setAttribute("aria-invalid", "true");
      if (valid && selected !== null) write();
    });
    clear.addEventListener("click", () => {
      selected = null;
      time.value = "";
      render();
      write();
    });
    done.addEventListener("click", () => picker.hidePopover());
    window.addEventListener("resize", () => { if (picker.matches(":popover-open")) place(); });
    document.addEventListener("scroll", () => { if (picker.matches(":popover-open")) place(); }, true);
  };

  const enhanceAll = (root) => root.querySelectorAll('input[type="datetime-local"][data-date-picker]').forEach(enhance);
  enhanceAll(document);
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.target instanceof Element) enhanceAll(event.target);
  });
})();
