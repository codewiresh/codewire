// The Billing page's card form (#4750): Stripe's Payment Element, in the
// Add card dialog and, with no card yet, under Add credit. The card number
// stays inside Stripe's frame. The form mounts without a SetupIntent; on
// save, this script asks the dashboard for one, sending the choices made
// beside the form, which billing keeps in the SetupIntent. It confirms the
// card with Stripe (which opens the bank's check over the page when the bank
// asks) and tells the dashboard which SetupIntent is done, nothing more; the
// dashboard then says where to go, normally back to Billing with what
// happened. Without script there is no card form; Add credit with a saved
// card still posts.
(() => {
  // Back from a bank's check that needed a full redirect, Stripe's
  // SetupIntent and its secret are in the URL. It is cleaned before anything
  // else runs, so it stays out of history and no later request carries it;
  // the page's Referer carries only its origin.
  const returned = new URLSearchParams(window.location.search);
  const cardReturn = returned.get("card_return") === "1" && returned.has("redirect_status");
  if (cardReturn) window.history.replaceState(null, "", window.location.pathname);

  const setup = document.querySelector("[data-card-setup]");
  if (!(setup instanceof HTMLElement)) return;
  const csrf = () => setup.querySelector('[name="_csrf"]')?.value || "";
  const UNAVAILABLE = "The billing service is temporarily unavailable. Try again in a moment.";
  const OFF = "Adding a card isn't available right now. Try again later.";

  // Same-origin form posts that answer JSON; any other answer is a failure.
  const post = async (url, fields) => {
    let response;
    try {
      response = await fetch(url, {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: { Accept: "application/json" },
        body: new URLSearchParams({ _csrf: csrf(), ...fields }),
      });
    } catch {
      throw new Error(UNAVAILABLE);
    }
    const json = (response.headers.get("content-type") || "").startsWith("application/json");
    const answer = json ? await response.json().catch(() => ({})) : {};
    if (!response.ok || typeof answer.error === "string") throw new Error(answer.error || UNAVAILABLE);
    return answer;
  };

  // Where a finished setup may send the page: Billing on this origin, or
  // Stripe's invoice page when the bank wants a purchase approved.
  const safeLocation = (location) => {
    if (typeof location !== "string") return null;
    try {
      const url = new URL(location, window.location.origin);
      if (url.origin === window.location.origin) return url.href;
      if (url.protocol === "https:" && url.hostname === "invoice.stripe.com") return url.href;
    } catch {
      return null;
    }
    return null;
  };

  // Stripe's form takes its colours and type from the console's tokens.
  const appearance = () => {
    const style = getComputedStyle(document.body);
    const token = (name) => style.getPropertyValue(name).trim();
    const dark = document.documentElement.dataset.theme === "dark" ||
      (document.documentElement.dataset.theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    return {
      theme: dark ? "night" : "stripe",
      variables: {
        colorPrimary: token("--accent"), colorText: token("--fg-primary"), colorBackground: token("--bg-field"),
        colorDanger: token("--destructive"), fontFamily: token("--font-sans"), borderRadius: token("--radius-md"),
      },
    };
  };

  // One card form: its parts, its Stripe objects once mounted, and a
  // confirmed SetupIntent whose finish is still owed.
  const forms = new WeakMap();
  const formOf = (region) => {
    if (!forms.has(region)) {
      const owner = region.closest("form[data-add-credit]");
      forms.set(region, {
        region, owner,
        element: region.querySelector("[data-card-element]"),
        error: region.querySelector("[data-card-error]"),
        declined: region.querySelector("[data-card-declined]"),
        status: region.querySelector("[data-card-status]"),
        topUp: region.querySelector("[data-card-top-up]"),
        amount: region.querySelector("[data-card-top-up-amount]"),
        submit: owner ? owner.querySelector("[data-add-credit-submit]") : region.querySelector("[data-card-submit]"),
        cancel: region.querySelector("[data-card-cancel]"),
        stripe: null, elements: null, mounting: null, confirmed: "",
      });
    }
    return forms.get(region);
  };

  const say = (form, text) => {
    if (!form.status) return;
    form.status.hidden = !text;
    form.status.textContent = text || "";
  };
  const fail = (form, text) => {
    if (!form.error) return;
    form.error.hidden = !text;
    form.error.textContent = text || "";
  };
  const busy = (form, on) => {
    form.region.setAttribute("aria-busy", on ? "true" : "false");
    if (form.submit) form.submit.disabled = on;
    if (form.cancel) form.cancel.disabled = on;
  };

  // The dialog's button names the charge saving makes: with no credit left
  // and top-up on, saving charges the top-up at once (owner, 2026-11-14).
  const syncDialog = (form) => {
    if (!form.topUp || !form.amount || form.done) return;
    form.amount.disabled = !form.topUp.checked;
    const euros = `€${form.amount.value}`;
    form.region.querySelectorAll("[data-card-top-up-euros]").forEach((node) => { node.textContent = euros; });
    if (form.owner || !form.submit) return;
    form.submit.textContent = form.submit.hasAttribute("data-card-pays") && form.topUp.checked
      ? `Save card and pay ${euros}` : "Save card";
  };

  // Stripe.js loads only once a card form opens, so a visit to Billing
  // fetches nothing from Stripe.
  let stripeLoading = null;
  const loadStripe = () => {
    stripeLoading ||= new Promise((resolve, reject) => {
      if (typeof window.Stripe === "function") return resolve();
      const script = document.createElement("script");
      script.src = setup.dataset.cardStripe || "";
      script.addEventListener("load", () => (typeof window.Stripe === "function" ? resolve() : reject()));
      script.addEventListener("error", () => reject());
      document.head.append(script);
    }).catch(() => {
      stripeLoading = null;
      throw new Error("The card form couldn't load. Check your connection and try again.");
    });
    return stripeLoading;
  };

  // Stripe's form mounts with no SetupIntent: one is made only when the
  // card is saved, so opening a form spends none of billing's card-setup
  // caps (#4874).
  const mount = (form) => {
    form.mounting ||= (async () => {
      say(form, "Loading the card form…");
      await loadStripe();
      if (!setup.dataset.cardKey) throw new Error(OFF);
      form.stripe = window.Stripe(setup.dataset.cardKey);
      form.elements = form.stripe.elements({
        mode: "setup", currency: "eur", paymentMethodTypes: ["card"], appearance: appearance(),
      });
      // Cards only, as v4 shows them: no Link sign-up and no wallets.
      const payment = form.elements.create("payment", { wallets: { applePay: "never", googlePay: "never", link: "never" } });
      // Whether a card is typed in, which is what holds a live refresh
      // (#4981); emptied again, a held refresh runs.
      payment.on("change", (event) => {
        form.typed = !event.empty;
        if (event.empty) settle();
      });
      payment.mount(form.element);
      say(form, "");
    })().catch((error) => {
      form.mounting = null;
      say(form, "");
      fail(form, error.message);
      throw error;
    });
    return form.mounting;
  };

  // What saving chooses beside the card: the top-up setting, and with no
  // card yet the credit Add credit is buying. Billing reads them back only
  // from the SetupIntent, never from the finish.
  const choices = (form) => {
    const hidden = (name) => form.region.querySelector(`input[type="hidden"][name="${name}"]`)?.value || "";
    const fields = { top_up_amount: form.amount ? form.amount.value : hidden("top_up_amount") };
    if (form.topUp ? form.topUp.checked : hidden("top_up") === "true") fields.top_up = "true";
    if (form.owner) {
      const other = form.owner.querySelector("[data-add-credit-other]")?.value.trim() || "";
      const chip = form.owner.querySelector('input[name="choice"]:checked')?.value || "";
      Object.assign(fields, { credit: "1", credit_choice: other ? "custom" : chip, credit_amount: other });
    }
    return fields;
  };

  // Where Stripe sends the page back when the bank's check needs a full
  // redirect: Billing, which finishes the SetupIntent Stripe names there.
  const returnUrl = () => {
    const url = new URL(window.location.pathname, window.location.origin);
    url.searchParams.set("card_return", "1");
    return url.href;
  };

  const save = async (form) => {
    fail(form, "");
    busy(form, true);
    try {
      await mount(form);
      if (!form.confirmed) {
        // The card's own checks first, at the field, before any SetupIntent.
        const submitted = await form.elements.submit();
        if (submitted.error) {
          fail(form, `${submitted.error.message || "The card wasn't accepted."} Nothing was saved or charged.`);
          return;
        }
        say(form, "Saving your card with Stripe…");
        const begun = await post(setup.dataset.cardBegin, choices(form));
        if (typeof begun.client_secret !== "string") throw new Error(UNAVAILABLE);
        // A modal dialog sits in the browser's top layer, above anything
        // Stripe adds to the page, so the bank's check would open behind it.
        // While Stripe confirms, the dialog stays open but not modal.
        const dialog = form.region.closest("dialog");
        const wasModal = Boolean(dialog?.open && dialog.matches(":modal"));
        if (wasModal) {
          dialog.close();
          dialog.show();
        }
        const { error, setupIntent } = await form.stripe.confirmSetup({
          elements: form.elements, clientSecret: begun.client_secret, redirect: "if_required",
          confirmParams: { return_url: returnUrl() },
        });
        if (wasModal && dialog.open) {
          dialog.close();
          dialog.showModal();
        }
        if (error) {
          say(form, "");
          fail(form, error.code === "setup_intent_authentication_failure"
            ? "Your bank didn't confirm the card. Nothing was saved."
            : `${error.message || "The card wasn't accepted."} Nothing was saved or charged.`);
          return;
        }
        form.confirmed = setupIntent.id;
      }
      say(form, "Finishing…");
      const answer = await post(setup.dataset.cardFinish, { setup_intent: form.confirmed });
      const next = safeLocation(answer.location);
      if (!next) throw new Error(UNAVAILABLE);
      if (typeof answer.declined === "string" && answer.declined && form.submit && !form.owner) {
        // The card is saved but its charge was declined (#6502): the dialog
        // stays open to say so, and Done goes on to Billing.
        say(form, "");
        if (form.declined) {
          form.declined.textContent = answer.declined;
          form.declined.hidden = false;
        } else {
          fail(form, answer.declined);
        }
        form.confirmed = "";
        form.done = next;
        if (form.cancel) form.cancel.hidden = true;
        form.submit.removeAttribute("data-card-pays");
        form.submit.textContent = "Done";
        return;
      }
      window.location.assign(next);
    } catch (error) {
      say(form, "");
      // A confirmed card is saved with Stripe; only the finish is retried.
      fail(form, form.confirmed ? `${error.message} Your card is saved with Stripe; try again to finish.` : error.message);
    } finally {
      busy(form, false);
    }
  };

  // The stack re-fetches itself on codewire:live:credit (#4762). A swap would
  // throw away a card being typed, a confirmed card not yet finished, or an
  // open dialog, so the refresh waits until none is in use, and runs once
  // then. An opened form with nothing typed in holds nothing (#4981), so one
  // left open doesn't keep the balance stale until a reload.
  let refreshOwed = false;
  const inUse = () => document.querySelector("dialog[open]") !== null ||
    [...document.querySelectorAll("[data-card-form]")].some((region) => {
      const form = forms.get(region);
      if (!form) return false;
      // A confirmed card waits for its finish wherever its form is; the form
      // under Add credit is in use while a card is typed in, the dialog's
      // while it's open.
      return Boolean(form.confirmed) || (!region.closest("dialog") && Boolean(form.typed) && !region.hidden);
    });
  const refresh = () => document.body.dispatchEvent(new CustomEvent("codewire:live:credit"));
  document.addEventListener("htmx:beforeRequest", (event) => {
    if (event.detail?.elt?.id !== "billing-stack" || !inUse()) return;
    event.preventDefault();
    refreshOwed = true;
  });
  const settle = () => {
    if (refreshOwed && !inUse()) {
      refreshOwed = false;
      refresh();
    }
  };
  document.addEventListener("close", settle, true);
  // A page restored from the back-forward cache may be stale.
  window.addEventListener("pageshow", (event) => { if (event.persisted) refresh(); });

  // A card's menu closes when one of its items opens a dialog.
  document.addEventListener("click", (event) => {
    const item = event.target instanceof Element ? event.target.closest(".cw-menu [data-dialog-open]") : null;
    item?.closest("details.cw-menu")?.removeAttribute("open");
  });

  // The Add card dialog mounts Stripe's form when it opens.
  const dialogForm = document.querySelector("form[data-card-dialog]");
  if (dialogForm) {
    const form = formOf(dialogForm);
    syncDialog(form);
    const dialog = dialogForm.closest("dialog");
    new MutationObserver(() => { if (dialog?.open) mount(form).catch(() => {}); })
      .observe(dialog, { attributes: true, attributeFilter: ["open"] });
    dialogForm.addEventListener("change", () => syncDialog(form));
    dialogForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (form.done) window.location.assign(form.done);
      else save(form);
    });
  }

  // Finishing the returned SetupIntent: billing applies only the choices it
  // stored at Begin, and only once.
  if (cardReturn) {
    const intent = returned.get("setup_intent") || "";
    if (returned.get("redirect_status") === "succeeded" && /^seti_[A-Za-z0-9]{1,64}$/.test(intent)) {
      post(setup.dataset.cardFinish, { setup_intent: intent })
        .then((answer) => {
          const next = safeLocation(answer.location);
          window.location.assign(next || `${window.location.pathname}?error=unavailable`);
        })
        .catch(() => window.location.assign(`${window.location.pathname}?error=card-unfinished`));
    } else {
      window.location.assign(`${window.location.pathname}?error=card-not-confirmed`);
    }
  }

  // With no card yet, Pay first opens Stripe's form under Add credit; the
  // next Pay saves the card and buys the credit with it.
  document.addEventListener("submit", (event) => {
    const owner = event.target;
    if (!(owner instanceof HTMLFormElement) || !owner.matches("form[data-add-credit-new-card]")) return;
    event.preventDefault();
    const region = document.getElementById(owner.dataset.addCreditNewCard);
    if (!region) return;
    const form = formOf(region);
    if (region.hidden) {
      region.hidden = false;
      mount(form).catch(() => {});
      return;
    }
    save(form);
  });
})();
