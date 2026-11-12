// Sign-up in two steps: the account (name, email, password), then the
// request (invite code, what you want to build, Turnstile). The form is one
// form; without script both steps show and its one button submits it.
(() => {
  "use strict";
  const form = document.querySelector("form[data-signup]");
  if (!form) return;
  const account = form.querySelector('[data-signup-step="1"]');
  const request = form.querySelector('[data-signup-step="2"]');
  const next = form.querySelector("[data-signup-next]");
  const back = form.querySelector("[data-signup-back]");
  const submit = form.querySelector('button[type="submit"]');
  const alternatives = document.querySelector(".cw-auth-alternatives");
  const password = form.querySelector("#password");
  const confirm = form.querySelector("#confirm-password");
  if (!account || !request || !next || !back || !submit) return;

  const show = (step) => {
    account.hidden = step !== 1;
    next.hidden = step !== 1;
    request.hidden = step !== 2;
    submit.hidden = step !== 2;
    back.hidden = step !== 2;
    if (alternatives) alternatives.hidden = step !== 1;
  };

  // The account step stays checked as the user types, so Continue reports
  // the first problem there instead of on a hidden field at submit.
  const matchPasswords = () => {
    if (password && confirm) {
      confirm.setCustomValidity(confirm.value && password.value !== confirm.value ? "The passwords don't match." : "");
    }
  };
  password?.addEventListener("input", matchPasswords);
  confirm?.addEventListener("input", matchPasswords);

  next.addEventListener("click", () => {
    matchPasswords();
    for (const field of account.querySelectorAll("input")) {
      if (!field.reportValidity()) return;
    }
    show(2);
    request.querySelector("input, textarea")?.focus();
  });
  back.addEventListener("click", () => {
    show(1);
    next.focus();
  });
  show(1);
})();
