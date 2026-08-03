(() => {
  "use strict";

  const menuButton = document.querySelector(".cw-menu-toggle");
  const menu = document.querySelector(".cw-landing-links");
  if (menuButton instanceof HTMLButtonElement && menu instanceof HTMLElement) {
    const closeMenu = () => {
      menuButton.setAttribute("aria-expanded", "false");
      menu.classList.remove("is-open");
    };
    menuButton.addEventListener("click", () => {
      const expanded = menuButton.getAttribute("aria-expanded") === "true";
      menuButton.setAttribute("aria-expanded", String(!expanded));
      menu.classList.toggle("is-open", !expanded);
    });
    menu.addEventListener("click", (event) => {
      if (event.target instanceof HTMLAnchorElement) closeMenu();
    });
  }

  const tasks = Array.from(document.querySelectorAll("[data-task-index]"));
  const currentTask = document.querySelector("[data-current-task]");
  const colors = ["red", "cyan", "blue", "purple", "yellow"];
  let activeTask = 0;
  const renderTask = () => {
    tasks.forEach((task, index) => task.classList.toggle("is-active", index === activeTask));
    if (currentTask instanceof HTMLElement) {
      currentTask.textContent = String(activeTask + 1);
      colors.forEach((color) => currentTask.classList.remove(`cw-task--${color}`));
      currentTask.classList.add(`cw-task--${colors[activeTask]}`);
      currentTask.dataset.activeTask = String(activeTask);
    }
  };
  renderTask();
  if (tasks.length === colors.length && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    window.setInterval(() => {
      activeTask = (activeTask + 1) % colors.length;
      renderTask();
    }, 2500);
  }

  const waitlistForm = document.querySelector("[data-waitlist-form]");
  const waitlistStatus = document.querySelector("[data-waitlist-status]");
  if (waitlistForm instanceof HTMLFormElement && waitlistStatus instanceof HTMLElement) {
    waitlistForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const emailInput = waitlistForm.elements.namedItem("email");
      const submitButton = waitlistForm.querySelector("button[type='submit']");
      if (!(emailInput instanceof HTMLInputElement) || !emailInput.value) return;

      waitlistStatus.classList.remove("is-success");
      waitlistStatus.textContent = "";
      if (submitButton instanceof HTMLButtonElement) {
        submitButton.disabled = true;
        submitButton.textContent = "Joining…";
      }

      try {
        const response = await fetch("/api/v1/waitlist", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: emailInput.value }),
        });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(typeof body.error === "string" ? body.error : "Something went wrong");
        }
        waitlistStatus.classList.add("is-success");
        waitlistStatus.textContent = "You're on the list! We'll notify you when we're ready for you.";
        emailInput.value = "";
      } catch (error) {
        waitlistStatus.textContent = error instanceof Error ? error.message : "Something went wrong";
      } finally {
        if (submitButton instanceof HTMLButtonElement) {
          submitButton.disabled = false;
          submitButton.textContent = "Join waitlist →";
        }
      }
    });
  }
})();
