const app = document.querySelector("[data-dashboard-app]");

if (app) {
  const closeSidebar = () => app.setAttribute("data-mobile-open", "false");

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (target?.closest("[data-sidebar-toggle]")) {
      const open = app.getAttribute("data-mobile-open") === "true";
      app.setAttribute("data-mobile-open", String(!open));
      return;
    }
    if (target?.closest("[data-sidebar-close], .cw-mobile-drawer a")) {
      closeSidebar();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeSidebar();
  });
}
