(() => {
  const nextIndex = (container, selector, minimum = 0) => {
    let highest = minimum - 1;
    container.querySelectorAll(selector).forEach((row) => {
      row.querySelectorAll("[name]").forEach((field) => {
        const match = field.getAttribute("name")?.match(/_(\d+)$/);
        if (match) highest = Math.max(highest, Number(match[1]));
      });
    });
    return highest + 1;
  };

  const appendTemplateRow = (form, templateSelector, containerSelector, rowSelector, minimum = 0) => {
    const template = document.querySelector(templateSelector);
    const container = form.querySelector(containerSelector);
    if (!(template instanceof HTMLTemplateElement) || !container) return;
    const index = nextIndex(container, rowSelector, minimum);
    const fragment = template.content.cloneNode(true);
    fragment.querySelectorAll("[data-name-prefix]").forEach((field) => {
      const name = `${field.getAttribute("data-name-prefix")}${index}`;
      field.setAttribute("name", name);
      field.id = name.replaceAll("_", "-");
      const label = field.closest(".cw-field")?.querySelector("label");
      if (label instanceof HTMLLabelElement) label.htmlFor = field.id;
      field.removeAttribute("data-name-prefix");
    });
    container.querySelector("[data-empty-app-ports]")?.remove();
    container.append(fragment);
  };

  document.addEventListener("focusout", (event) => {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches("[data-ttl-input]")) return;
    const value = event.target.value.trim().toLocaleLowerCase();
    if (value === "" || value === "0" || value === "∞" || value === "infinity") {
      event.target.value = "infinity";
      return;
    }
    const duration = value.match(/^(\d+)\s*([smhd])$/);
    if (duration) event.target.value = `${duration[1]}${duration[2]}`;
  });

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-form]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.closest("[data-add-repository]")) {
      appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]", 100);
    } else if (event.target.closest("[data-remove-repository]")) {
      const rows = form.querySelectorAll("[data-repository-row]");
      if (rows.length > 1) event.target.closest("[data-repository-row]")?.remove();
    } else if (event.target.closest("[data-add-app-port]")) {
      appendTemplateRow(form, "[data-app-port-template]", "[data-app-port-rows]", "[data-app-port-row]");
    } else if (event.target.closest("[data-remove-app-port]")) {
      event.target.closest("[data-app-port-row]")?.remove();
    } else if (event.target.closest("[data-reset-workspace-image]")) {
      const image = form.querySelector('[name="image"]');
      if (image instanceof HTMLInputElement) image.value = "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff";
    }
  });
})();
