const deviceCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";
const deviceCodeCharacter = (value) => {
  const character = value.toUpperCase();
  return character.length === 1 && deviceCodeAlphabet.includes(character) ? character : null;
};
const normalizeDeviceCode = (value) => {
  const candidate = value.trim().toUpperCase();
  const compact = candidate.length === 8
    ? candidate
    : /^.{4}-.{4}$/.test(candidate) ? candidate.replace("-", "") : "";
  return compact.length === 8 && Array.from(compact).every((character) => (
    deviceCodeAlphabet.includes(character)
  )) ? Array.from(compact) : null;
};

document.querySelectorAll("[data-device-code]").forEach((field) => {
  const inputs = Array.from(field.querySelectorAll("[data-device-code-slot]"))
    .filter((input) => input instanceof HTMLInputElement);
  if (inputs.length !== 8) return;

  const acceptedValues = inputs.map((input) => deviceCodeCharacter(input.value) || "");
  const setSlot = (index, value) => {
    inputs[index].value = value;
    acceptedValues[index] = value;
  };
  inputs.forEach((input, index) => { input.value = acceptedValues[index]; });

  // A complete one-time-code autofill must reach the input handler so it can
  // be distributed; ordinary typing is still reduced to one character below.
  inputs[0].removeAttribute("maxlength");

  const focusAt = (index) => {
    const input = inputs[Math.max(0, Math.min(index, inputs.length - 1))];
    input.focus();
    input.select();
  };

  const writeCharacters = (characters, requestedStart) => {
    const start = characters.length === inputs.length ? 0 : requestedStart;
    if (characters.length === inputs.length) {
      inputs.forEach((_, index) => setSlot(index, ""));
    }
    let index = start;
    for (const character of characters) {
      if (index >= inputs.length) break;
      setSlot(index, character);
      index += 1;
    }
    focusAt(index < inputs.length ? index : inputs.length - 1);
  };

  inputs.forEach((input, index) => {
    input.addEventListener("input", () => {
      const rawValue = input.value;
      if (rawValue === "") {
        setSlot(index, "");
        return;
      }
      const character = deviceCodeCharacter(rawValue);
      if (character) {
        setSlot(index, "");
        writeCharacters([character], index);
        return;
      }
      const characters = normalizeDeviceCode(rawValue);
      if (characters) {
        writeCharacters(characters, 0);
        return;
      }
      setSlot(index, acceptedValues[index]);
    });

    input.addEventListener("paste", (event) => {
      const characters = normalizeDeviceCode(event.clipboardData?.getData("text") || "");
      event.preventDefault();
      if (characters) writeCharacters(characters, 0);
    });

    input.addEventListener("keydown", (event) => {
      if (event.key === "-") {
        event.preventDefault();
      } else if (event.key === "Backspace" && input.value === "" && index > 0) {
        event.preventDefault();
        setSlot(index - 1, "");
        focusAt(index - 1);
      } else if (event.key === "ArrowLeft" && index > 0) {
        event.preventDefault();
        focusAt(index - 1);
      } else if (event.key === "ArrowRight" && index < inputs.length - 1) {
        event.preventDefault();
        focusAt(index + 1);
      }
    });

    input.addEventListener("focus", () => input.select());
  });
});
