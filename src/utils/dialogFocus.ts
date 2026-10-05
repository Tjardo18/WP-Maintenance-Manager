import type { ObjectDirective } from "vue";

const cleanups = new WeakMap<HTMLElement, () => void>();

/** Keep keyboard navigation inside an open dialog; leave unrelated keys alone. */
export const vDialogFocus: ObjectDirective<HTMLElement, () => void> = {
  mounted(element, binding) {
    const previous = document.activeElement;
    const controls = () => Array.from(element.querySelectorAll<HTMLElement>(
      'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex="0"]',
    )).filter((control) => !control.hidden && control.getAttribute("aria-hidden") !== "true");
    element.tabIndex = -1;
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); binding.value(); return; }
      if (event.key !== "Tab") return;
      const items = controls();
      const first = items[0]; const last = items[items.length - 1];
      if (!first || !last) { event.preventDefault(); element.focus(); return; }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === element)) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === element)) {
        event.preventDefault(); first.focus();
      }
    };
    element.addEventListener("keydown", keydown);
    (element.querySelector<HTMLElement>("[data-dialog-initial-focus]") ?? controls()[0] ?? element).focus();
    cleanups.set(element, () => {
      element.removeEventListener("keydown", keydown);
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    });
  },
  unmounted(element) { cleanups.get(element)?.(); cleanups.delete(element); },
};
