document.addEventListener("DOMContentLoaded", () => {
  const dz = document.getElementById("dropzone"), inp = document.getElementById("file");
  const lbl = document.getElementById("fname"), btn = document.getElementById("upbtn");
  const show = () => {
    const f = inp.files[0];
    lbl.textContent = f ? "Selected: " + f.name + " (" + (f.size / 1024).toFixed(1) + " KB)" : "";
    btn.disabled = !f;
  };
  if (dz) {
    dz.addEventListener("click", () => inp.click());
    inp.addEventListener("click", e => e.stopPropagation());
    ["dragenter", "dragover"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave", "drop"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove("drag"); }));
    dz.addEventListener("drop", ev => { inp.files = ev.dataTransfer.files; show(); });
    inp.addEventListener("change", show);
    show();
  }
  const s = document.getElementById("search");
  if (s) s.addEventListener("input", () => {
    const q = s.value.toLowerCase();
    document.querySelectorAll(".file").forEach(r => { r.style.display = r.dataset.name.includes(q) ? "" : "none"; });
  });
  document.querySelectorAll("form.del").forEach(f =>
    f.addEventListener("submit", e => { if (!confirm("Delete this file permanently?")) e.preventDefault(); }));
  setTimeout(() => document.querySelectorAll(".toast").forEach(t => t.remove()), 4500);
});
