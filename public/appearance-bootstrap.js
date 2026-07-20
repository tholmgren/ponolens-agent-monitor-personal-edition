(() => {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem("ponolens-appearance") || "null") || {}; } catch {}
  document.documentElement.dataset.theme = saved.theme || "light";
  document.documentElement.dataset.fontSize = saved.fontSize || "regular";
})();
