// Runs the Random Forest exported by the Colab notebook (model/model.json) - no Python needed.
let cache = null;

export async function loadModel() {
  if (cache) return cache;
  const res = await fetch(chrome.runtime.getURL("model/model.json"));
  cache = await res.json();
  return cache;
}

// Probability (0..1) that the URL is phishing = average of the trees' leaf probabilities.
export function predictProba(model, features) {
  const x = model.feature_names.map((n) => Math.fround(features[n] ?? 0)); // sklearn compares in float32
  let sum = 0;
  for (const t of model.trees) {
    let i = 0;
    while (t.left[i] !== -1) i = x[t.feature[i]] <= t.threshold[i] ? t.left[i] : t.right[i];
    sum += t.p[i];
  }
  return sum / model.trees.length;
}
