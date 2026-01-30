"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const obsidian_1 = require("obsidian");

const VIEW_TYPE = "ai-quiz-panel-view";

const DEFAULT_SETTINGS = {
  endpoint: "https://api.openai.com/v1/responses",
  model: "gpt-4.1-mini",
  temperature: 0.7,
  maxTokens: 6000,
  defaultDifficulty: "medium",
  defaultChoices: 4,
  defaultQuestionCount: 10,
  immediateFeedback: false,
  rememberPassword: false,
  customInstructions: "",
  defaultTypeMode: "mcq",
  defaultMatchPairs: 4,
  mixedRatios: { mcq: 40, tf: 20, fib: 20, match: 10, sata: 10 }
};

const AIQ_BLOCK_MARKERS = {
  PROMPTS: "AIQ_BLOCK_PROMPTS_v3",
  FLEX_PICK: "AIQ_BLOCK_FLEX_PICK_v2",
  GENERATE: "AIQ_BLOCK_GENERATE_v4",
  UI: "AIQ_BLOCK_UI_v3"
};

function uid() { return "qz_" + Math.random().toString(16).slice(2) + "_" + Date.now().toString(16); }
function nowISO() { return new Date().toISOString(); }

function clampInt(n, min, max, fallback) {
  const x = parseInt(String(n), 10);
  if (!Number.isFinite(x)) return fallback;
  return Math.max(min, Math.min(max, x));
}
function clampNum(n, min, max, fallback) {
  const x = Number(n);
  if (!Number.isFinite(x)) return fallback;
  return Math.max(min, Math.min(max, x));
}

function openAIApiKeysUrl() {
  return "https://platform.openai.com/settings/organization/api-keys";
}
function openAIApiKeysDescFragment() {
  const frag = document.createDocumentFragment();
  frag.append("Stored encrypted in plugin data. ");
  const a = document.createElement("a");
  a.href = openAIApiKeysUrl();
  a.textContent = "OpenAI API dashboard (create a key / sign up)";
  a.target = "_blank";
  a.rel = "noopener";
  frag.appendChild(a);
  frag.append(".");
  return frag;
}

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

function normalizeRatioPercents(r) {
  const keys = ["mcq", "tf", "fib", "match", "sata"];
  const base = { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
  for (const k of keys) base[k] = clampInt(r && r[k] !== undefined ? r[k] : 0, 0, 100, 0);
  const sum = keys.reduce((a, k) => a + base[k], 0);
  if (sum <= 0) return Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
  const raw = keys.map(k => ({ k, x: (base[k] / sum) * 100 }));
  const out = { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
  let used = 0;
  for (const r0 of raw) {
    const f = Math.floor(r0.x);
    out[r0.k] = f;
    used += f;
  }
  raw.sort((a, b) => (b.x - Math.floor(b.x)) - (a.x - Math.floor(a.x)));
  let i = 0;
  while (used < 100) {
    out[raw[i % raw.length].k] += 1;
    used += 1;
    i++;
  }
  while (used > 100) {
    const k = raw[raw.length - 1].k;
    if (out[k] > 0) { out[k] -= 1; used -= 1; }
    else break;
  }
  return out;
}

function ratiosToCounts(total, ratios) {
  const r = normalizeRatioPercents(ratios || DEFAULT_SETTINGS.mixedRatios);
  const weights = { mcq: r.mcq, tf: r.tf, fib: r.fib, match: r.match, sata: r.sata };
  return weightsToTargetCounts(weights, total);
}

function countsFromMode(total, typeMode, mixedRatios) {
  const n = clampInt(total, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
  const t = String(typeMode || "mcq");
  if (t === "mcq") return { mcq: n, tf: 0, fib: 0, match: 0, sata: 0 };
  if (t === "tf") return { mcq: 0, tf: n, fib: 0, match: 0, sata: 0 };
  if (t === "fib") return { mcq: 0, tf: 0, fib: n, match: 0, sata: 0 };
  if (t === "match") return { mcq: 0, tf: 0, fib: 0, match: n, sata: 0 };
  if (t === "sata") return { mcq: 0, tf: 0, fib: 0, match: 0, sata: n };
  return ratiosToCounts(n, mixedRatios || DEFAULT_SETTINGS.mixedRatios);
}

function randomizeMCQChoices(q) {
  const pairs = q.choices.map((text, idx) => ({ text, idx }));
  shuffleInPlace(pairs);
  const newChoices = pairs.map(p => p.text);
  const newAnswerIndex = pairs.findIndex(p => p.idx === q.answer_index);
  const newUserIndex = (q.user_answer_index === null || q.user_answer_index === undefined) ? null : pairs.findIndex(p => p.idx === q.user_answer_index);
  return Object.assign(Object.assign({}, q), { choices: newChoices, answer_index: Math.max(0, newAnswerIndex), user_answer_index: newUserIndex });
}

function randomizeSATAChoices(q) {
  const pairs = q.choices.map((text, idx) => ({ text, idx }));
  shuffleInPlace(pairs);
  const newChoices = pairs.map(p => p.text);
  const oldToNew = new Map();
  pairs.forEach((p, newIdx) => oldToNew.set(p.idx, newIdx));
  const ans = Array.isArray(q.answer_indices) ? q.answer_indices : [];
  const newAns = ans.map(oldIdx => {
    const n = oldToNew.get(oldIdx);
    return Number.isFinite(n) ? n : 0;
  }).filter(x => Number.isFinite(x));
  const uniqAns = Array.from(new Set(newAns)).sort((a, b) => a - b);
  const ua = Array.isArray(q.user_answer_indices) ? q.user_answer_indices : [];
  const newUA = ua.map(oldIdx => {
    const n = oldToNew.get(oldIdx);
    return Number.isFinite(n) ? n : null;
  }).filter(x => x !== null && x !== undefined && Number.isFinite(x));
  const uniqUA = Array.from(new Set(newUA)).sort((a, b) => a - b);
  return Object.assign(Object.assign({}, q), { choices: newChoices, answer_indices: uniqAns, user_answer_indices: uniqUA });
}

function randomizeMatchRightOnce(q) {
  const pairs = q.right.map((text, idx) => ({ text, idx }));
  shuffleInPlace(pairs);
  const newRight = pairs.map(p => p.text);
  const oldToNew = new Map();
  pairs.forEach((p, newIdx) => oldToNew.set(p.idx, newIdx));
  const newAnswerMap = q.answer_map.map(oldIdx => {
    const n = oldToNew.get(oldIdx);
    return Number.isFinite(n) ? n : 0;
  });
  const newUserMap = Array.isArray(q.user_map) ? q.user_map.map(oldIdx => {
    if (oldIdx === null || oldIdx === undefined) return null;
    const n = oldToNew.get(oldIdx);
    return Number.isFinite(n) ? n : null;
  }) : new Array(q.left.length).fill(null);
  return Object.assign(Object.assign({}, q), { right: newRight, answer_map: newAnswerMap, user_map: newUserMap });
}

function randomizeQuestion(q) {
  const t = String(q.type || "mcq");
  if (t === "mcq") return randomizeMCQChoices(q);
  if (t === "tf") return q;
  if (t === "fib") return q;
  if (t === "match") return q;
  if (t === "sata") return randomizeSATAChoices(q);
  return randomizeMCQChoices(q);
}

function randomizeQuestions(questions) {
  const qs = questions.map(randomizeQuestion);
  return shuffleInPlace(qs);
}

function normText(s) { return String(s || "").toLowerCase().replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim(); }
function tokenSet(s) { return new Set(normText(s).split(" ").filter(w => w.length >= 3)); }
function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const uni = a.size + b.size - inter;
  return uni ? inter / uni : 0;
}
function isNearDuplicate(qText, existingNormSet, existingTokenSets, threshold = 0.72) {
  const n = normText(qText);
  if (!n) return true;
  if (existingNormSet.has(n)) return true;
  const t = tokenSet(n);
  for (const ex of existingTokenSets) if (jaccard(t, ex) >= threshold) return true;
  return false;
}

function idxToLetters(i) {
  let n = Number.isFinite(i) ? Math.floor(i) : 0;
  if (n < 0) n = 0;
  n = n + 1;
  let s = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s || "A";
}

function b64FromBuf(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function bufFromB64(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer; }
function strToBuf(s) { return new TextEncoder().encode(s).buffer; }
function bufToStr(b) { return new TextDecoder().decode(new Uint8Array(b)); }
function rand(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }

function safeB64Text(s) {
  const t = String(s || "");
  try { return btoa(unescape(encodeURIComponent(t))); } catch { }
  try { return btoa(t); } catch { }
  return "";
}

function getHostNameSafe() {
  try {
    const os = require("os");
    if (os && typeof os.hostname === "function") return String(os.hostname() || "");
  } catch { }
  return "";
}

function getDeviceName() {
  const hn = getHostNameSafe();
  if (hn) return hn;
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) ? navigator.userAgent : "";
  const plat = (typeof navigator !== "undefined" && navigator.platform) ? navigator.platform : "";
  const lang = (typeof navigator !== "undefined" && navigator.language) ? navigator.language : "";
  const core = [ua, plat, lang].filter(Boolean).join(" | ");
  return (core || "unknown-device").slice(0, 240);
}

function getDeviceNameB64() {
  const b = safeB64Text(getDeviceName());
  const cleaned = b.replace(/[^A-Za-z0-9]/g, "_");
  return cleaned || "device";
}

function getDeviceId() {
  return getDeviceNameB64().slice(0, 80);
}

function getLocalStorageSafe() {
  try { return window.localStorage; } catch { return null; }
}

const LOCAL_DEVICE_KEY_STORAGE = "aiq_device_key_b64_v1";

function getLocalDeviceKeyB64(createIfMissing) {
  const ls = getLocalStorageSafe();
  if (!ls) return null;
  const cur = ls.getItem(LOCAL_DEVICE_KEY_STORAGE);
  if (cur && String(cur).trim()) return String(cur);
  if (!createIfMissing) return null;
  const nk = b64FromBuf(rand(32).buffer);
  try { ls.setItem(LOCAL_DEVICE_KEY_STORAGE, nk); } catch { }
  return nk;
}

const KDF_ITER = 250000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey("raw", strToBuf(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: KDF_ITER, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptWithPassword(obj, password) {
  const salt = rand(SALT_BYTES);
  const iv = rand(IV_BYTES);
  const key = await deriveKey(password, salt.buffer);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, strToBuf(JSON.stringify(obj)));
  return { v: 1, salt: b64FromBuf(salt.buffer), iv: b64FromBuf(iv.buffer), data: b64FromBuf(cipher) };
}
async function decryptWithPassword(blob, password) {
  const key = await deriveKey(password, bufFromB64(blob.salt));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(bufFromB64(blob.iv)) }, key, bufFromB64(blob.data));
  return JSON.parse(bufToStr(plain));
}
async function importDeviceKey(b64) { return crypto.subtle.importKey("raw", bufFromB64(b64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]); }

async function rememberPasswordEncrypt(password, deviceKeyB64, deviceNameB64) {
  const key = await importDeviceKey(deviceKeyB64);
  const iv = rand(IV_BYTES);
  const additionalData = new Uint8Array(strToBuf(String(deviceNameB64 || "")));
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, strToBuf(password));
  return { v: 1, device: String(deviceNameB64 || ""), iv: b64FromBuf(iv.buffer), data: b64FromBuf(enc) };
}
async function rememberPasswordDecrypt(payload, deviceKeyB64, deviceNameB64) {
  const expected = String(deviceNameB64 || "");
  const stored = String(payload?.device || "");
  if (expected && stored && expected !== stored) throw new Error("Remembered password is for a different device.");
  const key = await importDeviceKey(deviceKeyB64);
  const additionalData = new Uint8Array(strToBuf(stored || expected || ""));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(bufFromB64(payload.iv)), additionalData }, key, bufFromB64(payload.data));
  return bufToStr(dec);
}

function difficultySpec(level) {
  if (level === "easy") return ["EASY SPEC:", "- Direct recall; no inference.", "- Distractors obviously wrong.", "- Exactly one correct choice (except SATA)."].join("\n");
  if (level === "hard") return ["HARD SPEC:", "- Requires inference/connecting ideas.", "- Distractors plausible but false per text.", "- Exactly one correct choice (except SATA)."].join("\n");
  if (level === "very_hard") return ["VERY HARD SPEC:", "- Multi-step reasoning; connect distant parts.", "- Distractors highly plausible.", "- Still unambiguous.", "- Explanation cites the textual clue."].join("\n");
  return ["MEDIUM SPEC:", "- Understanding + paraphrase + cause/effect.", "- Distractors plausible but not tricky.", "- Exactly one correct choice (except SATA)."].join("\n");
}

function systemPrompt(customInstructions) {
  const base = ["You generate quizzes.", "Output ONLY valid json.", "No markdown. No commentary.", "Use ONLY the provided source text.", "Follow the required JSON shape exactly.", "Do not include any keys not requested.", "Explanations must not cite external knowledge."].join(" ");
  const extra = (customInstructions || "").trim();
  if (!extra) return base;
  return base + " " + "Additional instructions (must not override rules): " + extra;
}

function generateUserPromptV2(text, title, counts, diff, mcqChoicesCount, matchPairs, customInstructions, avoidQuestions) {
  const planLines = [];
  if (counts.mcq) planLines.push(`- mcq: ${counts.mcq} (choices: ${mcqChoicesCount})`);
  if (counts.tf) planLines.push(`- tf: ${counts.tf} (choices must be exactly ["True","False"])`);
  if (counts.fib) planLines.push(`- fib: ${counts.fib} (short literal answer_text)`);
  if (counts.match) planLines.push(`- match: ${counts.match} (pairs per question: ${matchPairs})`);
  if (counts.sata) planLines.push(`- sata: ${counts.sata} (select-all-that-apply; choices: ${mcqChoicesCount})`);
  const total = (counts.mcq || 0) + (counts.tf || 0) + (counts.fib || 0) + (counts.match || 0) + (counts.sata || 0);
  return [
    AIQ_BLOCK_MARKERS.PROMPTS,
    "Output format: json",
    "Return a valid json object only.",
    "",
    difficultySpec(diff),
    "",
    `Total questions target: ${total}`,
    "Question type targets (best effort):",
    ...planLines,
    title ? `Title preference: ${title}` : "",
    "",
    "Avoid repeating/paraphrasing these questions (write truly new ones):",
    ...((avoidQuestions && avoidQuestions.length) ? avoidQuestions.slice(-160).map(q => "- " + String(q).slice(0, 280)) : ["- (none)"]),
    "",
    "REQUIRED JSON SHAPE:",
    `{ "title": string, "questions": [` +
      ` { "type":"mcq", "q": string, "choices": string[], "answer_index": number, "explanation": string },` +
      ` { "type":"tf", "q": string, "answer_index": 0|1, "explanation": string },` +
      ` { "type":"fib", "q": string, "answer_text": string, "explanation": string },` +
      ` { "type":"match", "q": string, "left": string[], "right": string[], "answer_map": number[], "explanation": string },` +
      ` { "type":"sata", "q": string, "choices": string[], "answer_indices": number[], "explanation": string }` +
      ` ] }`,
    "",
    "Rules:",
    "- If you cannot meet the targets exactly, return as many valid questions as possible (do not refuse).",
    "- Exactly one correct answer for mcq/tf.",
    `- For mcq: choices.length must be exactly ${mcqChoicesCount}. Choices must be short phrases.`,
    `- For tf: answer_index must be 0 for True or 1 for False. Do NOT include choices; the app will enforce True/False.`,
    "- For fib: answer_text must be a short literal string (NOT a sentence). The question must be answerable from the source text.",
    `- For match: left.length MUST equal right.length and MUST be exactly ${matchPairs}.`,
    "- For match: answer_map.length must equal left.length; each answer_map[i] is the index in right that matches left[i].",
    "- For match: answer_map must be a permutation of 0..(N-1) with no repeats.",
    `- For sata: choices.length must be exactly ${mcqChoicesCount}.`,
    "- For sata: answer_indices must be an array of 2+ unique indices into choices (multiple correct).",
    "- explanation is 1-2 sentences and must reference the clue from the source text.",
    "",
    customInstructions && customInstructions.trim() ? "CUSTOM INSTRUCTIONS (rules win if conflict):" : "",
    customInstructions && customInstructions.trim() ? customInstructions.trim() : "",
    "",
    "SOURCE TEXT (only allowed knowledge):",
    text.trim()
  ].filter(Boolean).join("\n");
}

function extractOutputText(resp) {
  if (typeof (resp?.output_text) === "string" && resp.output_text.trim()) return resp.output_text;
  const out = resp?.output;
  if (!Array.isArray(out)) return "";
  for (const item of out) {
    if ((item?.type) === "message" && Array.isArray(item.content)) {
      for (const c of item.content) {
        if ((c?.type) === "output_text" && typeof c.text === "string" && c.text.trim()) return c.text;
        if (typeof (c?.text) === "string" && c.text.trim()) return c.text;
      }
    }
  }
  return "";
}

function repairJsonCommon(s) {
  return (s || "")
    .replace(/```(?:json)?/gi, "")
    .replace(/```/g, "")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/}\s*\n\s*\{/g, "},{")
    .replace(/\]\s*\n\s*\[/g, "],[")
    .replace(/,\s*([}\]])/g, "$1")
    .trim();
}

function findLastBalancedJsonEnd(s, start) {
  let inStr = false;
  let esc = false;
  let depth = 0;
  let lastEnd = null;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === "\\") { esc = true; continue; }
      if (ch === '"') { inStr = false; continue; }
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") {
      depth--;
      if (depth === 0) lastEnd = i;
    }
  }
  return lastEnd;
}

function looksTruncatedJson(s) {
  const t = (s || "").trim();
  if (!t) return true;
  if (!/[}\]]\s*$/.test(t)) return true;
  let inStr = false, esc = false;
  let depth = 0;
  for (let i = 0; i < t.length; i++) {
    const ch = t[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === "\\") { esc = true; continue; }
      if (ch === '"') { inStr = false; continue; }
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") depth--;
  }
  return depth !== 0;
}

function safeParseJson(text) {
  const raw = (text || "").trim();
  if (!raw) throw new Error("Empty model output.");
  const cleaned = repairJsonCommon(raw);
  try { return JSON.parse(cleaned); } catch { }
  const o = cleaned.indexOf("{");
  const a = cleaned.indexOf("[");
  const start = o >= 0 && (a < 0 || o < a) ? o : a;
  if (start < 0) throw new Error("Model output was not JSON.");
  const end = findLastBalancedJsonEnd(cleaned, start);
  if (end !== null) {
    const candidate = repairJsonCommon(cleaned.slice(start, end + 1));
    try { return JSON.parse(candidate); } catch { }
  }
  const tail = repairJsonCommon(cleaned.slice(start));
  try { return JSON.parse(tail); }
  catch (e) {
    const msg = String((e?.message) || e || "Unknown JSON parse error");
    if (looksTruncatedJson(tail)) throw new Error("Model returned truncated/invalid JSON. Increase Max Output Tokens or reduce question count.");
    throw new Error("Model output was not valid JSON: " + msg);
  }
}

function recommendedMaxOutputTokens(questionCount) {
  const qc = clampInt(questionCount, 1, 80, 10);
  const est = 900 + qc * 260;
  return Math.max(1500, Math.min(20000, est));
}

function normAnswer(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeMCQ(q, choicesCount) {
  const qq = String(q?.q || "").trim();
  const choices = Array.isArray(q?.choices) ? q.choices.map((x) => String(x).trim()).filter(Boolean) : [];
  let ai = Number.isFinite(q?.answer_index) ? q.answer_index : parseInt(String(q?.answer_index), 10);
  if (!qq) throw new Error("Bad model output: missing question text.");
  if (choices.length !== choicesCount) throw new Error(`Bad model output: choices must be exactly ${choicesCount}.`);
  if (!Number.isFinite(ai)) ai = 0;
  ai = Math.max(0, Math.min(choices.length - 1, ai));
  return {
    id: uid(),
    type: "mcq",
    q: qq,
    choices,
    answer_index: ai,
    explanation: String(q?.explanation || "").trim(),
    user_answer_index: null
  };
}

function normalizeTF(q) {
  const qq = String(q?.q || "").trim();
  let ai = Number.isFinite(q?.answer_index) ? q.answer_index : parseInt(String(q?.answer_index), 10);
  if (!qq) throw new Error("Bad model output: missing question text.");
  ai = (ai === 1) ? 1 : 0;
  return {
    id: uid(),
    type: "tf",
    q: qq,
    choices: ["True", "False"],
    answer_index: ai,
    explanation: String(q?.explanation || "").trim(),
    user_answer_index: null
  };
}

function normalizeFIB(q) {
  const qq = String(q?.q || "").trim();
  const ans = String(q?.answer_text || "").trim();
  if (!qq) throw new Error("Bad model output: missing question text.");
  if (!ans) throw new Error("Bad model output: missing answer_text for fib.");
  return {
    id: uid(),
    type: "fib",
    q: qq,
    answer_text: ans,
    explanation: String(q?.explanation || "").trim(),
    user_answer_text: null
  };
}

function isPermutation0N(arr, n) {
  if (!Array.isArray(arr) || arr.length !== n) return false;
  const seen = new Set();
  for (const x of arr) {
    const k = Number.isFinite(x) ? x : parseInt(String(x), 10);
    if (!Number.isFinite(k)) return false;
    if (k < 0 || k >= n) return false;
    if (seen.has(k)) return false;
    seen.add(k);
  }
  return seen.size === n;
}

function normalizeMATCH(q, matchPairs) {
  const qq = String(q?.q || "").trim();
  const left = Array.isArray(q?.left) ? q.left.map(x => String(x).trim()).filter(Boolean) : [];
  const right = Array.isArray(q?.right) ? q.right.map(x => String(x).trim()).filter(Boolean) : [];
  const amapRaw = Array.isArray(q?.answer_map) ? q.answer_map : [];
  if (!qq) throw new Error("Bad model output: missing question text.");
  if (left.length !== matchPairs || right.length !== matchPairs) throw new Error(`Bad model output: match left/right must be exactly ${matchPairs} items.`);
  const amap = amapRaw.map(x => Number.isFinite(x) ? x : parseInt(String(x), 10));
  if (!isPermutation0N(amap, matchPairs)) throw new Error("Bad model output: match answer_map must be a permutation of 0..N-1.");
  const base = {
    id: uid(),
    type: "match",
    q: qq,
    left,
    right,
    answer_map: amap,
    explanation: String(q?.explanation || "").trim(),
    user_map: new Array(matchPairs).fill(null)
  };
  return randomizeMatchRightOnce(base);
}

function normalizeSATA(q, choicesCount) {
  const qq = String(q?.q || "").trim();
  const choices = Array.isArray(q?.choices) ? q.choices.map(x => String(x).trim()).filter(Boolean) : [];
  const raw = (q?.answer_indices) !== undefined ? q.answer_indices : (q?.answer_index);
  const arr = Array.isArray(raw) ? raw : (raw === null || raw === undefined ? [] : [raw]);
  const idxs = arr.map(x => Number.isFinite(x) ? x : parseInt(String(x), 10)).filter(x => Number.isFinite(x));
  const uniq = Array.from(new Set(idxs)).filter(x => x >= 0 && x < choicesCount).sort((a, b) => a - b);
  if (!qq) throw new Error("Bad model output: missing question text.");
  if (choices.length !== choicesCount) throw new Error(`Bad model output: choices must be exactly ${choicesCount}.`);
  if (!uniq.length) throw new Error("Bad model output: sata answer_indices missing/invalid.");
  return {
    id: uid(),
    type: "sata",
    q: qq,
    choices,
    answer_indices: uniq,
    explanation: String(q?.explanation || "").trim(),
    user_answer_indices: []
  };
}

function normalizeAnyQuestion(raw, mcqChoicesCount, matchPairs) {
  const t = String((raw?.type) || "mcq").toLowerCase();
  if (t === "tf") return normalizeTF(raw);
  if (t === "fib") return normalizeFIB(raw);
  if (t === "match") return normalizeMATCH(raw, matchPairs);
  if (t === "sata") return normalizeSATA(raw, mcqChoicesCount);
  return normalizeMCQ(raw, mcqChoicesCount);
}

function arraysEqualSet(a, b) {
  const aa = Array.isArray(a) ? a.slice().sort((x, y) => x - y) : [];
  const bb = Array.isArray(b) ? b.slice().sort((x, y) => x - y) : [];
  if (aa.length !== bb.length) return false;
  for (let i = 0; i < aa.length; i++) if (aa[i] !== bb[i]) return false;
  return true;
}

function computeGrade(quiz) {
  const total = quiz.questions.length;
  let answered = 0;
  let correct = 0;
  const per = quiz.questions.map((q) => {
    const t = String(q.type || "mcq");
    if (t === "fib") {
      const ua = q.user_answer_text;
      const isAnswered = ua !== null && ua !== undefined && String(ua).trim().length > 0;
      if (isAnswered) answered++;
      const isCorrect = isAnswered && (normAnswer(ua) === normAnswer(q.answer_text));
      if (isCorrect) correct++;
      return { isAnswered, isCorrect };
    }
    if (t === "match") {
      const um = Array.isArray(q.user_map) ? q.user_map : [];
      const isAnswered = um.length === q.left.length && um.every(x => x !== null && x !== undefined && Number.isFinite(x));
      if (isAnswered) answered++;
      let ok = false;
      if (isAnswered) {
        ok = true;
        for (let i = 0; i < q.answer_map.length; i++) {
          if (um[i] !== q.answer_map[i]) { ok = false; break; }
        }
      }
      if (ok) correct++;
      return { isAnswered, isCorrect: ok };
    }
    if (t === "sata") {
      const ua = Array.isArray(q.user_answer_indices) ? q.user_answer_indices : [];
      const isAnswered = ua.length > 0;
      if (isAnswered) answered++;
      const ok = isAnswered && arraysEqualSet(ua, q.answer_indices);
      if (ok) correct++;
      return { isAnswered, isCorrect: ok };
    }
    const ua = q.user_answer_index;
    const isAnswered = ua !== null && ua !== undefined;
    if (isAnswered) answered++;
    const isCorrect = isAnswered && ua === q.answer_index;
    if (isCorrect) correct++;
    return { isAnswered, isCorrect, ua: isAnswered ? ua : null, ca: q.answer_index };
  });
  const accuracyAnswered = answered ? Math.round((correct / answered) * 100) : 0;
  const accuracyTotal = total ? Math.round((correct / total) * 100) : 0;
  return { total, answered, correct, accuracyAnswered, accuracyTotal, per };
}

function weightsToTargetCounts(weights, total) {
  const keys = ["mcq", "tf", "fib", "match", "sata"];
  const w = {};
  let sum = 0;
  for (const k of keys) {
    const val = Math.max(0, Number(weights && weights[k] !== undefined ? weights[k] : 0));
    w[k] = Number.isFinite(val) ? val : 0;
    sum += w[k];
  }
  if (sum <= 0) return { mcq: total, tf: 0, fib: 0, match: 0, sata: 0 };
  const raw = keys.map(k => ({ k, x: (w[k] / sum) * total }));
  const out = { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
  let used = 0;
  for (const r of raw) {
    const f = Math.floor(r.x);
    out[r.k] = f;
    used += f;
  }
  raw.sort((a, b) => (b.x - Math.floor(b.x)) - (a.x - Math.floor(a.x)));
  let i = 0;
  while (used < total) {
    out[raw[i % raw.length].k] += 1;
    used += 1;
    i++;
  }
  return out;
}

function pickFromBucketsFlexible(buckets, desiredCountsOrWeights, targetTotal) {
  const keys = ["mcq", "tf", "fib", "match", "sata"];
  const available = {};
  let availableTotal = 0;
  for (const k of keys) {
    available[k] = Array.isArray(buckets[k]) ? buckets[k].length : 0;
    availableTotal += available[k];
  }
  if (!availableTotal) return { picked: [], pickedCounts: { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 }, targetTotal: 0 };

  const wantTotal = clampInt(targetTotal, 1, 80, 10);
  const finalTarget = Math.min(wantTotal, availableTotal);

  const desiredTotal = (desiredCountsOrWeights.mcq || 0) + (desiredCountsOrWeights.tf || 0) + (desiredCountsOrWeights.fib || 0) + (desiredCountsOrWeights.match || 0) + (desiredCountsOrWeights.sata || 0);
  const weights = desiredTotal > 0 ? desiredCountsOrWeights : { mcq: 1, tf: 0, fib: 0, match: 0, sata: 0 };

  let plan = weightsToTargetCounts(weights, finalTarget);
  for (const k of keys) plan[k] = Math.min(plan[k], available[k]);

  let plannedSum = keys.reduce((a, k) => a + plan[k], 0);
  let deficit = finalTarget - plannedSum;

  const weightOrder = keys
    .map(k => ({ k, w: Math.max(0, Number(weights[k] || 0)) }))
    .sort((a, b) => b.w - a.w)
    .map(x => x.k);

  let guard = 0;
  while (deficit > 0 && guard < 600) {
    guard++;
    let added = false;
    for (const k of weightOrder) {
      if (plan[k] < available[k]) {
        plan[k] += 1;
        deficit -= 1;
        added = true;
        if (deficit <= 0) break;
      }
    }
    if (!added) break;
  }

  const picked = [];
  const pickedCounts = { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
  for (const k of keys) {
    const take = Math.max(0, Math.min(plan[k], available[k]));
    for (let i = 0; i < take; i++) picked.push(buckets[k][i]);
    pickedCounts[k] = take;
  }

  return { picked, pickedCounts, targetTotal: finalTarget };
}

class UnlockModal extends obsidian_1.Modal {
  constructor(app, plugin, mode, done) {
    super(app);
    this.plugin = plugin;
    this.mode = mode;
    this.done = done;
    this.resolved = false;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "AI Quiz Generator" });
    contentEl.createEl("div", { text: this.mode === "setup" ? "Set master password" : "Enter master password to unlock", cls: "aiq-muted aiq-subtitle" });
    contentEl.createEl("div", { text: "This encrypts plugin data stored locally (data.json).", cls: "aiq-muted" });

    const wrap = contentEl.createDiv({ cls: "aiq-grid aiq-grid-2" });
    const f1 = wrap.createDiv({ cls: "aiq-field" });
    f1.createEl("label", { text: "Master password" });
    this.passEl = f1.createEl("input", { type: "password" });

    const f2 = wrap.createDiv({ cls: "aiq-field" });
    f2.createEl("label", { text: "Confirm (setup only)" });
    this.pass2El = f2.createEl("input", { type: "password" });
    if (this.mode !== "setup") f2.hide();

    const row = contentEl.createDiv({ cls: "aiq-row" });
    const left = row.createDiv({ cls: "aiq-row-left" });
    const right = row.createDiv({ cls: "aiq-row-right" });

    const rememberWrap = left.createEl("label", { cls: "aiq-muted" });
    this.rememberEl = rememberWrap.createEl("input", { type: "checkbox" });
    rememberWrap.appendText(" Remember password on this device (convenience; weak security)");

    const cancelBtn = right.createEl("button", { text: "Cancel", cls: "aiq-btn" });
    cancelBtn.onclick = () => {
      if (!this.resolved) { this.resolved = true; this.done(false); }
      this.close();
    };

    const btn = right.createEl("button", { text: this.mode === "setup" ? "Create" : "Unlock", cls: "aiq-btn aiq-btn-primary" });
    btn.onclick = async () => {
      try {
        this.setStatus("Working...");
        const p1 = this.passEl.value.trim();
        if (!p1) throw new Error("Password required.");
        if (this.mode === "setup") {
          const p2 = this.pass2El.value.trim();
          if (!p2) throw new Error("Confirm password.");
          if (p1 !== p2) throw new Error("Passwords do not match.");
        }
        await this.plugin.unlockWithPassword(p1, this.mode === "setup", this.rememberEl.checked);
        this.close();
      } catch (e) {
        this.setStatus((e?.message) || "Unlock failed.", true);
      }
    };

    this.statusEl = contentEl.createDiv({ cls: "aiq-status" });
  }
  onClose() {
    if (!this.resolved) { this.resolved = true; this.done(false); }
  }
  setStatus(msg, err = false) {
    this.statusEl.setText(msg);
    this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
  }
}

class SettingsModal extends obsidian_1.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "AI Quiz Settings" });

    if (!this.plugin.vaultPlain) {
      contentEl.createEl("div", { text: "Locked. Set or enter your master password first.", cls: "aiq-muted" });
      const row = contentEl.createDiv({ cls: "aiq-topbar" });
      const btn = row.createEl("button", { text: this.plugin.encrypted ? "Unlock" : "Set Master Password", cls: "aiq-btn aiq-btn-primary" });
      btn.onclick = async () => {
        try {
          await this.plugin.ensureUnlocked();
          this.close();
          new SettingsModal(this.app, this.plugin).open();
        } catch (e) {
          new obsidian_1.Notice((e?.message) || "Locked.");
        }
      };
      return;
    }

    const v = this.plugin.vaultPlain;
    const s = v.settings;

    if (!s.mixedRatios) s.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
    s.mixedRatios = normalizeRatioPercents(s.mixedRatios);
    if (!s.defaultQuestionCount) s.defaultQuestionCount = DEFAULT_SETTINGS.defaultQuestionCount;

    const mkSection = (title, desc) => {
      const sec = contentEl.createDiv({ cls: "aiq-card aiq-settings-section" });
      sec.createEl("div", { text: title, cls: "aiq-qtext" });
      if (desc) sec.createEl("div", { text: desc, cls: "aiq-muted" });
      return sec;
    };

    const apiSec = mkSection("API & Model", "Controls which model is called and how the request is sent.");
    new obsidian_1.Setting(apiSec)
      .setName("OpenAI API key")
      .setDesc(openAIApiKeysDescFragment())
      .addText(t => t.setPlaceholder("sk-...").setValue(v.apiKey || "").onChange(async (val) => {
        v.apiKey = val.trim();
        await this.plugin.saveEncrypted();
      }));

    new obsidian_1.Setting(apiSec)
      .setName("Model")
      .setDesc("Higher models are usually smarter but slower/more expensive.")
      .addDropdown(d => {
        d.addOption("gpt-4.1-mini", "gpt-4.1-mini (default)");
        d.addOption("gpt-4.1-nano", "gpt-4.1-nano (fast/cheap)");
        d.addOption("gpt-5-mini", "gpt-5-mini");
        d.addOption("gpt-5-nano", "gpt-5-nano (fastest)");
        d.addOption("gpt-5.2", "gpt-5.2 (best)");
        d.addOption("o4-mini", "o4-mini (reasoning)");
        d.setValue(s.model || "gpt-4.1-mini");
        d.onChange(async (val) => { s.model = val; await this.plugin.saveEncrypted(); this.plugin.view?.render(); });
      });

    new obsidian_1.Setting(apiSec)
      .setName("Temperature")
      .setDesc("Lower = more consistent; higher = more variety.")
      .addSlider(sl => {
        sl.setLimits(0, 2, 0.1);
        sl.setValue(s.temperature ?? 0.7);
        sl.setDynamicTooltip();
        sl.onChange(async (val) => { s.temperature = val; await this.plugin.saveEncrypted(); });
      });

    let maxTokText = null;
    const maxTokSetting = new obsidian_1.Setting(apiSec)
      .setName("Max output tokens")
      .setDesc("If you get truncated JSON errors, increase this (or lower question count).")
      .addText(t => {
        maxTokText = t;
        t.setValue(String(s.maxTokens ?? 6000));
        t.onChange(async (val) => {
          s.maxTokens = clampInt(val, 256, 20000, 6000);
          await this.plugin.saveEncrypted();
        });
      })
      .addButton(b => {
        b.setButtonText("Set recommended");
        b.onClick(async () => {
          s.maxTokens = recommendedMaxOutputTokens(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount);
          if (maxTokText) maxTokText.setValue(String(s.maxTokens));
          await this.plugin.saveEncrypted();
          updateRecs();
        });
      });

    new obsidian_1.Setting(apiSec)
      .setName("Endpoint")
      .setDesc("Defaults to OpenAI Responses API. Change only if you know what you’re doing.")
      .addText(t => t.setValue(s.endpoint || DEFAULT_SETTINGS.endpoint).onChange(async (val) => {
        s.endpoint = val.trim() || DEFAULT_SETTINGS.endpoint;
        await this.plugin.saveEncrypted();
      }));

    const genSec = mkSection("Generation Defaults", "These settings drive Generate and Add Questions unless a quiz already pins values.");
    const recLine = genSec.createDiv({ cls: "aiq-muted" });

    const updateRecs = () => {
      const qc = clampInt(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
      const rec = recommendedMaxOutputTokens(qc);
      recLine.setText(`Tip: For ${qc} questions, a good starting Max output tokens is ~${rec}.`);
    };

    new obsidian_1.Setting(genSec)
      .setName("Default total questions")
      .setDesc("Used by Generate. Larger quizzes often require higher Max output tokens.")
      .addText(t => t.setValue(String(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount)).onChange(async (val) => {
        s.defaultQuestionCount = clampInt(val, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
        await this.plugin.saveEncrypted();
        this.plugin.view?.render();
        updateRecs();
      }));

    new obsidian_1.Setting(genSec)
      .setName("Default difficulty")
      .setDesc("Controls how direct vs. inferential questions are.")
      .addDropdown(d => {
        d.addOption("easy", "easy");
        d.addOption("medium", "medium");
        d.addOption("hard", "hard");
        d.addOption("very_hard", "very hard");
        d.setValue(s.defaultDifficulty || "medium");
        d.onChange(async (val) => { s.defaultDifficulty = val; await this.plugin.saveEncrypted(); this.plugin.view?.render(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default question type mode")
      .setDesc("Pick a single type, or use Mixed (ratios below).")
      .addDropdown(d => {
        d.addOption("mcq", "MCQ only");
        d.addOption("tf", "True/False only");
        d.addOption("fib", "Fill in the blank only");
        d.addOption("match", "Matching only");
        d.addOption("sata", "Select all that apply only");
        d.addOption("mixed", "Mixed (ratios from Settings)");
        d.setValue(s.defaultTypeMode || "mcq");
        d.onChange(async (val) => { s.defaultTypeMode = val; await this.plugin.saveEncrypted(); this.plugin.view?.render(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default MCQ choices")
      .setDesc("How many choices each multiple choice question has.")
      .addDropdown(d => {
        ["3", "4", "5", "6", "7", "8"].forEach(x => d.addOption(x, x));
        d.setValue(String(s.defaultChoices ?? 4));
        d.onChange(async (val) => { s.defaultChoices = clampInt(val, 3, 8, 4); await this.plugin.saveEncrypted(); this.plugin.view?.render(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default match pairs per question")
      .setDesc("Matching questions show N items on the left and N on the right.")
      .addText(t => t.setValue(String(s.defaultMatchPairs ?? 4)).onChange(async (val) => {
        s.defaultMatchPairs = clampInt(val, 3, 8, 4);
        await this.plugin.saveEncrypted();
        this.plugin.view?.render();
      }));

    updateRecs();

    const ratiosSec = mkSection("Mixed Mode Ratios", "Used only when Type Mode = Mixed. Must sum to 100%.");
    const sumEl = ratiosSec.createDiv({ cls: "aiq-muted" });

    const ratioInputs = {};
    const updateSumEl = () => {
      const r = normalizeRatioPercents(s.mixedRatios);
      const sum = (r.mcq || 0) + (r.tf || 0) + (r.fib || 0) + (r.match || 0) + (r.sata || 0);
      sumEl.setText(`Current: MCQ ${r.mcq}% • TF ${r.tf}% • FIB ${r.fib}% • MATCH ${r.match}% • SATA ${r.sata}% (sum ${sum}%)`);
    };

    const setRatios = async (key, val) => {
      const cur = Object.assign({}, s.mixedRatios || DEFAULT_SETTINGS.mixedRatios);
      cur[key] = clampInt(val, 0, 100, 0);
      const norm = normalizeRatioPercents(cur);
      s.mixedRatios = norm;
      for (const k of ["mcq", "tf", "fib", "match", "sata"]) {
        if (ratioInputs[k]) ratioInputs[k].setValue(String(norm[k] || 0));
      }
      updateSumEl();
      await this.plugin.saveEncrypted();
      this.plugin.view?.render();
    };

    const mkRatio = (name, key) => {
      new obsidian_1.Setting(ratiosSec)
        .setName(name)
        .setDesc("Percent of total questions in Mixed mode.")
        .addText(t => {
          ratioInputs[key] = t;
          t.setValue(String(s.mixedRatios[key] || 0));
          t.onChange(async (v0) => { await setRatios(key, v0); });
        });
    };

    mkRatio("MCQ %", "mcq");
    mkRatio("True/False %", "tf");
    mkRatio("Fill in the blank %", "fib");
    mkRatio("Matching %", "match");
    mkRatio("Select all that apply %", "sata");
    updateSumEl();

    const promptSec = mkSection("Prompting", "These instructions are appended to every generation request.");
    const ciSetting = new obsidian_1.Setting(promptSec)
      .setName("Custom instructions (optional)")
      .setDesc("Example: focus on definitions and key claims. Keep explanations concise.");
    ciSetting.settingEl.addClass("aiq-setting-textarea");
    ciSetting.addTextArea(t => {
      t.setPlaceholder("Example: Focus on definitions and key claims. Keep explanations concise.");
      t.setValue(s.customInstructions || "");
      t.inputEl.addClass("aiq-custom-instructions");
      t.inputEl.style.resize = "vertical";
      t.onChange(async (val) => {
        s.customInstructions = val;
        await this.plugin.saveEncrypted();
      });
    });

    const behaviorSec = mkSection("Behavior", "How the quiz UI behaves while you answer.");
    new obsidian_1.Setting(behaviorSec)
      .setName("Immediate feedback")
      .setDesc("If enabled: show correctness after selecting/submitting input. Otherwise only show after Submit Quiz.")
      .addToggle(tg => tg.setValue(!!s.immediateFeedback).onChange(async (val) => {
        s.immediateFeedback = val;
        await this.plugin.saveEncrypted();
        this.plugin.view?.render();
      }));

    const securitySec = mkSection("Security", "Password and encryption-related convenience settings.");
    new obsidian_1.Setting(securitySec)
      .setName("Remember password on this device")
      .setDesc("Convenience only. Stored per-device; sync won’t break other devices. Turning off removes the remembered entry for this device.")
      .addToggle(tg => tg.setValue(!!s.rememberPassword).onChange(async (val) => {
        s.rememberPassword = val;
        await this.plugin.saveEncrypted();
      }));

    const advSec = mkSection("Advanced", "Reset everything back to defaults (API key not cleared).");
    new obsidian_1.Setting(advSec)
      .setName("Reset settings to defaults")
      .setDesc("Resets settings values (not quizzes). API key stays as-is.")
      .addButton(b => {
        b.setButtonText("Reset");
        b.setWarning();
        b.onClick(async () => {
          const ok = window.confirm("Reset all AI Quiz settings to defaults? This does not delete quizzes.");
          if (!ok) return;
          const keepApiKey = v.apiKey;
          v.settings = Object.assign({}, DEFAULT_SETTINGS);
          v.apiKey = keepApiKey;
          if (!v.settings.mixedRatios) v.settings.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
          v.settings.mixedRatios = normalizeRatioPercents(v.settings.mixedRatios);
          await this.plugin.saveEncrypted();
          this.close();
          new SettingsModal(this.app, this.plugin).open();
        });
      });
  }
}

class RenameQuizModal extends obsidian_1.Modal {
  constructor(app, plugin, quiz, onRenamed) {
    super(app);
    this.plugin = plugin;
    this.quiz = quiz;
    this.onRenamed = onRenamed;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Rename quiz" });
    let next = this.quiz.title || "";
    new obsidian_1.Setting(contentEl)
      .setName("New title")
      .addText(t => {
        t.setValue(next);
        window.setTimeout(() => { t.inputEl.focus(); t.inputEl.select(); }, 1);
        t.onChange(v => { next = v; });
        t.inputEl.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter") { ev.preventDefault(); void doSave(); }
        });
      });
    const actions = contentEl.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
    const saveBtn = actions.createEl("button", { text: "Save", cls: "aiq-btn aiq-btn-primary" });
    const cancelBtn = actions.createEl("button", { text: "Cancel", cls: "aiq-btn" });
    const doSave = async () => {
      try {
        const trimmed = (next || "").trim();
        if (!trimmed) throw new Error("Title can't be empty.");
        this.quiz.title = trimmed;
        this.quiz.updated_at = nowISO();
        await this.plugin.saveEncrypted();
        this.onRenamed();
        this.close();
      } catch (e) {
        this.setStatus((e?.message) || "Rename failed.", true);
      }
    };
    saveBtn.onclick = () => { void doSave(); };
    cancelBtn.onclick = () => this.close();
    this.statusEl = contentEl.createDiv({ cls: "aiq-status" });
  }
  setStatus(msg, err = false) {
    this.statusEl.setText(msg);
    this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
  }
}

class AddQuestionsModal extends obsidian_1.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Add questions" });
    contentEl.createEl("div", { text: "Generate additional questions for the currently loaded quiz (no repeats). Uses your current Settings.", cls: "aiq-muted" });

    const grid = contentEl.createDiv({ cls: "aiq-grid aiq-grid-2" });
    const f1 = grid.createDiv({ cls: "aiq-field" });
    f1.createEl("label", { text: "How many?" });
    this.countEl = f1.createEl("input", { type: "number" });
    this.countEl.value = "5";
    this.countEl.min = "1";
    this.countEl.max = "80";

    const actions = contentEl.createDiv({ cls: "aiq-row" });
    actions.createDiv({ cls: "aiq-row-left" });
    const right = actions.createDiv({ cls: "aiq-row-right" });
    const cancel = right.createEl("button", { text: "Cancel", cls: "aiq-btn" });
    cancel.onclick = () => this.close();
    const go = right.createEl("button", { text: "Generate", cls: "aiq-btn aiq-btn-primary" });
    go.onclick = async () => {
      try {
        go.disabled = true;
        cancel.disabled = true;
        this.setStatus("Working...");
        const n = clampInt(this.countEl.value, 1, 80, 5);
        await this.plugin.addMoreQuestionsToCurrentQuiz(n);
        this.close();
      } catch (e) {
        this.setStatus((e?.message) || "Failed.", true);
      } finally {
        go.disabled = false;
        cancel.disabled = false;
      }
    };
    this.statusEl = contentEl.createDiv({ cls: "aiq-status" });
  }
  setStatus(msg, err = false) {
    this.statusEl.setText(msg);
    this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
  }
}

class LibraryModal extends obsidian_1.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    this.modalEl.addClass("aiq-modal-full");
    const { contentEl } = this;
    const v = this.plugin.vaultPlain;
    const render = () => {
      contentEl.empty();
      contentEl.createEl("h2", { text: "Saved Quizzes" });
      const list = contentEl.createDiv({ cls: "aiq-grid" });
      const quizzes = [...v.quizzes].sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
      if (!quizzes.length) { list.createEl("div", { text: "No quizzes yet.", cls: "aiq-muted" }); return; }
      for (const q of quizzes) {
        const card = list.createDiv({ cls: "aiq-card" });
        card.createEl("div", { text: q.title, cls: "aiq-qtext" });
        card.createEl("div", { text: `${q.questions.length} Q • ${q.difficulty} • ${q.submitted ? "submitted" : "in progress"}`, cls: "aiq-muted" });
        const row = card.createDiv({ cls: "aiq-topbar aiq-card-actions" });
        const loadBtn = row.createEl("button", { text: "Load", cls: "aiq-btn aiq-btn-primary" });
        loadBtn.onclick = async () => { this.plugin.setCurrentQuiz(q.id); await this.plugin.openView("quiz"); this.close(); };
        const renameBtn = row.createEl("button", { text: "Rename", cls: "aiq-btn" });
        renameBtn.onclick = () => { new RenameQuizModal(this.app, this.plugin, q, () => render()).open(); };
        const copyBtn = row.createEl("button", { text: "Copy", cls: "aiq-btn" });
        copyBtn.onclick = async () => {
          this.plugin.copyQuiz(q.id);
          await this.plugin.saveEncrypted();
          new obsidian_1.Notice("Copied.");
          this.close();
          await this.plugin.openView("quiz");
        };
        const delBtn = row.createEl("button", { text: "Delete", cls: "aiq-btn aiq-btn-danger" });
        delBtn.onclick = async () => {
          const ok = window.confirm(`Delete "${q.title}"?`);
          if (!ok) return;
          this.plugin.deleteQuiz(q.id);
          await this.plugin.saveEncrypted();
          new obsidian_1.Notice("Deleted.");
          render();
        };
      }
    };
    render();
  }
}

class GenerateModal extends obsidian_1.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.modalEl.addClass("aiq-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Generate quiz" });

    const file = this.plugin.app.workspace.getActiveFile();
    if (!file) { contentEl.createEl("div", { text: "No active file.", cls: "aiq-muted" }); }
    else { contentEl.createEl("div", { text: `Current page: ${file.path}`, cls: "aiq-muted" }); }

    let sourceMode = file ? "page" : "prompt";
    let customSourceText = "";

    const srcWrap = contentEl.createDiv({ cls: "aiq-source-mode" });
    srcWrap.createEl("div", { text: "Source", cls: "aiq-muted" });
    const radioName = `aiq-src-${uid()}`;

    const r1 = srcWrap.createEl("label", { cls: "aiq-radio" });
    const r1i = r1.createEl("input", { type: "radio" });
    r1i.name = radioName;
    r1i.checked = sourceMode === "page";
    r1.createSpan({ text: file ? `Current page: ${file.basename}` : "Current page (none)" });
    if (!file) r1i.disabled = true;

    const r2 = srcWrap.createEl("label", { cls: "aiq-radio" });
    const r2i = r2.createEl("input", { type: "radio" });
    r2i.name = radioName;
    r2i.checked = sourceMode === "prompt";
    r2.createSpan({ text: "Custom prompt / source text" });

    const promptWrap = contentEl.createDiv({ cls: "aiq-prompt-wrap" });
    const ta = promptWrap.createEl("textarea", { cls: "aiq-textarea" });
    ta.rows = 6;
    ta.placeholder = "Paste source text or a custom prompt to generate a quiz from…";
    ta.style.display = sourceMode === "prompt" ? "" : "none";
    const promptHint = promptWrap.createEl("div", { cls: "aiq-muted" });
    promptHint.setText("Tip: When using a custom prompt, it is treated as the source text for the quiz.");
    promptHint.style.display = sourceMode === "prompt" ? "" : "none";

    const refreshSource = () => {
      const show = sourceMode === "prompt";
      ta.style.display = show ? "" : "none";
      promptHint.style.display = show ? "" : "none";
    };
    r1i.onchange = () => { if (r1i.checked) { sourceMode = "page"; refreshSource(); } };
    r2i.onchange = () => { if (r2i.checked) { sourceMode = "prompt"; refreshSource(); } };
    ta.oninput = () => { customSourceText = ta.value; };

    const s = this.plugin.vaultPlain.settings;
    const diff = s.defaultDifficulty || DEFAULT_SETTINGS.defaultDifficulty;
    const mcqChoices = clampInt(s.defaultChoices ?? DEFAULT_SETTINGS.defaultChoices, 3, 8, DEFAULT_SETTINGS.defaultChoices);
    const matchPairs = clampInt(s.defaultMatchPairs ?? DEFAULT_SETTINGS.defaultMatchPairs, 3, 8, DEFAULT_SETTINGS.defaultMatchPairs);
    const countTotal = clampInt(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
    const typeMode = s.defaultTypeMode || DEFAULT_SETTINGS.defaultTypeMode;
    const counts = countsFromMode(countTotal, typeMode, s.mixedRatios || DEFAULT_SETTINGS.mixedRatios);

    const info = contentEl.createDiv({ cls: "aiq-muted" });
    const sum = counts.mcq + counts.tf + counts.fib + counts.match + counts.sata;
    info.setText(`Using Settings: ${sum} questions • ${diff} • ${typeMode.toUpperCase()} • MCQ choices ${mcqChoices} • Match pairs ${matchPairs}`);

    const row = contentEl.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
    const settingsBtn = row.createEl("button", { text: "Settings", cls: "aiq-btn" });
    settingsBtn.onclick = async () => {
      try {
        await this.plugin.ensureUnlocked(true);
        new SettingsModal(this.app, this.plugin).open();
      } catch (e) {
        new obsidian_1.Notice((e?.message) || "Locked.");
      }
    };

    const btn = row.createEl("button", { text: "Generate", cls: "aiq-btn aiq-btn-primary" });
    btn.onclick = async () => {
      try {
        this.setStatus("Generating...");
        const total = counts.mcq + counts.tf + counts.fib + counts.match + counts.sata;
        if (!total) throw new Error("No questions selected in Settings.");
        if (counts.match && (matchPairs < 3 || matchPairs > 8)) throw new Error("Match pairs must be 3-8.");
        const prefTitle = (file ? file.basename : "Quiz") || "Quiz";

        if (sourceMode === "prompt") {
          const src = (customSourceText || ta.value || "").trim();
          if (!src) throw new Error("Custom prompt/source text is empty.");
          await this.plugin.generateFromTextV2(src, prefTitle, diff, mcqChoices, matchPairs, counts);
        } else {
          if (!file) throw new Error("No active note selected.");
          await this.plugin.generateFromFileV2(file, prefTitle, diff, mcqChoices, matchPairs, counts);
        }
        this.close();
      } catch (e) {
        this.setStatus((e?.message) || "Generate failed.", true);
      }
    };
    this.statusEl = contentEl.createDiv({ cls: "aiq-status" });
  }
  setStatus(msg, err = false) {
    this.statusEl.setText(msg);
    this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
  }
}

class AIQuizView extends obsidian_1.ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.tab = "generate";
    this.plugin = plugin;
    this.matchActiveLeft = new Map();
  }
  getViewType() { return VIEW_TYPE; }
  getDisplayText() { return "AI Quiz"; }
  async onOpen() { this.render(); }
  setTab(tab) { this.tab = tab; }

  render() {
    const root = this.contentEl;
    root.empty();
    root.addClass("aiq-root");

    const top = root.createDiv({ cls: "aiq-topbar aiq-topbar-main" });
    const menu = top.createDiv({ cls: "aiq-menu" });
    const genBtn = menu.createEl("button", { text: "Generate", cls: "aiq-btn aiq-menu-btn" });
    const quizBtn = menu.createEl("button", { text: "Quiz", cls: "aiq-btn aiq-menu-btn" });
    const libBtn = menu.createEl("button", { text: "Library", cls: "aiq-btn aiq-menu-btn" });
    const setBtn = menu.createEl("button", { text: "Settings", cls: "aiq-btn aiq-menu-btn" });

    genBtn.onclick = () => { this.tab = "generate"; this.render(); };
    quizBtn.onclick = () => { this.tab = "quiz"; this.render(); };
    libBtn.onclick = () => new LibraryModal(this.app, this.plugin).open();
    setBtn.onclick = async () => {
      try {
        await this.plugin.ensureUnlocked(true);
        new SettingsModal(this.app, this.plugin).open();
      } catch (e) {
        new obsidian_1.Notice((e?.message) || "Locked.");
      }
    };

    const body = root.createDiv({ cls: "aiq-body" });
    if (this.tab === "generate") {
      genBtn.addClass("aiq-btn-primary");
      this.renderGenerate(body);
    } else {
      quizBtn.addClass("aiq-btn-primary");
      this.renderQuiz(body);
    }
    this.statusEl = root.createDiv({ cls: "aiq-status" });
  }

  renderGenerate(root) {
    const card = root.createDiv({ cls: "aiq-card" });
    card.createEl("div", { text: AIQ_BLOCK_MARKERS.UI, cls: "aiq-muted" });
    card.createEl("div", { text: "Generate quiz", cls: "aiq-qtext" });

    const file = this.app.workspace.getActiveFile();
    card.createEl("div", { text: file ? `Current page: ${file.path}` : "No active note selected.", cls: "aiq-muted" });

    let sourceMode = file ? "page" : "prompt";
    let customSourceText = "";

    const srcWrap = card.createDiv({ cls: "aiq-source-mode" });
    srcWrap.createEl("div", { text: "Source", cls: "aiq-muted" });
    const radioName = `aiq-src-${uid()}`;

    const r1 = srcWrap.createEl("label", { cls: "aiq-radio" });
    const r1i = r1.createEl("input", { type: "radio" });
    r1i.name = radioName;
    r1i.checked = sourceMode === "page";
    r1.createSpan({ text: file ? `Current page: ${file.basename}` : "Current page (none)" });
    if (!file) r1i.disabled = true;

    const r2 = srcWrap.createEl("label", { cls: "aiq-radio" });
    const r2i = r2.createEl("input", { type: "radio" });
    r2i.name = radioName;
    r2i.checked = sourceMode === "prompt";
    r2.createSpan({ text: "Custom prompt / source text" });

    const promptWrap = card.createDiv({ cls: "aiq-prompt-wrap" });
    const ta = promptWrap.createEl("textarea", { cls: "aiq-textarea" });
    ta.rows = 6;
    ta.placeholder = "Paste source text or a custom prompt to generate a quiz from…";
    ta.value = customSourceText;
    const promptHint = promptWrap.createEl("div", { cls: "aiq-muted" });
    promptHint.setText("Tip: When using a custom prompt, it is treated as the source text for the quiz.");

    const refresh = () => {
      const show = sourceMode === "prompt";
      ta.style.display = show ? "" : "none";
      promptHint.style.display = show ? "" : "none";
    };

    r1i.onchange = () => { if (r1i.checked) { sourceMode = "page"; refresh(); } };
    r2i.onchange = () => { if (r2i.checked) { sourceMode = "prompt"; refresh(); } };
    ta.oninput = () => { customSourceText = ta.value; };
    refresh();

    const s = this.plugin.vaultPlain.settings;
    const diff = s.defaultDifficulty || DEFAULT_SETTINGS.defaultDifficulty;
    const mcqChoices = clampInt(s.defaultChoices ?? DEFAULT_SETTINGS.defaultChoices, 3, 8, DEFAULT_SETTINGS.defaultChoices);
    const matchPairs = clampInt(s.defaultMatchPairs ?? DEFAULT_SETTINGS.defaultMatchPairs, 3, 8, DEFAULT_SETTINGS.defaultMatchPairs);
    const countTotal = clampInt(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
    const typeMode = s.defaultTypeMode || DEFAULT_SETTINGS.defaultTypeMode;
    const counts = countsFromMode(countTotal, typeMode, s.mixedRatios || DEFAULT_SETTINGS.mixedRatios);
    const total = counts.mcq + counts.tf + counts.fib + counts.match + counts.sata;

    const info = card.createDiv({ cls: "aiq-muted" });
    info.setText(`Using Settings: ${total} questions • ${diff} • ${typeMode.toUpperCase()} • MCQ choices ${mcqChoices} • Match pairs ${matchPairs}`);

    const row = card.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
    const settingsBtn = row.createEl("button", { text: "Settings", cls: "aiq-btn" });
    settingsBtn.onclick = async () => {
      try {
        await this.plugin.ensureUnlocked(true);
        new SettingsModal(this.app, this.plugin).open();
      } catch (e) {
        new obsidian_1.Notice((e?.message) || "Locked.");
      }
    };

    const btn = row.createEl("button", { text: "Generate", cls: "aiq-btn aiq-btn-primary" });

    const setStatus = (msg, err = false) => {
      if (!this.statusEl) return;
      this.statusEl.setText(msg);
      this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
    };

    btn.onclick = async () => {
      btn.disabled = true;
      try {
        setStatus("Generating...");
        if (!total) throw new Error("No questions selected in Settings.");
        if (counts.match && (matchPairs < 3 || matchPairs > 8)) throw new Error("Match pairs must be 3-8.");
        const prefTitle = (file ? file.basename : "Quiz") || "Quiz";

        if (sourceMode === "prompt") {
          const src = (customSourceText || ta.value || "").trim();
          if (!src) throw new Error("Custom prompt/source text is empty.");
          await this.plugin.generateFromTextV2(src, prefTitle, diff, mcqChoices, matchPairs, counts);
        } else {
          if (!file) throw new Error("No active note selected.");
          await this.plugin.generateFromFileV2(file, prefTitle, diff, mcqChoices, matchPairs, counts);
        }
      } catch (e) {
        setStatus((e?.message) || "Generate failed.", true);
      } finally {
        btn.disabled = false;
      }
    };
  }

  renderQuiz(root) {
    const v = this.plugin.vaultPlain;
    const quiz = this.plugin.getCurrentQuiz();
    if (!quiz) {
      const card = root.createDiv({ cls: "aiq-card" });
      card.createEl("div", { text: "No quiz loaded.", cls: "aiq-qtext" });
      const row = card.createDiv({ cls: "aiq-topbar aiq-card-actions" });
      row.createEl("button", { text: "Open Library", cls: "aiq-btn aiq-btn-primary" }).onclick = () => new LibraryModal(this.app, this.plugin).open();
      row.createEl("button", { text: "Generate", cls: "aiq-btn" }).onclick = () => new GenerateModal(this.app, this.plugin).open();
      return;
    }

    const card = root.createDiv({ cls: "aiq-card" });
    const header = card.createDiv({ cls: "aiq-quiz-titlebar" });
    header.createEl("div", { text: quiz.title, cls: "aiq-qtext" });
    const headerActions = header.createDiv({ cls: "aiq-quiz-title-actions" });
    const addMore = headerActions.createEl("button", { text: "Add Questions", cls: "aiq-btn" });
    addMore.disabled = quiz.submitted;
    addMore.onclick = () => new AddQuestionsModal(this.app, this.plugin).open();
    const submit = headerActions.createEl("button", { text: "Submit Quiz", cls: "aiq-btn aiq-btn-primary" });
    submit.disabled = quiz.submitted;
    submit.onclick = async () => {
      quiz.grade = computeGrade(quiz);
      quiz.submitted = true;
      quiz.submittedAt = nowISO();
      quiz.updated_at = nowISO();
      await this.plugin.saveEncrypted();
      this.render();
    };

    card.createEl("div", { text: `${quiz.questions.length} Q • ${quiz.difficulty} • ${quiz.submitted ? "submitted" : "in progress"}`, cls: "aiq-muted" });

    const qWrap = root.createDiv({ cls: "aiq-card" });
    const idx = clampInt(quiz.currentIndex, 0, quiz.questions.length - 1, 0);
    quiz.currentIndex = idx;
    const q = quiz.questions[idx];
    const qType = String(q.type || "mcq");

    qWrap.createEl("div", { text: `${idx + 1} / ${quiz.questions.length} • ${qType.toUpperCase()}`, cls: "aiq-muted" });
    qWrap.createEl("div", { text: q.q, cls: "aiq-qtext" });

    const showImmediate = !!v.settings.immediateFeedback;

    const explain = qWrap.createDiv({ cls: "aiq-explain" });
    const setExplain = (text) => { explain.setText(text || ""); };

    const showRevealForQuestion = () => {
      if (quiz.submitted) return true;
      if (!showImmediate) return false;
      if (qType === "fib") return q.user_answer_text !== null && q.user_answer_text !== undefined && String(q.user_answer_text).trim().length > 0;
      if (qType === "match") return Array.isArray(q.user_map) && q.user_map.length === q.left.length && q.user_map.every(x => x !== null && x !== undefined && Number.isFinite(x));
      if (qType === "sata") return Array.isArray(q.user_answer_indices) && q.user_answer_indices.length > 0;
      return q.user_answer_index !== null && q.user_answer_index !== undefined;
    };

    const showReveal = showRevealForQuestion();

    if (qType === "mcq" || qType === "tf") {
      const choicesEl = qWrap.createDiv({ cls: "aiq-choices" });
      q.choices.forEach((c, i) => {
        const b = choicesEl.createEl("button", { text: `${String.fromCharCode(65 + i)}. ${c}`, cls: "aiq-choice" });
        if (q.user_answer_index === i) b.addClass("selected");
        if (showReveal) {
          if (i === q.answer_index) b.addClass("correct");
          if (q.user_answer_index === i && i !== q.answer_index) b.addClass("incorrect");
        }
        b.onclick = async () => {
          if (quiz.submitted) return;
          q.user_answer_index = i;
          quiz.updated_at = nowISO();
          await this.plugin.saveEncrypted();
          this.render();
        };
      });
      if (!showReveal) explain.hide();
      else {
        explain.show();
        const answered = q.user_answer_index !== null && q.user_answer_index !== undefined;
        const ok = answered && q.user_answer_index === q.answer_index;
        setExplain((ok ? "✅ Correct. " : "❌ Wrong. ") + (q.explanation || "(No explanation)"));
      }
    } else if (qType === "sata") {
      const choicesEl = qWrap.createDiv({ cls: "aiq-choices" });
      const ua = Array.isArray(q.user_answer_indices) ? q.user_answer_indices : [];
      q.choices.forEach((c, i) => {
        const b = choicesEl.createEl("button", { text: `${String.fromCharCode(65 + i)}. ${c}`, cls: "aiq-choice" });
        const selected = ua.includes(i);
        if (selected) b.addClass("selected");
        if (showReveal) {
          const isCorrectChoice = Array.isArray(q.answer_indices) && q.answer_indices.includes(i);
          if (isCorrectChoice) b.addClass("correct");
          if (selected && !isCorrectChoice) b.addClass("incorrect");
        }
        b.onclick = async () => {
          if (quiz.submitted) return;
          const cur = Array.isArray(q.user_answer_indices) ? q.user_answer_indices.slice() : [];
          const idx0 = cur.indexOf(i);
          if (idx0 >= 0) cur.splice(idx0, 1);
          else cur.push(i);
          q.user_answer_indices = Array.from(new Set(cur)).sort((a, b) => a - b);
          quiz.updated_at = nowISO();
          await this.plugin.saveEncrypted();
          this.render();
        };
      });
      if (!showReveal) explain.hide();
      else {
        explain.show();
        const answered = Array.isArray(q.user_answer_indices) && q.user_answer_indices.length > 0;
        const ok = answered && arraysEqualSet(q.user_answer_indices, q.answer_indices);
        setExplain((ok ? "✅ Correct. " : "❌ Wrong. ") + (q.explanation || "(No explanation)"));
      }
    } else if (qType === "fib") {
      const fibWrap = qWrap.createDiv({ cls: "aiq-fib" });
      const input = fibWrap.createEl("input", { type: "text" });
      input.value = q.user_answer_text || "";
      input.placeholder = "Type your answer…";
      input.disabled = quiz.submitted;

      const actions = fibWrap.createDiv({ cls: "aiq-topbar aiq-card-actions" });
      const saveBtn = actions.createEl("button", { text: "Save Answer", cls: "aiq-btn aiq-btn-primary" });
      saveBtn.disabled = quiz.submitted;

      const save = async () => {
        if (quiz.submitted) return;
        q.user_answer_text = input.value;
        quiz.updated_at = nowISO();
        await this.plugin.saveEncrypted();
        this.render();
      };

      saveBtn.onclick = () => { void save(); };
      input.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") { ev.preventDefault(); void save(); }
      });

      if (!showReveal) explain.hide();
      else {
        explain.show();
        const answered = q.user_answer_text !== null && q.user_answer_text !== undefined && String(q.user_answer_text).trim().length > 0;
        const ok = answered && (normAnswer(q.user_answer_text) === normAnswer(q.answer_text));
        setExplain((ok ? "✅ Correct. " : "❌ Wrong. ") + (q.explanation || "(No explanation)"));
      }
    } else if (qType === "match") {
      const matchCard = qWrap.createDiv({ cls: "aiq-match" });
      const row = matchCard.createDiv({ cls: "aiq-match-row" });
      const leftCol = row.createDiv({ cls: "aiq-match-col" });
      const rightCol = row.createDiv({ cls: "aiq-match-col" });

      const active = this.matchActiveLeft.get(q.id);
      const setActive = (i) => { this.matchActiveLeft.set(q.id, i); this.render(); };

      const computeRightBadges = () => {
        const badges = Array(q.right.length).fill(null);
        (q.user_map || []).forEach((rIdx, lIdx) => {
          if (rIdx !== null && rIdx !== undefined && Number.isFinite(rIdx) && rIdx >= 0 && rIdx < badges.length) badges[rIdx] = lIdx + 1;
        });
        return badges;
      };
      const rightBadges = computeRightBadges();

      const clearAll = async () => {
        if (quiz.submitted) return;
        q.user_map = new Array(q.left.length).fill(null);
        quiz.updated_at = nowISO();
        await this.plugin.saveEncrypted();
        this.render();
      };

      const topActions = matchCard.createDiv({ cls: "aiq-topbar aiq-card-actions" });
      const clearBtn = topActions.createEl("button", { text: "Clear Links", cls: "aiq-btn" });
      clearBtn.disabled = quiz.submitted;
      clearBtn.onclick = () => { void clearAll(); };
      const hint = topActions.createDiv({ cls: "aiq-muted" });
      hint.setText("Pick a left item, then pick its match on the right.");

      q.left.forEach((txt, i) => {
        const b = leftCol.createEl("button", { text: `${i + 1}. ${txt}`, cls: "aiq-choice" });
        if (active === i) b.addClass("selected");
        const linkedIdx = (q.user_map && q.user_map[i] !== null && q.user_map[i] !== undefined) ? q.user_map[i] : null;
        const linked = (linkedIdx !== null && linkedIdx !== undefined && Number.isFinite(linkedIdx)) ? idxToLetters(linkedIdx) : null;
        if (linked !== null) b.setText(`${i + 1}. ${txt}  →  ${linked}`);
        if (showReveal) {
          const ok = (q.user_map && q.user_map[i] === q.answer_map[i]);
          b.addClass(ok ? "correct" : "incorrect");
        }
        b.onclick = () => { if (!quiz.submitted) setActive(i); };
      });

      q.right.forEach((txt, rIdx) => {
        const badge = rightBadges[rIdx];
        const letter = idxToLetters(rIdx);
        const label = badge ? `${letter}. ${txt}  (${badge})` : `${letter}. ${txt}`;
        const b = rightCol.createEl("button", { text: label, cls: "aiq-choice" });
        if (badge) b.addClass("selected");
        if (showReveal) {
          let ok = false;
          for (let li = 0; li < q.left.length; li++) {
            if (q.answer_map[li] === rIdx) {
              ok = (q.user_map && q.user_map[li] === rIdx);
              break;
            }
          }
          b.addClass(ok ? "correct" : "incorrect");
        }
        b.onclick = async () => {
          if (quiz.submitted) return;
          const lIdx = this.matchActiveLeft.get(q.id);
          if (lIdx === null || lIdx === undefined || !Number.isFinite(lIdx)) return;
          const um = Array.isArray(q.user_map) ? q.user_map : new Array(q.left.length).fill(null);
          for (let j = 0; j < um.length; j++) {
            if (um[j] === rIdx) um[j] = null;
          }
          um[lIdx] = rIdx;
          q.user_map = um;
          quiz.updated_at = nowISO();
          await this.plugin.saveEncrypted();
          this.render();
        };
      });

      if (!showReveal) explain.hide();
      else {
        explain.show();
        let ok = true;
        for (let i = 0; i < q.answer_map.length; i++) {
          if (!q.user_map || q.user_map[i] !== q.answer_map[i]) { ok = false; break; }
        }
        setExplain((ok ? "✅ Correct. " : "❌ Wrong. ") + (q.explanation || "(No explanation)"));
      }
    } else {
      qWrap.createEl("div", { text: "Unsupported question type.", cls: "aiq-muted" });
      explain.hide();
    }

    const nav = qWrap.createDiv({ cls: "aiq-topbar aiq-nav" });
    const prev = nav.createEl("button", { text: "← Prev", cls: "aiq-btn" });
    const next = nav.createEl("button", { text: "Next →", cls: "aiq-btn aiq-btn-primary" });
    prev.disabled = idx === 0;
    next.disabled = idx === quiz.questions.length - 1;
    prev.onclick = async () => { quiz.currentIndex = Math.max(0, idx - 1); await this.plugin.saveEncrypted(); this.render(); };
    next.onclick = async () => { quiz.currentIndex = Math.min(quiz.questions.length - 1, idx + 1); await this.plugin.saveEncrypted(); this.render(); };

    const mapCard = root.createDiv({ cls: "aiq-card" });
    mapCard.createEl("div", { text: "Jump", cls: "aiq-muted" });
    const map = mapCard.createDiv({ cls: "aiq-map" });
    quiz.questions.forEach((qq, i) => {
      const dot = map.createEl("button", { text: String(i + 1), cls: "aiq-dot" });
      dot.setAttr("type", "button");
      if (i === idx) dot.addClass("active");
      if (quiz.submitted && quiz.grade?.per?.[i]) {
        const r = quiz.grade.per[i];
        if (r.isAnswered) dot.addClass(r.isCorrect ? "good" : "bad");
      }
      dot.onclick = async () => { quiz.currentIndex = i; await this.plugin.saveEncrypted(); this.render(); };
    });

    if (quiz.submitted && quiz.grade) {
      const r = quiz.grade;
      const res = root.createDiv({ cls: "aiq-card" });
      res.createEl("div", { text: `Score: ${r.correct}/${r.total}`, cls: "aiq-qtext" });
      res.createEl("div", { text: `Accuracy(total): ${r.accuracyTotal}% • Accuracy(answered): ${r.accuracyAnswered}%`, cls: "aiq-muted" });
      const ul = res.createEl("ul");
      quiz.questions.forEach((qq, i) => {
        const rr = r.per[i];
        const t = String(qq.type || "mcq");
        let line = "";
        if (t === "fib") {
          const ua = (qq.user_answer_text && String(qq.user_answer_text).trim()) ? `"${String(qq.user_answer_text).trim()}"` : "—";
          const ca = `"${String(qq.answer_text || "").trim()}"`;
          const tag = rr.isCorrect ? "✅" : (rr.isAnswered ? "❌" : "⏳");
          line = `${tag} ${i + 1}. your: ${ua} • correct: ${ca} — ${qq.q}`;
        } else if (t === "match") {
          const tag = rr.isCorrect ? "✅" : (rr.isAnswered ? "❌" : "⏳");
          line = `${tag} ${i + 1}. MATCH — ${qq.q}`;
        } else if (t === "sata") {
          const ua = Array.isArray(qq.user_answer_indices) && qq.user_answer_indices.length ? qq.user_answer_indices.map(x => String.fromCharCode(65 + x)).join("") : "—";
          const ca = Array.isArray(qq.answer_indices) ? qq.answer_indices.map(x => String.fromCharCode(65 + x)).join("") : "—";
          const tag = rr.isCorrect ? "✅" : (rr.isAnswered ? "❌" : "⏳");
          line = `${tag} ${i + 1}. your: ${ua} • correct: ${ca} — ${qq.q}`;
        } else {
          const ua = rr.isAnswered ? String.fromCharCode(65 + (rr.ua ?? 0)) : "—";
          const ca = String.fromCharCode(65 + rr.ca);
          const tag = rr.isCorrect ? "✅" : (rr.isAnswered ? "❌" : "⏳");
          line = `${tag} ${i + 1}. your: ${ua} • correct: ${ca} — ${qq.q}`;
        }
        ul.createEl("li", { text: line });
      });
    }
  }
}

class AIQuizPanelPlugin extends obsidian_1.Plugin {
  constructor() {
    super(...arguments);
    this.encrypted = null;
    this.vaultPlain = null;
    this.password = null;
    this.view = null;
    this.currentQuizId = null;
  }

  async onload() {
    this.registerView(VIEW_TYPE, (leaf) => {
      this.view = new AIQuizView(leaf, this);
      return this.view;
    });

    this.addCommand({
      id: "open-ai-quiz-panel",
      name: "Open Quiz Panel",
      callback: async () => { await this.openView(); }
    });

    this.addCommand({
      id: "generate-quiz-from-active-note",
      name: "Generate quiz from active note",
      callback: async () => {
        await this.ensureUnlocked();
        new GenerateModal(this.app, this).open();
      }
    });

    this.addCommand({
      id: "open-ai-quiz-generator",
      name: "Open Quiz Generator",
      callback: async () => { await this.openView("generate"); }
    });

    this.addRibbonIcon("sparkles", "AI Quiz Generator", async () => {
      await this.openView("generate");
    });

    this.addSettingTab(new AIQuizSettingTab(this.app, this));

    await this.loadEncrypted();
    await this.ensureUnlocked(true);
  }

  async onunload() {
    this.app.workspace.detachLeavesOfType(VIEW_TYPE);
  }

  async openView(tab) {
    try {
      await this.ensureUnlocked();
    } catch (e) {
      new obsidian_1.Notice(String((e?.message) || e || "Locked."));
      return;
    }

    const existing = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    const leaf = existing && existing.length ? existing[0] : this.app.workspace.getLeaf("tab");

    await leaf.setViewState({ type: VIEW_TYPE, active: true });
    this.app.workspace.revealLeaf(leaf);

    const v = leaf.view;
    if (v instanceof AIQuizView) {
      this.view = v;
      if (tab) v.setTab(tab);
      v.render();
    } else {
      if (tab && this.view) this.view.setTab(tab);
      this.view?.render();
    }
  }

  async loadEncrypted() {
    try {
      const data = await this.loadData();
      if (data?.v === 1) this.encrypted = data;
      else this.encrypted = null;
    } catch (e) {
      console.warn("AI Quiz Generator: failed to load plugin data (data.json). Treating as empty.", e);
      this.encrypted = null;
    }
  }

  async saveEncryptedBlob(blob) {
    this.encrypted = blob;
    await this.saveData(blob);
  }

  async saveEncrypted() {
    if (!this.vaultPlain || !this.password) return;
    const blob = await encryptWithPassword(this.vaultPlain, this.password);
    const deviceId = getDeviceId();
    const deviceNameB64 = getDeviceNameB64();
    const prev = this.encrypted || {};
    const rememberedByDevice = Object.assign({}, (prev && prev.rememberedByDevice) ? prev.rememberedByDevice : {});
    if (this.vaultPlain.settings.rememberPassword) {
      const deviceKeyB64 = getLocalDeviceKeyB64(true);
      if (deviceKeyB64) {
        const remembered = await rememberPasswordEncrypt(this.password, deviceKeyB64, deviceNameB64);
        rememberedByDevice[deviceId] = remembered;
      }
    } else {
      if (rememberedByDevice && rememberedByDevice[deviceId]) delete rememberedByDevice[deviceId];
    }
    blob.rememberedByDevice = rememberedByDevice;
    await this.saveEncryptedBlob(blob);
  }

  async unlockWithPassword(password, isSetup, remember) {
    if (isSetup || !this.encrypted) {
      this.vaultPlain = {
        apiKey: "",
        settings: Object.assign(Object.assign({}, DEFAULT_SETTINGS), { rememberPassword: remember }),
        quizzes: []
      };
      this.password = password;
      await this.saveEncrypted();
      new obsidian_1.Notice("Vault created.");
      return;
    }
    const plain = await decryptWithPassword(this.encrypted, password);
    plain.settings = Object.assign(Object.assign({}, DEFAULT_SETTINGS), (plain.settings || {}));
    plain.settings.rememberPassword = remember;
    if (!plain.settings.defaultTypeMode) plain.settings.defaultTypeMode = DEFAULT_SETTINGS.defaultTypeMode;
    if (!plain.settings.defaultMatchPairs) plain.settings.defaultMatchPairs = DEFAULT_SETTINGS.defaultMatchPairs;
    if (!plain.settings.defaultQuestionCount) plain.settings.defaultQuestionCount = DEFAULT_SETTINGS.defaultQuestionCount;
    if (!plain.settings.mixedRatios) plain.settings.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
    plain.settings.mixedRatios = normalizeRatioPercents(plain.settings.mixedRatios);
    this.vaultPlain = plain;
    this.password = password;
    await this.saveEncrypted();
    new obsidian_1.Notice("Unlocked.");
  }

  async tryRememberedUnlock() {
    if (!this.encrypted) return false;
    const deviceId = getDeviceId();
    const deviceNameB64 = getDeviceNameB64();
    const entry = this.encrypted?.rememberedByDevice ? this.encrypted.rememberedByDevice[deviceId] : null;
    if (entry) {
      try {
        const keyB64 = getLocalDeviceKeyB64(false);
        if (!keyB64) return false;
        const pw = await rememberPasswordDecrypt(entry, keyB64, deviceNameB64);
        const plain = await decryptWithPassword(this.encrypted, pw);
        plain.settings = Object.assign(Object.assign({}, DEFAULT_SETTINGS), (plain.settings || {}));
        if (!plain.settings.defaultTypeMode) plain.settings.defaultTypeMode = DEFAULT_SETTINGS.defaultTypeMode;
        if (!plain.settings.defaultMatchPairs) plain.settings.defaultMatchPairs = DEFAULT_SETTINGS.defaultMatchPairs;
        if (!plain.settings.defaultQuestionCount) plain.settings.defaultQuestionCount = DEFAULT_SETTINGS.defaultQuestionCount;
        if (!plain.settings.mixedRatios) plain.settings.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
        plain.settings.mixedRatios = normalizeRatioPercents(plain.settings.mixedRatios);
        this.vaultPlain = plain;
        this.password = pw;
        return true;
      } catch {
        return false;
      }
    }
    if (this.encrypted?.remembered && this.encrypted?.deviceKeyB64) {
      try {
        const pw = await (async () => {
          const key = await importDeviceKey(this.encrypted.deviceKeyB64);
          const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(bufFromB64(this.encrypted.remembered.iv)) }, key, bufFromB64(this.encrypted.remembered.data));
          return bufToStr(dec);
        })();
        const plain = await decryptWithPassword(this.encrypted, pw);
        plain.settings = Object.assign(Object.assign({}, DEFAULT_SETTINGS), (plain.settings || {}));
        if (!plain.settings.defaultTypeMode) plain.settings.defaultTypeMode = DEFAULT_SETTINGS.defaultTypeMode;
        if (!plain.settings.defaultMatchPairs) plain.settings.defaultMatchPairs = DEFAULT_SETTINGS.defaultMatchPairs;
        if (!plain.settings.defaultQuestionCount) plain.settings.defaultQuestionCount = DEFAULT_SETTINGS.defaultQuestionCount;
        if (!plain.settings.mixedRatios) plain.settings.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
        plain.settings.mixedRatios = normalizeRatioPercents(plain.settings.mixedRatios);
        this.vaultPlain = plain;
        this.password = pw;
        await this.saveEncrypted();
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  async ensureUnlocked(silent = false) {
    if (this.vaultPlain && this.password) return;
    await this.loadEncrypted();
    if (this.encrypted && await this.tryRememberedUnlock()) return;
    const mode = this.encrypted ? "unlock" : "setup";
    const ok = await new Promise((resolve) => { new UnlockModal(this.app, this, mode, resolve).open(); });
    if (!ok) {
      if (silent) return;
      throw new Error(mode === "setup" ? "Master password not set." : "Locked.");
    }
  }

  setCurrentQuiz(id) {
    this.currentQuizId = id;
    this.view?.render();
  }

  getCurrentQuiz() {
    const v = this.vaultPlain;
    if (!v) return null;
    const id = this.currentQuizId || (v.quizzes[0]?.id ?? null);
    if (!id) return null;
    const q = v.quizzes.find(x => x.id === id) || null;
    if (!q) return null;
    this.currentQuizId = q.id;
    return q;
  }

  copyQuiz(id) {
    const v = this.vaultPlain;
    const orig = v.quizzes.find(q => q.id === id);
    if (!orig) return;
    const clone = JSON.parse(JSON.stringify(orig));
    clone.id = uid();
    clone.title = `${orig.title} (copy)`;
    clone.created_at = nowISO();
    clone.updated_at = nowISO();
    clone.currentIndex = 0;
    clone.submitted = false;
    clone.submittedAt = null;
    clone.grade = null;
    clone.questions.forEach(q => {
      const t = String(q.type || "mcq");
      if (t === "fib") q.user_answer_text = null;
      else if (t === "match") q.user_map = new Array(q.left.length).fill(null);
      else if (t === "sata") q.user_answer_indices = [];
      else q.user_answer_index = null;
    });
    clone.questions = randomizeQuestions(clone.questions);
    v.quizzes.push(clone);
    this.currentQuizId = clone.id;
  }

  deleteQuiz(id) {
    const v = this.vaultPlain;
    v.quizzes = v.quizzes.filter(q => q.id !== id);
    if (this.currentQuizId === id) this.currentQuizId = v.quizzes[0]?.id ?? null;
  }

  async generateFromTextV2(sourceText, title, diff, mcqChoicesCount, matchPairs, counts, sourcePath) {
    await this.ensureUnlocked();
    const v = this.vaultPlain;
    if (!v.apiKey) throw new Error("API key missing. Open Settings and set it.");
    const text = (sourceText || "").trim();
    if (!text) throw new Error("Source text is empty.");

    const requestedCounts = {
      mcq: clampInt(counts.mcq || 0, 0, 80, 0),
      tf: clampInt(counts.tf || 0, 0, 80, 0),
      fib: clampInt(counts.fib || 0, 0, 80, 0),
      match: clampInt(counts.match || 0, 0, 80, 0),
      sata: clampInt(counts.sata || 0, 0, 80, 0)
    };
    const requestedTotal = requestedCounts.mcq + requestedCounts.tf + requestedCounts.fib + requestedCounts.match + requestedCounts.sata;
    if (!requestedTotal) throw new Error("No questions selected.");

    const existingNorm = new Set();
    const existingTokenSets = [];
    const collectedRaw = [];
    const collectedNorm = new Set();
    const collectedToken = [];

    const pushIfUnique = (rq) => {
      const qText = String((rq && rq.q) || "").trim();
      if (!qText) return false;
      if (isNearDuplicate(qText, existingNorm, existingTokenSets)) return false;
      if (isNearDuplicate(qText, collectedNorm, collectedToken)) return false;
      collectedRaw.push(rq);
      collectedNorm.add(normText(qText));
      collectedToken.push(tokenSet(qText));
      return true;
    };

    const doRequest = async (needCounts, avoidQuestions) => {
      const totalNeed = (needCounts.mcq || 0) + (needCounts.tf || 0) + (needCounts.fib || 0) + (needCounts.match || 0) + (needCounts.sata || 0);
      const body = {
        model: v.settings.model,
        input: [
          { role: "system", content: systemPrompt(v.settings.customInstructions) },
          { role: "user", content: generateUserPromptV2(text, title, needCounts, diff, mcqChoicesCount, matchPairs, v.settings.customInstructions, avoidQuestions || []) }
        ],
        temperature: v.settings.temperature,
        max_output_tokens: Math.max(v.settings.maxTokens, recommendedMaxOutputTokens(totalNeed))
      };
      const resp = await (0, obsidian_1.requestUrl)({
        url: v.settings.endpoint,
        method: "POST",
        headers: { Authorization: `Bearer ${v.apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const parsed = safeParseJson(extractOutputText(resp.json));
      const rawQs = Array.isArray(parsed?.questions) ? parsed.questions : [];
      return { parsed, rawQs };
    };

    let parsedFirst = null;

    for (let attempt = 0; attempt < 3 && collectedRaw.length < requestedTotal; attempt++) {
      const remaining = requestedTotal - collectedRaw.length;
      const chunk = Math.min(22, remaining);

      const ratioPlan = weightsToTargetCounts(requestedCounts, chunk);
      const needCounts = {
        mcq: ratioPlan.mcq,
        tf: ratioPlan.tf,
        fib: ratioPlan.fib,
        match: ratioPlan.match,
        sata: ratioPlan.sata
      };

      const avoid = collectedRaw.map(x => String((x && x.q) || "")).filter(Boolean);
      const res = await doRequest(needCounts, avoid);
      if (!parsedFirst) parsedFirst = res.parsed;

      for (const rq of res.rawQs) {
        if (collectedRaw.length >= requestedTotal) break;
        const t = String((rq?.type) || "mcq").toLowerCase();
        const safe = (t === "tf" || t === "fib" || t === "match" || t === "mcq" || t === "sata") ? rq : Object.assign({ type: "mcq" }, rq);
        pushIfUnique(safe);
      }
    }

    if (!collectedRaw.length) throw new Error("Model returned zero usable questions.");

    const buckets = { mcq: [], tf: [], fib: [], match: [], sata: [] };
    for (const rq of collectedRaw) {
      const t = String((rq?.type) || "mcq").toLowerCase();
      if (t === "tf") buckets.tf.push(rq);
      else if (t === "fib") buckets.fib.push(rq);
      else if (t === "match") buckets.match.push(rq);
      else if (t === "sata") buckets.sata.push(rq);
      else buckets.mcq.push(rq);
    }

    const pick = pickFromBucketsFlexible(buckets, requestedCounts, requestedTotal);

    const pickedRaw = pick.picked.map(x => {
      const t = String((x?.type) || "mcq").toLowerCase();
      if (t === "tf" || t === "fib" || t === "match" || t === "mcq" || t === "sata") return x;
      return Object.assign({ type: "mcq" }, x);
    });

    if (!pickedRaw.length) throw new Error("Model returned zero usable questions.");

    const normalized = pickedRaw.map(rq => normalizeAnyQuestion(rq, mcqChoicesCount, matchPairs));

    const actualCounts = { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
    for (const q of normalized) actualCounts[q.type] = (actualCounts[q.type] || 0) + 1;

    const quiz = {
      id: uid(),
      title: String((parsedFirst && parsedFirst.title) || title || "Quiz").trim() || "Quiz",
      sourcePath: sourcePath || "",
      sourceText: sourcePath ? void 0 : text,
      created_at: nowISO(),
      updated_at: nowISO(),
      difficulty: diff,
      mcqChoicesCount,
      matchPairs,
      typeCounts: actualCounts,
      requestedTypeCounts: requestedCounts,
      model: v.settings.model,
      temperature: v.settings.temperature,
      questions: randomizeQuestions(normalized),
      currentIndex: 0,
      submitted: false,
      submittedAt: null,
      grade: null
    };

    v.quizzes.push(quiz);
    this.currentQuizId = quiz.id;
    await this.saveEncrypted();
    await this.openView("quiz");
    new obsidian_1.Notice(`Quiz generated (${quiz.questions.length}).`);
  }

  async generateFromFileV2(file, title, diff, mcqChoicesCount, matchPairs, counts) {
    const text = await this.app.vault.read(file);
    const prefTitle = (title || "").trim() || file.basename || "Quiz";
    return this.generateFromTextV2(text, prefTitle, diff, mcqChoicesCount, matchPairs, counts, file.path);
  }

  async addMoreQuestionsToCurrentQuiz(count) {
    await this.ensureUnlocked(true);
    const v = this.vaultPlain;
    if (!v.apiKey) throw new Error("API key missing. Open Settings and set it.");
    const quiz = this.getCurrentQuiz();
    if (!quiz) throw new Error("No quiz loaded.");
    if (quiz.submitted) throw new Error("Quiz already submitted.");

    const desired = clampInt(count, 1, 80, 5);

    let sourceText = "";
    if (quiz.sourceText && quiz.sourceText.trim()) sourceText = quiz.sourceText.trim();
    else if (quiz.sourcePath) {
      const af = this.app.vault.getAbstractFileByPath(quiz.sourcePath);
      if (af instanceof obsidian_1.TFile) sourceText = (await this.app.vault.read(af)).trim();
      else throw new Error("Source file not found for this quiz.");
    } else {
      throw new Error("This quiz has no source text. Regenerate it from a note or custom prompt.");
    }

    const s = v.settings || Object.assign({}, DEFAULT_SETTINGS);
    const diff = s.defaultDifficulty || quiz.difficulty || DEFAULT_SETTINGS.defaultDifficulty;
    const mcqChoicesCount = clampInt(s.defaultChoices ?? DEFAULT_SETTINGS.defaultChoices, 3, 8, DEFAULT_SETTINGS.defaultChoices);
    const matchPairs = clampInt(s.defaultMatchPairs ?? DEFAULT_SETTINGS.defaultMatchPairs, 3, 8, DEFAULT_SETTINGS.defaultMatchPairs);
    const typeMode = s.defaultTypeMode || DEFAULT_SETTINGS.defaultTypeMode;
    const addCounts = countsFromMode(desired, typeMode, s.mixedRatios || DEFAULT_SETTINGS.mixedRatios);

    const totalNeed = addCounts.mcq + addCounts.tf + addCounts.fib + addCounts.match + addCounts.sata;
    if (!totalNeed) throw new Error("Nothing to add.");

    const existingQuestions = quiz.questions.map(q => q.q).filter(Boolean);
    const existingNorm = new Set(existingQuestions.map(normText));
    const existingTokenSets = existingQuestions.map(tokenSet);

    const collected = [];
    const collectedNorm = new Set();
    const collectedTokenSets = [];

    const thresholdForAttempt = (n) => (n <= 2 ? 0.72 : (n <= 4 ? 0.78 : 0.82));

    const buildAvoidList = () => {
      if (existingQuestions.length <= 160) return existingQuestions.concat(collected.map(q => q.q));
      const last = existingQuestions.slice(-120);
      const earlier = existingQuestions.slice(0, Math.max(0, existingQuestions.length - 120));
      const sample = [];
      const want = Math.min(40, earlier.length);
      for (let i = 0; i < want; i++) sample.push(earlier[Math.floor(Math.random() * earlier.length)]);
      return sample.concat(last).concat(collected.map(q => q.q));
    };

    let attempts = 0;

    while (collected.length < totalNeed && attempts < 8) {
      attempts++;
      const remaining = totalNeed - collected.length;
      const reqThis = Math.min(28, Math.max(remaining + 6, Math.ceil(remaining * 1.6)));
      const reqCounts = weightsToTargetCounts(addCounts, reqThis);

      const body = {
        model: s.model,
        input: [
          { role: "system", content: systemPrompt(s.customInstructions) },
          { role: "user", content: generateUserPromptV2(sourceText, quiz.title, reqCounts, diff, mcqChoicesCount, matchPairs, s.customInstructions, buildAvoidList()) }
        ],
        temperature: s.temperature,
        max_output_tokens: Math.max(s.maxTokens, recommendedMaxOutputTokens(reqThis))
      };

      const resp = await (0, obsidian_1.requestUrl)({
        url: s.endpoint || DEFAULT_SETTINGS.endpoint,
        method: "POST",
        headers: { Authorization: `Bearer ${v.apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const parsed = safeParseJson(extractOutputText(resp.json));
      const raw = Array.isArray(parsed?.questions) ? parsed.questions : [];
      const thr = thresholdForAttempt(attempts);

      for (const rq of raw) {
        if (collected.length >= totalNeed) break;
        let nq = null;
        try { nq = normalizeAnyQuestion(rq, mcqChoicesCount, matchPairs); } catch { continue; }
        if (isNearDuplicate(nq.q, existingNorm, existingTokenSets, thr)) continue;
        if (isNearDuplicate(nq.q, collectedNorm, collectedTokenSets, thr)) continue;
        collected.push(randomizeQuestion(nq));
        collectedNorm.add(normText(nq.q));
        collectedTokenSets.push(tokenSet(nq.q));
      }
    }

    if (!collected.length) {
      const reqThis = Math.min(30, Math.max(10, desired + 10));
      const reqCounts = weightsToTargetCounts(addCounts, reqThis);
      const body = {
        model: s.model,
        input: [
          { role: "system", content: systemPrompt(s.customInstructions) },
          { role: "user", content: generateUserPromptV2(sourceText, quiz.title, reqCounts, diff, mcqChoicesCount, matchPairs, s.customInstructions, buildAvoidList()) }
        ],
        temperature: s.temperature,
        max_output_tokens: Math.max(s.maxTokens, recommendedMaxOutputTokens(reqThis))
      };

      const resp = await (0, obsidian_1.requestUrl)({
        url: s.endpoint || DEFAULT_SETTINGS.endpoint,
        method: "POST",
        headers: { Authorization: `Bearer ${v.apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const parsed = safeParseJson(extractOutputText(resp.json));
      const raw = Array.isArray(parsed?.questions) ? parsed.questions : [];
      const thr = 0.86;

      for (const rq of raw) {
        if (collected.length >= totalNeed) break;
        let nq = null;
        try { nq = normalizeAnyQuestion(rq, mcqChoicesCount, matchPairs); } catch { continue; }
        if (existingNorm.has(normText(nq.q))) continue;
        if (isNearDuplicate(nq.q, collectedNorm, collectedTokenSets, thr)) continue;
        collected.push(randomizeQuestion(nq));
        collectedNorm.add(normText(nq.q));
        collectedTokenSets.push(tokenSet(nq.q));
      }
    }

    if (!collected.length) throw new Error("No new, non-duplicate questions were produced. The source may be too small/exhausted, or your settings demand too many highly similar questions.");

    quiz.questions.push(...shuffleInPlace(collected));
    quiz.typeCounts = quiz.typeCounts || { mcq: 0, tf: 0, fib: 0, match: 0, sata: 0 };
    for (const q of collected) quiz.typeCounts[q.type] = (quiz.typeCounts[q.type] || 0) + 1;

    quiz.difficulty = diff;
    quiz.mcqChoicesCount = mcqChoicesCount;
    quiz.matchPairs = matchPairs;
    quiz.model = s.model;
    quiz.temperature = s.temperature;

    quiz.updated_at = nowISO();
    await this.saveEncrypted();
    this.view?.render();
    new obsidian_1.Notice(`Added ${collected.length} question${collected.length === 1 ? "" : "s"}.`);
  }
}

exports.default = AIQuizPanelPlugin;

class AIQuizSettingTab extends obsidian_1.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "AI Quiz Panel" });
    containerEl.createEl("div", { text: "Settings here mirror the in-panel Settings modal.", cls: "aiq-muted" });

    if (!this.plugin.vaultPlain) {
      containerEl.createEl("div", { text: "Locked. Set or enter your master password to access settings.", cls: "aiq-muted" });
      const btnRow = containerEl.createDiv({ cls: "aiq-topbar" });
      const unlockBtn = btnRow.createEl("button", { text: this.plugin.encrypted ? "Unlock" : "Set Master Password", cls: "aiq-btn aiq-btn-primary" });
      unlockBtn.onclick = async () => {
        try { await this.plugin.ensureUnlocked(); this.display(); }
        catch (e) { new obsidian_1.Notice((e?.message) || "Locked."); }
      };
      return;
    }

    const v = this.plugin.vaultPlain;
    const s = v.settings;

    if (!s.mixedRatios) s.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
    s.mixedRatios = normalizeRatioPercents(s.mixedRatios);
    if (!s.defaultQuestionCount) s.defaultQuestionCount = DEFAULT_SETTINGS.defaultQuestionCount;

    const mkSection = (title, desc) => {
      const sec = containerEl.createDiv({ cls: "aiq-card aiq-settings-section" });
      sec.createEl("div", { text: title, cls: "aiq-qtext" });
      if (desc) sec.createEl("div", { text: desc, cls: "aiq-muted" });
      return sec;
    };

    const apiSec = mkSection("API & Model", "Controls which model is called and how the request is sent.");
    new obsidian_1.Setting(apiSec)
      .setName("OpenAI API key")
      .setDesc(openAIApiKeysDescFragment())
      .addText(t => t.setPlaceholder("sk-...").setValue(v.apiKey || "").onChange(async (val) => {
        v.apiKey = val.trim();
        await this.plugin.saveEncrypted();
      }));

    new obsidian_1.Setting(apiSec)
      .setName("Model")
      .setDesc("Higher models are usually smarter but slower/more expensive.")
      .addDropdown(d => {
        d.addOption("gpt-4.1-mini", "gpt-4.1-mini (default)");
        d.addOption("gpt-4.1-nano", "gpt-4.1-nano (fast/cheap)");
        d.addOption("gpt-5-mini", "gpt-5-mini");
        d.addOption("gpt-5-nano", "gpt-5-nano (fastest)");
        d.addOption("gpt-5.2", "gpt-5.2 (best)");
        d.addOption("o4-mini", "o4-mini (reasoning)");
        d.setValue(s.model || "gpt-4.1-mini");
        d.onChange(async (val) => { s.model = val; await this.plugin.saveEncrypted(); });
      });

    new obsidian_1.Setting(apiSec)
      .setName("Temperature")
      .setDesc("Lower = more consistent; higher = more variety.")
      .addSlider(sl => {
        sl.setLimits(0, 2, 0.1);
        sl.setValue(s.temperature ?? 0.7);
        sl.setDynamicTooltip();
        sl.onChange(async (val) => { s.temperature = val; await this.plugin.saveEncrypted(); });
      });

    let maxTokText = null;
    new obsidian_1.Setting(apiSec)
      .setName("Max output tokens")
      .setDesc("If you get truncated JSON errors, increase this (or lower question count).")
      .addText(t => {
        maxTokText = t;
        t.setValue(String(s.maxTokens ?? 6000));
        t.onChange(async (val) => {
          s.maxTokens = clampInt(val, 256, 20000, 6000);
          await this.plugin.saveEncrypted();
        });
      })
      .addButton(b => {
        b.setButtonText("Set recommended");
        b.onClick(async () => {
          s.maxTokens = recommendedMaxOutputTokens(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount);
          if (maxTokText) maxTokText.setValue(String(s.maxTokens));
          await this.plugin.saveEncrypted();
        });
      });

    new obsidian_1.Setting(apiSec)
      .setName("Endpoint")
      .setDesc("Defaults to OpenAI Responses API. Change only if you know what you’re doing.")
      .addText(t => t.setValue(s.endpoint || DEFAULT_SETTINGS.endpoint).onChange(async (val) => {
        s.endpoint = val.trim() || DEFAULT_SETTINGS.endpoint;
        await this.plugin.saveEncrypted();
      }));

    const genSec = mkSection("Generation Defaults", "These settings drive Generate and Add Questions.");
    const recLine = genSec.createDiv({ cls: "aiq-muted" });
    const updateRecs = () => {
      const qc = clampInt(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
      const rec = recommendedMaxOutputTokens(qc);
      recLine.setText(`Tip: For ${qc} questions, a good starting Max output tokens is ~${rec}.`);
    };

    new obsidian_1.Setting(genSec)
      .setName("Default total questions")
      .setDesc("Used by Generate. Larger quizzes often require higher Max output tokens.")
      .addText(t => t.setValue(String(s.defaultQuestionCount ?? DEFAULT_SETTINGS.defaultQuestionCount)).onChange(async (val) => {
        s.defaultQuestionCount = clampInt(val, 1, 80, DEFAULT_SETTINGS.defaultQuestionCount);
        await this.plugin.saveEncrypted();
        this.plugin.view?.render();
        updateRecs();
      }));

    new obsidian_1.Setting(genSec)
      .setName("Default difficulty")
      .setDesc("Controls how direct vs. inferential questions are.")
      .addDropdown(d => {
        d.addOption("easy", "easy");
        d.addOption("medium", "medium");
        d.addOption("hard", "hard");
        d.addOption("very_hard", "very hard");
        d.setValue(s.defaultDifficulty || "medium");
        d.onChange(async (val) => { s.defaultDifficulty = val; await this.plugin.saveEncrypted(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default question type mode")
      .setDesc("Pick a single type, or use Mixed (ratios below).")
      .addDropdown(d => {
        d.addOption("mcq", "MCQ only");
        d.addOption("tf", "True/False only");
        d.addOption("fib", "Fill in the blank only");
        d.addOption("match", "Matching only");
        d.addOption("sata", "Select all that apply only");
        d.addOption("mixed", "Mixed (ratios from Settings)");
        d.setValue(s.defaultTypeMode || "mcq");
        d.onChange(async (val) => { s.defaultTypeMode = val; await this.plugin.saveEncrypted(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default MCQ choices")
      .setDesc("How many choices each multiple choice question has.")
      .addDropdown(d => {
        ["3", "4", "5", "6", "7", "8"].forEach(x => d.addOption(x, x));
        d.setValue(String(s.defaultChoices ?? 4));
        d.onChange(async (val) => { s.defaultChoices = clampInt(val, 3, 8, 4); await this.plugin.saveEncrypted(); });
      });

    new obsidian_1.Setting(genSec)
      .setName("Default match pairs")
      .setDesc("Matching questions show N items on the left and N on the right.")
      .addText(t => t.setValue(String(s.defaultMatchPairs ?? 4)).onChange(async (val) => {
        s.defaultMatchPairs = clampInt(val, 3, 8, 4);
        await this.plugin.saveEncrypted();
      }));

    updateRecs();

    const ratiosSec = mkSection("Mixed Mode Ratios", "Used only when Type Mode = Mixed. Must sum to 100%.");
    const sumEl = ratiosSec.createDiv({ cls: "aiq-muted" });
    const ratioInputs = {};

    const updateSumEl = () => {
      const r = normalizeRatioPercents(s.mixedRatios);
      const sum = (r.mcq || 0) + (r.tf || 0) + (r.fib || 0) + (r.match || 0) + (r.sata || 0);
      sumEl.setText(`Current: MCQ ${r.mcq}% • TF ${r.tf}% • FIB ${r.fib}% • MATCH ${r.match}% • SATA ${r.sata}% (sum ${sum}%)`);
    };

    const setRatios = async (key, val) => {
      const cur = Object.assign({}, s.mixedRatios || DEFAULT_SETTINGS.mixedRatios);
      cur[key] = clampInt(val, 0, 100, 0);
      const norm = normalizeRatioPercents(cur);
      s.mixedRatios = norm;
      for (const k of ["mcq", "tf", "fib", "match", "sata"]) {
        if (ratioInputs[k]) ratioInputs[k].setValue(String(norm[k] || 0));
      }
      updateSumEl();
      await this.plugin.saveEncrypted();
    };

    const mkRatio = (name, key) => {
      new obsidian_1.Setting(ratiosSec)
        .setName(name)
        .setDesc("Percent of total questions in Mixed mode.")
        .addText(t => {
          ratioInputs[key] = t;
          t.setValue(String(s.mixedRatios[key] || 0));
          t.onChange(async (v0) => { await setRatios(key, v0); });
        });
    };

    mkRatio("MCQ %", "mcq");
    mkRatio("True/False %", "tf");
    mkRatio("Fill in the blank %", "fib");
    mkRatio("Matching %", "match");
    mkRatio("Select all that apply %", "sata");
    updateSumEl();

    const promptSec = mkSection("Prompting", "These instructions are appended to every generation request.");
    const ciSetting2 = new obsidian_1.Setting(promptSec)
      .setName("Custom instructions (optional)")
      .setDesc("Example: focus on definitions and key claims. Keep explanations concise.");
    ciSetting2.settingEl.addClass("aiq-setting-textarea");
    ciSetting2.addTextArea(t => {
      t.setPlaceholder("Example: Focus on definitions and key claims. Keep explanations concise.");
      t.setValue(s.customInstructions || "");
      t.inputEl.addClass("aiq-custom-instructions");
      t.inputEl.style.resize = "vertical";
      t.onChange(async (val) => { s.customInstructions = val; await this.plugin.saveEncrypted(); });
    });

    const behaviorSec = mkSection("Behavior", "How the quiz UI behaves while you answer.");
    new obsidian_1.Setting(behaviorSec)
      .setName("Immediate feedback")
      .setDesc("If enabled: show correctness after selecting/submitting input. Otherwise only show after Submit Quiz.")
      .addToggle(tg => tg.setValue(!!s.immediateFeedback).onChange(async (val) => {
        s.immediateFeedback = val;
        await this.plugin.saveEncrypted();
        this.plugin.view?.render();
      }));

    const securitySec = mkSection("Security", "Password and encryption-related convenience settings.");
    new obsidian_1.Setting(securitySec)
      .setName("Remember password on this device")
      .setDesc("Convenience only. Stored per-device; sync won’t break other devices. Turning off removes the remembered entry for this device.")
      .addToggle(tg => tg.setValue(!!s.rememberPassword).onChange(async (val) => {
        s.rememberPassword = val;
        await this.plugin.saveEncrypted();
      }));

    const advSec = mkSection("Advanced", "Reset everything back to defaults (API key not cleared).");
    new obsidian_1.Setting(advSec)
      .setName("Reset settings to defaults")
      .setDesc("Resets settings values (not quizzes). API key stays as-is.")
      .addButton(b => {
        b.setButtonText("Reset");
        b.setWarning();
        b.onClick(async () => {
          const ok = window.confirm("Reset all AI Quiz settings to defaults? This does not delete quizzes.");
          if (!ok) return;
          const keepApiKey = v.apiKey;
          v.settings = Object.assign({}, DEFAULT_SETTINGS);
          v.apiKey = keepApiKey;
          if (!v.settings.mixedRatios) v.settings.mixedRatios = Object.assign({}, DEFAULT_SETTINGS.mixedRatios);
          v.settings.mixedRatios = normalizeRatioPercents(v.settings.mixedRatios);
          await this.plugin.saveEncrypted();
          this.display();
        });
      });
  }
}
