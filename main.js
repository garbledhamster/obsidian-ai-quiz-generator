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
    immediateFeedback: false,
    rememberPassword: false,
    customInstructions: ""
};
function uid() {
    return "qz_" + Math.random().toString(16).slice(2) + "_" + Date.now().toString(16);
}
function nowISO() { return new Date().toISOString(); }
function clampInt(n, min, max, fallback) {
    const x = parseInt(String(n), 10);
    if (!Number.isFinite(x))
        return fallback;
    return Math.max(min, Math.min(max, x));
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
function randomizeQuestionChoices(q) {
    const pairs = q.choices.map((text, idx) => ({ text, idx }));
    shuffleInPlace(pairs);
    const newChoices = pairs.map(p => p.text);
    const newAnswerIndex = pairs.findIndex(p => p.idx === q.answer_index);
    const newUserIndex = q.user_answer_index === null ? null : pairs.findIndex(p => p.idx === q.user_answer_index);
    return Object.assign(Object.assign({}, q), { choices: newChoices, answer_index: Math.max(0, newAnswerIndex), user_answer_index: newUserIndex });
}
function randomizeQuestions(questions) {
    const qs = questions.map(randomizeQuestionChoices);
    return shuffleInPlace(qs);
}
function normText(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
}
function tokenSet(s) {
    const toks = normText(s).split(" ").filter(w => w.length >= 3);
    return new Set(toks);
}
function jaccard(a, b) {
    if (!a.size || !b.size)
        return 0;
    let inter = 0;
    for (const x of a)
        if (b.has(x))
            inter++;
    const uni = a.size + b.size - inter;
    return uni ? inter / uni : 0;
}
function isNearDuplicate(qText, existing, existingTokenSets) {
    const n = normText(qText);
    if (!n)
        return true;
    if (existing.has(n))
        return true;
    const t = tokenSet(n);
    for (const ex of existingTokenSets) {
        if (jaccard(t, ex) >= 0.72)
            return true;
    }
    return false;
}
function clampNum(n, min, max, fallback) {
    const x = Number(n);
    if (!Number.isFinite(x))
        return fallback;
    return Math.max(min, Math.min(max, x));
}
function b64FromBuf(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function bufFromB64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}
function strToBuf(s) {
    return new TextEncoder().encode(s).buffer;
}
function bufToStr(b) {
    return new TextDecoder().decode(new Uint8Array(b));
}
function rand(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
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
async function importDeviceKey(b64) {
    return crypto.subtle.importKey("raw", bufFromB64(b64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function rememberPasswordEncrypt(password, deviceKeyB64) {
    const key = await importDeviceKey(deviceKeyB64);
    const iv = rand(IV_BYTES);
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, strToBuf(password));
    return { iv: b64FromBuf(iv.buffer), data: b64FromBuf(enc) };
}
async function rememberPasswordDecrypt(payload, deviceKeyB64) {
    const key = await importDeviceKey(deviceKeyB64);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(bufFromB64(payload.iv)) }, key, bufFromB64(payload.data));
    return bufToStr(dec);
}
function difficultySpec(level) {
    if (level === "easy")
        return [
            "EASY SPEC:",
            "- Direct recall; no inference.",
            "- Distractors obviously wrong.",
            "- Exactly one correct choice."
        ].join("\n");
    if (level === "hard")
        return [
            "HARD SPEC:",
            "- Requires inference/connecting ideas.",
            "- Distractors plausible but false per text.",
            "- Exactly one correct choice."
        ].join("\n");
    if (level === "very_hard")
        return [
            "VERY HARD SPEC:",
            "- Multi-step reasoning; connect distant parts.",
            "- Distractors highly plausible.",
            "- Still unambiguous; exactly one correct choice.",
            "- Explanation cites the textual clue."
        ].join("\n");
    return [
        "MEDIUM SPEC:",
        "- Understanding + paraphrase + cause/effect.",
        "- Distractors plausible but not tricky.",
        "- Exactly one correct choice."
    ].join("\n");
}
function systemPrompt(customInstructions) {
    const base = [
        "You generate multiple-choice quizzes.",
        "Output ONLY valid json.",
        "No markdown. No commentary.",
        "Use ONLY the provided source text.",
        "Exactly one correct answer per question."
    ].join(" ");
    const extra = (customInstructions || "").trim();
    if (!extra)
        return base;
    return base + " " + "Additional instructions (must not override rules): " + extra;
}
function generateUserPrompt(text, title, count, diff, choicesCount, customInstructions, avoidQuestions) {
    return [
        "Output format: json",
        "Return a valid json object only.",
        "",
        difficultySpec(diff),
        "",
        `Number of questions: ${count}`,
        `Choices per question: ${choicesCount}`,
        title ? `Title preference: ${title}` : "",
        "",
        "Do not repeat or paraphrase any of these questions (write truly new ones):",
        ...((avoidQuestions && avoidQuestions.length) ? avoidQuestions.slice(0, 120).map(q => "- " + String(q).slice(0, 280)) : ["- (none)"]),
        "",
        "REQUIRED JSON SHAPE:",
        `{ "title": string, "questions": [ { "q": string, "choices": string[], "answer_index": number, "explanation": string } ] }`,
        "",
        "Rules:",
        "- choices.length must match choices per question exactly.",
        "- choices should be short phrases.",
        "- explanation is 1-2 sentences.",
        "",
        customInstructions && customInstructions.trim() ? "CUSTOM INSTRUCTIONS (rules win if conflict):" : "",
        customInstructions && customInstructions.trim() ? customInstructions.trim() : "",
        "",
        "SOURCE TEXT (only allowed knowledge):",
        text.trim()
    ].filter(Boolean).join("\n");
}
function extractOutputText(resp) {
    if (typeof resp?.output_text === "string" && resp.output_text.trim())
        return resp.output_text;
    const out = resp?.output;
    if (!Array.isArray(out))
        return "";
    for (const item of out) {
        if (item?.type === "message" && Array.isArray(item.content)) {
            for (const c of item.content) {
                if (c?.type === "output_text" && typeof c.text === "string" && c.text.trim())
                    return c.text;
                if (typeof c?.text === "string" && c.text.trim())
                    return c.text;
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
    // Fix common missing-comma patterns between array/object elements
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
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === "\\") {
        esc = true;
        continue;
      }
      if (ch === '"') {
        inStr = false;
        continue;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{" || ch === "[")
      depth++;
    else if (ch === "}" || ch === "]") {
      depth--;
      if (depth === 0)
        lastEnd = i;
    }
  }
  return lastEnd;
}
function looksTruncatedJson(s) {
  const t = (s || "").trim();
  if (!t)
    return true;
  if (!/[}\]]\s*$/.test(t))
    return true;
  let inStr = false, esc = false;
  let depth = 0;
  for (let i = 0; i < t.length; i++) {
    const ch = t[i];
    if (inStr) {
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === "\\") {
        esc = true;
        continue;
      }
      if (ch === '"') {
        inStr = false;
        continue;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{" || ch === "[")
      depth++;
    else if (ch === "}" || ch === "]")
      depth--;
  }
  return depth !== 0;
}
function safeParseJson(text) {
  const raw = (text || "").trim();
  if (!raw)
    throw new Error("Empty model output.");
  const cleaned = repairJsonCommon(raw);
  try {
    return JSON.parse(cleaned);
  } catch {
  }
  const o = cleaned.indexOf("{");
  const a = cleaned.indexOf("[");
  const start = o >= 0 && (a < 0 || o < a) ? o : a;
  if (start < 0)
    throw new Error("Model output was not JSON.");
  const end = findLastBalancedJsonEnd(cleaned, start);
  if (end !== null) {
    const candidate = repairJsonCommon(cleaned.slice(start, end + 1));
    try {
      return JSON.parse(candidate);
    } catch {
    }
  }
  const tail = repairJsonCommon(cleaned.slice(start));
  try {
    return JSON.parse(tail);
  } catch (e) {
    const msg = String((e == null ? void 0 : e.message) || e || "Unknown JSON parse error");
    if (looksTruncatedJson(tail)) {
      throw new Error("Model returned truncated/invalid JSON. Increase Max Output Tokens or reduce question count.");
    }
    throw new Error("Model output was not valid JSON: " + msg);
  }
}
function recommendedMaxOutputTokens(questionCount) {
  const qc = clampInt(questionCount, 1, 60, 10);
  const est = 900 + qc * 190;
  return Math.max(1200, Math.min(12000, est));
}
function normalizeQuestion(q, choicesCount) {
    const qq = String(q?.q || "").trim();
    const choices = Array.isArray(q?.choices) ? q.choices.map((x) => String(x).trim()).filter(Boolean) : [];
    let ai = Number.isFinite(q?.answer_index) ? q.answer_index : parseInt(String(q?.answer_index), 10);
    if (!qq)
        throw new Error("Bad model output: missing question text.");
    if (choices.length !== choicesCount)
        throw new Error(`Bad model output: choices must be exactly ${choicesCount}.`);
    if (!Number.isFinite(ai))
        ai = 0;
    ai = Math.max(0, Math.min(choices.length - 1, ai));
    return {
        id: uid(),
        q: qq,
        choices,
        answer_index: ai,
        explanation: String(q?.explanation || "").trim(),
        user_answer_index: null
    };
}
function computeGrade(quiz) {
    const total = quiz.questions.length;
    let answered = 0;
    let correct = 0;
    const per = quiz.questions.map((q) => {
        const ua = q.user_answer_index;
        const isAnswered = ua !== null && ua !== undefined;
        if (isAnswered)
            answered++;
        const isCorrect = isAnswered && ua === q.answer_index;
        if (isCorrect)
            correct++;
        return { isAnswered, isCorrect, ua: isAnswered ? ua : null, ca: q.answer_index };
    });
    const accuracyAnswered = answered ? Math.round((correct / answered) * 100) : 0;
    const accuracyTotal = total ? Math.round((correct / total) * 100) : 0;
    return { total, answered, correct, accuracyAnswered, accuracyTotal, per };
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
        if (this.mode !== "setup")
            f2.hide();
        const row = contentEl.createDiv({ cls: "aiq-row" });
        const left = row.createDiv({ cls: "aiq-row-left" });
        const right = row.createDiv({ cls: "aiq-row-right" });
        const rememberWrap = left.createEl("label", { cls: "aiq-muted" });
        this.rememberEl = rememberWrap.createEl("input", { type: "checkbox" });
        rememberWrap.appendText(" Remember password (convenience; weak security)");
        const cancelBtn = right.createEl("button", { text: "Cancel", cls: "aiq-btn" });
        cancelBtn.onclick = () => {
            if (!this.resolved) {
                this.resolved = true;
                this.done(false);
            }
            this.close();
        };
        const btn = right.createEl("button", { text: this.mode === "setup" ? "Create" : "Unlock", cls: "aiq-btn aiq-btn-primary" });
        btn.onclick = async () => {
            try {
                this.setStatus("Working...");
                const p1 = this.passEl.value.trim();
                if (!p1)
                    throw new Error("Password required.");
                if (this.mode === "setup") {
                    const p2 = this.pass2El.value.trim();
                    if (!p2)
                        throw new Error("Confirm password.");
                    if (p1 !== p2)
                        throw new Error("Passwords do not match.");
                }
                await this.plugin.unlockWithPassword(p1, this.mode === "setup", this.rememberEl.checked);
                this.close();
            }
            catch (e) {
                this.setStatus(e?.message || "Unlock failed.", true);
            }
        };
        this.statusEl = contentEl.createDiv({ cls: "aiq-status" });
    }
    onClose() {
        if (!this.resolved) {
            this.resolved = true;
            this.done(false);
        }
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
                }
                catch (e) {
                    new obsidian_1.Notice((e === null || e === void 0 ? void 0 : e.message) || "Locked.");
                }
            };
            return;
        }
        const v = this.plugin.vaultPlain;
        const s = v.settings;
        new obsidian_1.Setting(contentEl)
            .setName("API key")
            .setDesc("Stored encrypted in plugin data.")
            .addText(t => t.setPlaceholder("sk-...").setValue(v.apiKey || "").onChange(async (val) => {
            v.apiKey = val.trim();
            await this.plugin.saveEncrypted();
        }));
        new obsidian_1.Setting(contentEl)
            .setName("Model")
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
        new obsidian_1.Setting(contentEl)
            .setName("Temperature")
            .addSlider(sl => {
            sl.setLimits(0, 2, 0.1);
            sl.setValue(s.temperature ?? 0.7);
            sl.setDynamicTooltip();
            sl.onChange(async (val) => { s.temperature = val; await this.plugin.saveEncrypted(); });
        });
        new obsidian_1.Setting(contentEl)
            .setName("Max output tokens")
            .addText(t => t.setValue(String(s.maxTokens ?? 1800)).onChange(async (val) => {
            s.maxTokens = clampInt(val, 256, 8000, 1800);
            await this.plugin.saveEncrypted();
        }));
        new obsidian_1.Setting(contentEl)
            .setName("Default difficulty")
            .addDropdown(d => {
            d.addOption("easy", "easy");
            d.addOption("medium", "medium");
            d.addOption("hard", "hard");
            d.addOption("very_hard", "very hard");
            d.setValue(s.defaultDifficulty || "medium");
            d.onChange(async (val) => { s.defaultDifficulty = val; await this.plugin.saveEncrypted(); });
        });
        new obsidian_1.Setting(contentEl)
            .setName("Choices per question")
            .addDropdown(d => {
            ["4", "5", "6", "7", "8"].forEach(x => d.addOption(x, x));
            d.setValue(String(s.defaultChoices ?? 4));
            d.onChange(async (val) => { s.defaultChoices = clampInt(val, 4, 8, 4); await this.plugin.saveEncrypted(); });
        });
        const ciSetting = new obsidian_1.Setting(contentEl)
    .setName("Custom instructions (optional)")
    .setDesc("Appended to every generation request. Rules still win if conflict.");
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

new obsidian_1.Setting(contentEl)
            .setName("Immediate feedback")
            .setDesc("If enabled: show correctness after selecting an answer. Otherwise only show after Submit.")
            .addToggle(tg => tg.setValue(!!s.immediateFeedback).onChange(async (val) => {
            s.immediateFeedback = val;
            await this.plugin.saveEncrypted();
            this.plugin.view?.render();
        }));
        new obsidian_1.Setting(contentEl)
            .setName("Endpoint")
            .setDesc("Defaults to OpenAI Responses API.")
            .addText(t => t.setValue(s.endpoint || DEFAULT_SETTINGS.endpoint).onChange(async (val) => {
            s.endpoint = val.trim() || DEFAULT_SETTINGS.endpoint;
            await this.plugin.saveEncrypted();
        }));
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
                if (ev.key === "Enter") {
                    ev.preventDefault();
                    void doSave();
                }
            });
        });
        const actions = contentEl.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
        const saveBtn = actions.createEl("button", { text: "Save", cls: "aiq-btn aiq-btn-primary" });
        const cancelBtn = actions.createEl("button", { text: "Cancel", cls: "aiq-btn" });
        const doSave = async () => {
            try {
                const trimmed = (next || "").trim();
                if (!trimmed)
                    throw new Error("Title can't be empty.");
                this.quiz.title = trimmed;
                this.quiz.updated_at = nowISO();
                await this.plugin.saveEncrypted();
                this.onRenamed();
                this.close();
            }
            catch (e) {
                this.setStatus((e === null || e === void 0 ? void 0 : e.message) || "Rename failed.", true);
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
        contentEl.createEl("div", { text: "Generate additional questions for the currently loaded quiz (no repeats).", cls: "aiq-muted" });
        const grid = contentEl.createDiv({ cls: "aiq-grid aiq-grid-2" });
        const f1 = grid.createDiv({ cls: "aiq-field" });
        f1.createEl("label", { text: "How many?" });
        this.countEl = f1.createEl("input", { type: "number" });
        this.countEl.value = "5";
        this.countEl.min = "1";
        this.countEl.max = "50";
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
                const n = clampInt(this.countEl.value, 1, 50, 5);
                await this.plugin.addMoreQuestionsToCurrentQuiz(n);
                this.close();
            }
            catch (e) {
                this.setStatus((e === null || e === void 0 ? void 0 : e.message) || "Failed.", true);
            }
            finally {
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
            if (!quizzes.length) {
                list.createEl("div", { text: "No quizzes yet.", cls: "aiq-muted" });
                return;
            }
            for (const q of quizzes) {
                const card = list.createDiv({ cls: "aiq-card" });
                card.createEl("div", { text: q.title, cls: "aiq-qtext" });
                card.createEl("div", { text: `${q.questions.length} Q • ${q.difficulty} • ${q.submitted ? "submitted" : "in progress"}`, cls: "aiq-muted" });
                const row = card.createDiv({ cls: "aiq-topbar aiq-card-actions" });
                const loadBtn = row.createEl("button", { text: "Load", cls: "aiq-btn aiq-btn-primary" });
                loadBtn.onclick = async () => {
                    this.plugin.setCurrentQuiz(q.id);
                    await this.plugin.openView("quiz");
                    this.close();
                };
const renameBtn = row.createEl("button", { text: "Rename", cls: "aiq-btn" });
renameBtn.onclick = () => {
    new RenameQuizModal(this.app, this.plugin, q, () => render()).open();
};
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
                    if (!ok)
                        return;
                    this.plugin.deleteQuiz(q.id);
                    await this.plugin.saveEncrypted();
                    new obsidian_1.Notice("Deleted.");
                    render(); // keep library open
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
        if (!file) {
            contentEl.createEl("div", { text: "No active file.", cls: "aiq-muted" });
            return;
        }
        contentEl.createEl("div", { text: `Current page: ${file.path}`, cls: "aiq-muted" });
        let sourceMode = "page";
        let customSourceText = "";
        const srcWrap = contentEl.createDiv({ cls: "aiq-source-mode" });
        srcWrap.createEl("div", { text: "Source", cls: "aiq-muted" });
        const radioName = `aiq-src-${uid()}`;
        const r1 = srcWrap.createEl("label", { cls: "aiq-radio" });
        const r1i = r1.createEl("input", { type: "radio" });
        r1i.name = radioName;
        r1i.checked = true;
        r1.createSpan({ text: `Current page: ${file.basename}` });
        const r2 = srcWrap.createEl("label", { cls: "aiq-radio" });
        const r2i = r2.createEl("input", { type: "radio" });
        r2i.name = radioName;
        r2.createSpan({ text: "Custom prompt / source text" });
        const promptWrap = contentEl.createDiv({ cls: "aiq-prompt-wrap" });
        const ta = promptWrap.createEl("textarea", { cls: "aiq-textarea" });
        ta.rows = 6;
        ta.placeholder = "Paste source text or a custom prompt to generate a quiz from…";
        ta.style.display = "none";
        const promptHint = promptWrap.createEl("div", { cls: "aiq-muted" });
        promptHint.setText("Tip: When using a custom prompt, it is treated as the source text for the quiz.");
        promptHint.style.display = "none";
        const refresh = () => {
            const show = sourceMode === "prompt";
            ta.style.display = show ? "" : "none";
            promptHint.style.display = show ? "" : "none";
        };
        r1i.onchange = () => { if (r1i.checked) {
            sourceMode = "page";
            refresh();
        } };
        r2i.onchange = () => { if (r2i.checked) {
            sourceMode = "prompt";
            refresh();
        } };
        ta.oninput = () => { customSourceText = ta.value; };
        let count = 10;
        let title = "";
        let diff = this.plugin.vaultPlain.settings.defaultDifficulty;
        let choices = this.plugin.vaultPlain.settings.defaultChoices;
        new obsidian_1.Setting(contentEl).setName("Questions").addText(t => {
            t.setValue(String(count));
            t.onChange(v => { count = clampInt(v, 1, 50, 10); });
        });
        new obsidian_1.Setting(contentEl).setName("Title preference (optional)").addText(t => {
            t.setValue(title);
            t.onChange(v => { title = v; });
        });
        new obsidian_1.Setting(contentEl).setName("Difficulty").addDropdown(d => {
            d.addOption("easy", "easy");
            d.addOption("medium", "medium");
            d.addOption("hard", "hard");
            d.addOption("very_hard", "very hard");
            d.setValue(diff);
            d.onChange(v => { diff = v; });
        });
        new obsidian_1.Setting(contentEl).setName("Choices").addDropdown(d => {
            ["4", "5", "6", "7", "8"].forEach(x => d.addOption(x, x));
            d.setValue(String(choices));
            d.onChange(v => { choices = clampInt(v, 4, 8, 4); });
        });
        const row = contentEl.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
        const btn = row.createEl("button", { text: "Generate", cls: "aiq-btn aiq-btn-primary" });
        btn.onclick = async () => {
            try {
                this.setStatus("Generating...");
                if (sourceMode === "prompt") {
                    const src = (customSourceText || ta.value || "").trim();
                    if (!src)
                        throw new Error("Custom prompt/source text is empty.");
                    const prefTitle = (title || "").trim() || "Quiz";
                    await this.plugin.generateFromText(src, count, prefTitle, diff, choices);
                }
                else {
                    await this.plugin.generateFromFile(file, count, title, diff, choices);
                }
                this.close();
            }
            catch (e) {
                this.setStatus(e?.message || "Generate failed.", true);
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
    }
    getViewType() { return VIEW_TYPE; }
    getDisplayText() { return "AI Quiz"; }
    async onOpen() {
        this.render();
    }
    setTab(tab) {
        this.tab = tab;
    }
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
            }
            catch (e) {
                new obsidian_1.Notice((e === null || e === void 0 ? void 0 : e.message) || "Locked.");
            }
        };

const body = root.createDiv({ cls: "aiq-body" });
        if (this.tab === "generate") {
            genBtn.addClass("aiq-btn-primary");
            this.renderGenerate(body);
        }
        else {
            quizBtn.addClass("aiq-btn-primary");
            this.renderQuiz(body);
        }
        this.statusEl = root.createDiv({ cls: "aiq-status" });
    }
    renderGenerate(root) {
    const card = root.createDiv({ cls: "aiq-card" });
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
    if (!file)
        r1i.disabled = true;
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
    r1i.onchange = () => { if (r1i.checked) {
        sourceMode = "page";
        refresh();
    } };
    r2i.onchange = () => { if (r2i.checked) {
        sourceMode = "prompt";
        refresh();
    } };
    ta.oninput = () => { customSourceText = ta.value; };
    refresh();
    let count = 10;
    let title = "";
    let diff = this.plugin.vaultPlain.settings.defaultDifficulty;
    let choices = this.plugin.vaultPlain.settings.defaultChoices;
    new obsidian_1.Setting(card).setName("Questions").addText(t => {
        t.setValue(String(count));
        t.onChange(v => { count = clampInt(v, 1, 50, 10); });
    });
    new obsidian_1.Setting(card).setName("Title preference (optional)").addText(t => {
        t.setValue(title);
        t.onChange(v => { title = v; });
    });
    new obsidian_1.Setting(card).setName("Difficulty").addDropdown(d => {
        d.addOption("easy", "easy");
        d.addOption("medium", "medium");
        d.addOption("hard", "hard");
        d.addOption("very_hard", "very hard");
        d.setValue(diff);
        d.onChange(v => { diff = v; });
    });
    new obsidian_1.Setting(card).setName("Choices").addDropdown(d => {
        ["4", "5", "6", "7", "8"].forEach(x => d.addOption(x, x));
        d.setValue(String(choices));
        d.onChange(v => { choices = clampInt(v, 4, 8, 4); });
    });
    const row = card.createDiv({ cls: "aiq-topbar aiq-modal-actions" });
    const btn = row.createEl("button", { text: "Generate", cls: "aiq-btn aiq-btn-primary" });
    const setStatus = (msg, err = false) => {
        if (!this.statusEl)
            return;
        this.statusEl.setText(msg);
        this.statusEl.style.color = err ? "var(--color-red)" : "var(--text-muted)";
    };
    btn.onclick = async () => {
        btn.disabled = true;
        try {
            setStatus("Generating...");
            if (sourceMode === "prompt") {
                const src = (customSourceText || ta.value || "").trim();
                if (!src)
                    throw new Error("Custom prompt/source text is empty.");
                const prefTitle = (title || "").trim() || "Quiz";
                await this.plugin.generateFromText(src, count, prefTitle, diff, choices);
            }
            else {
                if (!file)
                    throw new Error("No active note selected.");
                await this.plugin.generateFromFile(file, count, title, diff, choices);
            }
        }
        catch (e) {
            setStatus((e === null || e === void 0 ? void 0 : e.message) || "Generate failed.", true);
        }
        finally {
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
        qWrap.createEl("div", { text: `${idx + 1} / ${quiz.questions.length}`, cls: "aiq-muted" });
        qWrap.createEl("div", { text: q.q, cls: "aiq-qtext" });
        const choicesEl = qWrap.createDiv({ cls: "aiq-choices" });
        const showImmediate = !!v.settings.immediateFeedback;
        const answered = q.user_answer_index !== null && q.user_answer_index !== undefined;
        const showReveal = quiz.submitted || (showImmediate && answered);
        q.choices.forEach((c, i) => {
            const b = choicesEl.createEl("button", { text: `${String.fromCharCode(65 + i)}. ${c}`, cls: "aiq-choice" });
            if (q.user_answer_index === i)
                b.addClass("selected");
            if (showReveal) {
                if (i === q.answer_index)
                    b.addClass("correct");
                if (q.user_answer_index === i && i !== q.answer_index)
                    b.addClass("incorrect");
            }
            b.onclick = async () => {
                if (quiz.submitted)
                    return;
                q.user_answer_index = i;
                quiz.updated_at = nowISO();
                await this.plugin.saveEncrypted();
                this.render();
            };
        });
        const explain = qWrap.createDiv({ cls: "aiq-explain" });
        if (!showReveal) {
            explain.hide();
        }
        else {
            const ok = answered && q.user_answer_index === q.answer_index;
            explain.setText((ok ? "✅ Correct. " : "❌ Wrong. ") + (q.explanation || "(No explanation)"));
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
            if (i === idx)
                dot.addClass("active");
            if (quiz.submitted && quiz.grade?.per?.[i]) {
                const r = quiz.grade.per[i];
                if (r.isAnswered)
                    dot.addClass(r.isCorrect ? "good" : "bad");
            }
            dot.onclick = async () => {
                quiz.currentIndex = i;
                await this.plugin.saveEncrypted();
                this.render();
            };
        });
        if (quiz.submitted && quiz.grade) {
            const r = quiz.grade;
            const res = root.createDiv({ cls: "aiq-card" });
            res.createEl("div", { text: `Score: ${r.correct}/${r.total}`, cls: "aiq-qtext" });
            res.createEl("div", { text: `Accuracy(total): ${r.accuracyTotal}% • Accuracy(answered): ${r.accuracyAnswered}%`, cls: "aiq-muted" });
            const ul = res.createEl("ul");
            quiz.questions.forEach((qq, i) => {
                const rr = r.per[i];
                const ua = rr.isAnswered ? String.fromCharCode(65 + (rr.ua ?? 0)) : "—";
                const ca = String.fromCharCode(65 + rr.ca);
                const tag = rr.isCorrect ? "✅" : (rr.isAnswered ? "❌" : "⏳");
                ul.createEl("li", { text: `${tag} ${i + 1}. your: ${ua} • correct: ${ca} — ${qq.q}` });
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
this.addSettingTab(
new AIQuizSettingTab(this.app, this));
        // First run may not have data.json yet, and the user may dismiss the unlock
        // modal during startup. Neither should crash Obsidian.
        await this.loadEncrypted();
        await this.ensureUnlocked(true);
    }
    async onunload() {
        this.app.workspace.detachLeavesOfType(VIEW_TYPE);
    }
    async openView(tab) {
        try {
            await this.ensureUnlocked();
        }
        catch (e) {
            new obsidian_1.Notice(String(e?.message || e || "Locked."));
            return;
        }
        const leaf = this.app.workspace.getLeaf("tab");
        await leaf.setViewState({ type: VIEW_TYPE, active: true });
        this.app.workspace.revealLeaf(leaf);
        if (tab && this.view)
            this.view.setTab(tab);
        this.view?.render();
    }
    async loadEncrypted() {
        try {
            const data = await this.loadData();
            if (data?.v === 1)
                this.encrypted = data;
            else
                this.encrypted = null;
        }
        catch (e) {
            // Missing / unreadable data.json (or a transient read error) should be
            // treated as "no data".
            console.warn("AI Quiz Generator: failed to load plugin data (data.json). Treating as empty.", e);
            this.encrypted = null;
        }
    }
    async saveEncryptedBlob(blob) {
        this.encrypted = blob;
        await this.saveData(blob);
    }
    async saveEncrypted() {
        if (!this.vaultPlain || !this.password)
            return;
        const blob = await encryptWithPassword(this.vaultPlain, this.password);
        if (this.vaultPlain.settings.rememberPassword) {
            const deviceKeyB64 = this.encrypted?.deviceKeyB64 || b64FromBuf(rand(32).buffer);
            const remembered = await rememberPasswordEncrypt(this.password, deviceKeyB64);
            blob.deviceKeyB64 = deviceKeyB64;
            blob.remembered = remembered;
        }
        else {
            blob.deviceKeyB64 = this.encrypted?.deviceKeyB64;
        }
        await this.saveEncryptedBlob(blob);
    }
    async unlockWithPassword(password, isSetup, remember) {
        if (isSetup || !this.encrypted) {
            this.vaultPlain = {
                apiKey: "",
                settings: { ...DEFAULT_SETTINGS, rememberPassword: remember },
                quizzes: []
            };
            this.password = password;
            await this.saveEncrypted();
            new obsidian_1.Notice("Vault created.");
            return;
        }
        const plain = await decryptWithPassword(this.encrypted, password);
        plain.settings = { ...DEFAULT_SETTINGS, ...(plain.settings || {}) };
        plain.settings.rememberPassword = remember;
        this.vaultPlain = plain;
        this.password = password;
        await this.saveEncrypted();
        new obsidian_1.Notice("Unlocked.");
    }
    async tryRememberedUnlock() {
        if (!this.encrypted?.remembered || !this.encrypted.deviceKeyB64)
            return false;
        try {
            const pw = await rememberPasswordDecrypt(this.encrypted.remembered, this.encrypted.deviceKeyB64);
            const plain = await decryptWithPassword(this.encrypted, pw);
            plain.settings = { ...DEFAULT_SETTINGS, ...(plain.settings || {}) };
            this.vaultPlain = plain;
            this.password = pw;
            return true;
        }
        catch {
            return false;
        }
    }
    async ensureUnlocked(silent = false) {
        if (this.vaultPlain && this.password)
            return;
        await this.loadEncrypted();
        if (this.encrypted && await this.tryRememberedUnlock())
            return;
        const mode = this.encrypted ? "unlock" : "setup";
        const ok = await new Promise((resolve) => {
            new UnlockModal(this.app, this, mode, resolve).open();
        });
        if (!ok) {
            // During startup (silent) we don't want to crash the plugin if the user closes the modal.
            // Callers that need an unlocked vault should call ensureUnlocked() with silent=false.
            if (silent)
                return;
            throw new Error(mode === "setup" ? "Master password not set." : "Locked.");
        }
    }
    setCurrentQuiz(id) {
        this.currentQuizId = id;
        this.view?.render();
    }
    getCurrentQuiz() {
        const v = this.vaultPlain;
        if (!v)
            return null;
        const id = this.currentQuizId || (v.quizzes[0]?.id ?? null);
        if (!id)
            return null;
        const q = v.quizzes.find(x => x.id === id) || null;
        if (!q)
            return null;
        this.currentQuizId = q.id;
        return q;
    }
    copyQuiz(id) {
        const v = this.vaultPlain;
        const orig = v.quizzes.find(q => q.id === id);
        if (!orig)
            return;
        const clone = JSON.parse(JSON.stringify(orig));
        clone.id = uid();
        clone.title = `${orig.title} (copy)`;
        clone.created_at = nowISO();
        clone.updated_at = nowISO();
        clone.currentIndex = 0;
        clone.submitted = false;
        clone.submittedAt = null;
        clone.grade = null;
        clone.questions.forEach(q => q.user_answer_index = null);
        clone.questions = randomizeQuestions(clone.questions);
        v.quizzes.push(clone);
        this.currentQuizId = clone.id;
    }
    deleteQuiz(id) {
        const v = this.vaultPlain;
        v.quizzes = v.quizzes.filter(q => q.id !== id);
        if (this.currentQuizId === id)
            this.currentQuizId = v.quizzes[0]?.id ?? null;
    }
    async generateFromText(sourceText, count, title, diff, choicesCount, sourcePath) {
        await this.ensureUnlocked();
        const v = this.vaultPlain;
        if (!v.apiKey)
            throw new Error("API key missing. Open Settings and set it.");
        const text = (sourceText || "").trim();
        if (!text)
            throw new Error("Source text is empty.");
        const body = {
            model: v.settings.model,
            input: [
                { role: "system", content: systemPrompt() },
                { role: "user", content: generateUserPrompt(text, title, count, diff, choicesCount, v.settings.customInstructions) }
            ],
            temperature: v.settings.temperature,
            max_output_tokens: Math.max(v.settings.maxTokens, recommendedMaxOutputTokens(count))
        };
        const resp = await (0, obsidian_1.requestUrl)({
            url: v.settings.endpoint,
            method: "POST",
            headers: {
                Authorization: `Bearer ${v.apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        });
        const parsed = safeParseJson(extractOutputText(resp.json));
        const questionsRaw = parsed?.questions;
        if (!Array.isArray(questionsRaw) || !questionsRaw.length)
            throw new Error("Bad model output: missing questions.");
        const quiz = {
            id: uid(),
            title: String(parsed?.title || title || "Quiz").trim() || "Quiz",
            sourcePath: sourcePath || "",
            sourceText: sourcePath ? void 0 : text,
            created_at: nowISO(),
            updated_at: nowISO(),
            difficulty: diff,
            choicesCount,
            model: v.settings.model,
            temperature: v.settings.temperature,
            questions: randomizeQuestions(questionsRaw.map((q) => normalizeQuestion(q, choicesCount))),
            currentIndex: 0,
            submitted: false,
            submittedAt: null,
            grade: null
        };
        v.quizzes.push(quiz);
        this.currentQuizId = quiz.id;
        await this.saveEncrypted();
        await this.openView("quiz");
        new obsidian_1.Notice("Quiz generated.");
    }

    async addMoreQuestionsToCurrentQuiz(count) {
        await this.ensureUnlocked(true);
        const v = this.vaultPlain;
        if (!v.apiKey)
            throw new Error("API key missing. Open Settings and set it.");
        const quiz = this.getCurrentQuiz();
        if (!quiz)
            throw new Error("No quiz loaded.");
        if (quiz.submitted)
            throw new Error("Quiz already submitted.");
        const desired = clampInt(count, 1, 50, 5);
        let sourceText = "";
        if (quiz.sourceText && quiz.sourceText.trim()) {
            sourceText = quiz.sourceText.trim();
        }
        else if (quiz.sourcePath) {
            const af = this.app.vault.getAbstractFileByPath(quiz.sourcePath);
            if (af instanceof obsidian_1.TFile)
                sourceText = (await this.app.vault.read(af)).trim();
            else
                throw new Error("Source file not found for this quiz.");
        }
        else {
            throw new Error("This quiz has no source text. Regenerate it from a note or custom prompt.");
        }
        const existingQuestions = quiz.questions.map(q => q.q);
        const existingNorm = new Set(existingQuestions.map(normText));
        const existingTokenSets = existingQuestions.map(tokenSet);
        const collected = [];
        const collectedNorm = new Set();
        const collectedTokenSets = [];
        let attempts = 0;
        while (collected.length < desired && attempts < 3) {
            attempts++;
            const reqCount = Math.min(12, desired - collected.length);
            const body = {
                model: v.settings.model,
                input: [
                    { role: "system", content: systemPrompt() },
                    { role: "user", content: generateUserPrompt(sourceText, quiz.title, reqCount, quiz.difficulty, quiz.choicesCount, v.settings.customInstructions, existingQuestions) }
                ],
                temperature: v.settings.temperature,
                max_output_tokens: Math.max(v.settings.maxTokens, recommendedMaxOutputTokens(reqCount))
            };
            const resp = await (0, obsidian_1.requestUrl)({
                url: v.settings.endpoint,
                method: "POST",
                headers: {
                    Authorization: `Bearer ${v.apiKey}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(body)
            });
            const parsed = safeParseJson(extractOutputText(resp.json));
            const questionsRaw = Array.isArray(parsed === null || parsed === void 0 ? void 0 : parsed.questions) ? parsed.questions : [];
            const normalized = questionsRaw.map((q) => normalizeQuestion(q, quiz.choicesCount));
            for (const q of normalized) {
                if (collected.length >= desired)
                    break;
                if (isNearDuplicate(q.q, existingNorm, existingTokenSets))
                    continue;
                if (isNearDuplicate(q.q, collectedNorm, collectedTokenSets))
                    continue;
                collected.push(randomizeQuestionChoices(q));
                collectedNorm.add(normText(q.q));
                collectedTokenSets.push(tokenSet(q.q));
            }
        }
        if (!collected.length)
            throw new Error("No new, non-duplicate questions were produced. Try again.");
        quiz.questions.push(...shuffleInPlace(collected));
        quiz.updated_at = nowISO();
        await this.saveEncrypted();
        var _a;
        (_a = this.view) === null || _a === void 0 ? void 0 : _a.render();
        new obsidian_1.Notice(`Added ${collected.length} question${collected.length === 1 ? "" : "s"}.`);
    }

    async generateFromFile(file, count, title, diff, choicesCount) {
        const text = await this.app.vault.read(file);
        const prefTitle = (title || "").trim() || file.basename || "Quiz";
        return this.generateFromText(text, count, prefTitle, diff, choicesCount, file.path);
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
                try {
                    await this.plugin.ensureUnlocked();
                    this.display();
                }
                catch (e) {
                    new obsidian_1.Notice((e === null || e === void 0 ? void 0 : e.message) || "Locked.");
                }
            };
            return;
        }
        const v = this.plugin.vaultPlain;
        const s = v.settings;
        new obsidian_1.Setting(containerEl)
            .setName("API key")
            .setDesc("Encrypted in plugin data.json.")
            .addText(t => t.setPlaceholder("sk-...").setValue(v.apiKey || "").onChange(async (val) => {
            v.apiKey = val.trim();
            await this.plugin.saveEncrypted();
        }));
        new obsidian_1.Setting(containerEl)
            .setName("Model")
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
        new obsidian_1.Setting(containerEl)
            .setName("Default difficulty")
            .addDropdown(d => {
            d.addOption("easy", "easy");
            d.addOption("medium", "medium");
            d.addOption("hard", "hard");
            d.addOption("very_hard", "very hard");
            d.setValue(s.defaultDifficulty || "medium");
            d.onChange(async (val) => { s.defaultDifficulty = val; await this.plugin.saveEncrypted(); });
        });
        const ciSetting2 = new obsidian_1.Setting(containerEl)
    .setName("Custom instructions (optional)")
    .setDesc("Appended to every generation request. Rules still win if conflict.");
ciSetting2.settingEl.addClass("aiq-setting-textarea");
ciSetting2.addTextArea(t => {
    t.setPlaceholder("Example: Focus on definitions and key claims. Keep explanations concise.");
    t.setValue(s.customInstructions || "");
    t.inputEl.addClass("aiq-custom-instructions");
    t.inputEl.style.resize = "vertical";
    t.onChange(async (val) => { s.customInstructions = val; await this.plugin.saveEncrypted(); });
});

new obsidian_1.Setting(containerEl)
            .setName("Immediate feedback")
            .addToggle(tg => tg.setValue(!!s.immediateFeedback).onChange(async (val) => {
            s.immediateFeedback = val;
            await this.plugin.saveEncrypted();
            this.plugin.view?.render();
        }));
        new obsidian_1.Setting(containerEl)
            .setName("Remember password (convenience)")
            .setDesc("Weak security. If you need real security: don’t store the password, use session-only.")
            .addToggle(tg => tg.setValue(!!s.rememberPassword).onChange(async (val) => {
            s.rememberPassword = val;
            await this.plugin.saveEncrypted();
        }));
    }
}
