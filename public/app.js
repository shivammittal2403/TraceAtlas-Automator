"use strict";

const $ = (selector) => document.querySelector(selector);
const placeholders = {
  domain: "example.com",
  ip: "203.0.113.10",
  url: "https://example.com/about",
  email: "consenting.user@example.com",
  username: "public_handle",
  hash: "64-character SHA-256 hash",
};

if (location.hostname !== "osint-tools.vercel.app") {
  document.querySelectorAll(".legacy-link").forEach((link) => { link.hidden = true; });
}

function isPrivateIPv4(value) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    (parts[0] === 169 && parts[1] === 254) || (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
}

function validateTarget(type, raw) {
  const value = raw.trim();
  if (!value || value.length > 2048 || /[\r\n\0]/.test(value)) throw new Error("Enter one valid target.");
  if (type === "domain" && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)) throw new Error("Enter a valid public domain.");
  if (type === "ip") {
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split(".").every((part) => Number(part) <= 255);
    const ipv6 = /^[0-9a-f:]+$/i.test(value) && value.includes(":");
    if ((!ipv4 && !ipv6) || isPrivateIPv4(value) || value === "::1") throw new Error("Enter a public IP address.");
  }
  if (type === "url") {
    let parsed;
    try { parsed = new URL(value); } catch { throw new Error("Enter a valid HTTP or HTTPS URL."); }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hostname === "localhost" || isPrivateIPv4(parsed.hostname)) throw new Error("Enter a public HTTP or HTTPS URL without credentials.");
  }
  if (type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw new Error("Enter a valid email address with consent.");
  if (type === "username" && !/^[a-z0-9_.-]{1,64}$/i.test(value)) throw new Error("Use 1–64 letters, numbers, dot, underscore or hyphen.");
  if (type === "hash" && !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) throw new Error("Enter an MD5, SHA-1 or SHA-256 hex digest.");
  return value;
}

function shellQuote(value) {
  if (/^[a-zA-Z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function caseId(target) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(target));
  return `rk-${Array.from(new Uint8Array(digest)).slice(0, 6).map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}

function buildCommand(argv, target, id) {
  return argv.map((token) => shellQuote(token.replaceAll("{target}", target).replaceAll("{case_id}", id))).join(" ");
}

function renderPlan(plan, target, id) {
  const list = $("#commands");
  list.replaceChildren();
  for (const step of plan.steps) {
    const item = document.createElement("li");
    const label = document.createElement("b");
    const code = document.createElement("code");
    const button = document.createElement("button");
    const command = buildCommand(step.argv, target, id);
    label.textContent = step.label;
    code.textContent = command;
    button.type = "button";
    button.className = "copy";
    button.textContent = "COPY";
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(command);
      button.textContent = "COPIED";
      setTimeout(() => { button.textContent = "COPY"; }, 1400);
    });
    item.append(label, button, code);
    list.append(item);
  }
  $("#result-title").textContent = `${plan.engine} / ${plan.target_type} / ${id}`;
  $("#result").hidden = false;
  $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#target-type").addEventListener("change", (event) => {
  $("#target").placeholder = placeholders[event.target.value];
});

$("#plan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("#form-error");
  error.textContent = "";
  try {
    if (!$("#authorized").checked) throw new Error("Authorization confirmation is required.");
    const type = $("#target-type").value;
    const target = validateTarget(type, $("#target").value);
    const response = await fetch("/api/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_type: type, engine: $("#engine").value, authorized: true }),
    });
    const plan = await response.json();
    if (!response.ok) throw new Error(plan.error || "Planner request failed.");
    renderPlan(plan, target, await caseId(target));
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : "Unable to create the plan.";
  }
});

fetch("/api/catalog").then((response) => response.ok ? response.json() : Promise.reject())
  .then((catalog) => {
    $("#version").textContent = catalog.version;
    for (const [name, value] of Object.entries(catalog.metrics)) {
      const element = document.querySelector(`[data-metric="${name}"]`);
      if (element) element.textContent = String(value);
    }
  }).catch(() => {});
