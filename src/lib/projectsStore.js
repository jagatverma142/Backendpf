const path = require("path");
const crypto = require("crypto");
const { readJson, writeJsonAtomic } = require("./jsonStore");

const filePath = path.join(__dirname, "..", "..", "data", "projects.json");

function makeId() {
  return "proj_" + crypto.randomBytes(8).toString("hex");
}

async function listProjects() {
  return await readJson(filePath, []);
}

async function getProject(id) {
  const all = await listProjects();
  return all.find(p => p.id === id) || null;
}

async function createProject(project) {
  const all = await listProjects();
  const next = { ...project, id: makeId() };
  all.unshift(next);
  await writeJsonAtomic(filePath, all);
  return next;
}

async function updateProject(id, patch) {
  const all = await listProjects();
  const idx = all.findIndex(p => p.id === id);
  if (idx === -1) return null;
  all[idx] = { ...all[idx], ...patch, id };
  await writeJsonAtomic(filePath, all);
  return all[idx];
}

async function deleteProject(id) {
  const all = await listProjects();
  const next = all.filter(p => p.id !== id);
  if (next.length === all.length) return false;
  await writeJsonAtomic(filePath, next);
  return true;
}

module.exports = { listProjects, getProject, createProject, updateProject, deleteProject };
