/*
  AI adapter (Node.js) - placeholder
  - Reads keys from process.env (GITHUB_API_KEY, GEMINI_API_KEY)
  - Routes public queries to Gemini (gemini-2.5-flash)
  - Routes GitHub/code queries to GPT-4o (gpt-4o) but only after fetching repository data with GitHub API (using GITHUB_API_KEY)
  - Blocks forwarding INTERNAL company data to external LLMs when BLOCK_INTERNAL_EXTERNAL=true

  This is a safe template. DO NOT commit real secrets. Use .env locally or CI secret manager.
*/

const fetch = require('node-fetch');

const GITHUB_API_KEY = process.env.GITHUB_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const AI_PUBLIC_MODEL = process.env.AI_PUBLIC_MODEL || 'gemini-2.5-flash';
const AI_CODE_MODEL = process.env.AI_CODE_MODEL || 'gpt-4o';
const BLOCK_INTERNAL_EXTERNAL = (process.env.BLOCK_INTERNAL_EXTERNAL || 'true') === 'true';

function isInternalQuery(query) {
  // Basic heuristic — replace with an allowlist/metadata in production
  const lowered = (query || '').toString().toLowerCase();
  const internalKeywords = ['salary', 'employee record', 'personal data', 'ssn', 'confidential', 'internal only', 'company secret'];
  return internalKeywords.some(k => lowered.includes(k));
}

async function callGemini(prompt) {
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY is not set');
  // Placeholder: vendor-specific integration goes here. Example HTTP call format may differ.
  return {
    model: AI_PUBLIC_MODEL,
    text: `Simulated Gemini response for prompt: ${prompt.slice(0, 200)}`,
  };
}

async function callGpt4o(prompt) {
  if (!GITHUB_API_KEY) throw new Error('GITHUB_API_KEY is not set for code model');
  // Placeholder: actually call OpenAI / GPT-4o-compatible endpoint or internal LLM gateway
  return {
    model: AI_CODE_MODEL,
    text: `Simulated GPT-4o response for code prompt: ${prompt.slice(0, 200)}`,
  };
}

async function fetchGithubFile(owner, repo, path) {
  if (!GITHUB_API_KEY) throw new Error('GITHUB_API_KEY not set');
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `token ${GITHUB_API_KEY}`,
      'User-Agent': 'vvc-hrm-ai-adapter',
      Accept: 'application/vnd.github.v3.raw',
    },
  });
  if (!res.ok) throw new Error(`GitHub API error: ${res.status} ${await res.text()}`);
  return await res.text();
}

module.exports = {
  async answerQuery({ query, tags = [], repoContext = null }) {
    // If the query is internal-sensitive, block external forwarding
    if (BLOCK_INTERNAL_EXTERNAL && (tags.includes('internal') || isInternalQuery(query))) {
      return {
        blocked: true,
        reason: 'This query is flagged as internal/private — external LLM calls are blocked by policy.',
      };
    }

    // If user asked to search code / repo, prefer gpt-4o with GitHub context
    if (tags.includes('code') && repoContext && repoContext.owner && repoContext.repo && repoContext.path) {
      // Fetch requested file (example) and send limited context to code model
      const fileText = await fetchGithubFile(repoContext.owner, repoContext.repo, repoContext.path);
      const prompt = `Repository context (file ${repoContext.path}):\n${fileText.slice(0, 10000)}\n\nUser question: ${query}`;
      const resp = await callGpt4o(prompt);
      return { blocked: false, model: resp.model, text: resp.text };
    }

    // Default: use Gemini for general public questions
    const resp = await callGemini(query);
    return { blocked: false, model: resp.model, text: resp.text };
  },
};
