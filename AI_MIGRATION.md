AI Assistant migration notes

Objective
- Stop using any Graq-specific integration and migrate to API-key driven usage.
- Use environment variables to store secrets (do NOT commit them).
- Use gpt-4o for GitHub/code-related tasks and gemini-2.5-flash for general public questions.
- Enforce a policy preventing internal/company-sensitive content from being sent to external LLM APIs.

What was added
- .env.example: example env variables showing GITHUB_API_KEY, GEMINI_API_KEY, and model names.
- scripts/ai_adapter.js: a safe template adapter showing how to read env keys, fetch GitHub files with a PAT, route prompts to the appropriate model, and block forwarding internal queries.

Next steps (recommended)
1. Rotate any leaked/secrets that were shared in chat immediately. Treat those keys as compromised.
2. Remove any committed .env files from git history and add .env to .gitignore (if not already). Use the following commands:
   git rm --cached .env
   git commit -m "chore(secrets): remove committed .env and add .env to .gitignore"
   git push

3. Locate the backend service that powers the AI HR Assistant. Typical locations:
   - A server/ directory in the repo (Node.js, Python, Go)
   - cloud functions or separate repo referenced in deployment scripts
   - CI/CD pipeline steps that call AI APIs

4. Replace the existing AI calls with a central adapter/gateway like scripts/ai_adapter.js. Ensure all callers route through the adapter so the policy enforcement is centralized.

5. Deploy an internal-only LLM or a private proxy if internal data must be processed. If not available, ensure internal queries are rejected and logged.

6. Add audit logging for requests that were blocked or proxied.

Security note
- DO NOT commit real API keys. Use your CI/CD secret store, environment variables on the server, or a secret manager (Vault, AWS Secrets Manager, GitHub Secrets).
- Rotate any keys that were exposed in conversation immediately.

If you want, I can:
- Search the repository to find the backend code that currently calls AI providers and prepare a patch there to switch to env-based keys and the models you requested.
- Remove the committed .env from the repository index (and from history if you want — requires force-push or BFG/ git filter-branch).
- Implement the adapter into the real backend (need path/stack: Node/Python/etc.).
