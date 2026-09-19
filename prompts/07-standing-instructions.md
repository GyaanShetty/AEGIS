## Standing instructions (worth putting in CLAUDE.md)

```
- Tests before implementation. Show me failing tests before you write the fix.
- Never claim something works without running it and showing the output.
- The agent process is untrusted. If a design decision makes sense only when
  the agent behaves, it is wrong — flag it instead of building it.
- Custom errors over require strings. Events on every state mutation.
- When you hit a fork in the design, stop and give me the options with
  trade-offs. Do not silently pick one.
- Do not add dependencies without telling me what they are and why.
- Flag anything security-critical you are unsure about rather than guessing.
```
